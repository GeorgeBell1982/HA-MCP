import type { Config } from "../config.js";
import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
  type Phase3ValidationPort,
} from "./applyCoordinator.js";
import type {
  Phase3ReloadServicePort,
  Phase3ReloadDispatchResult,
} from "./reloadAdapter.js";
import type { Phase3ReloadTarget } from "./contracts.js";
import {
  StrictYamlPhase3Validation,
  type Phase3ValidationPhase,
} from "./validationAdapter.js";

const MAX_RESPONSE_BYTES = 2_000_000;

/** Inert until explicitly composed. Endpoints and empty service payload are fixed. */
export class HomeAssistantPhase3Client implements Phase3ReloadServicePort {
  private readonly base: URL;
  private readonly token: string;

  constructor(
    config: Pick<Config, "mode" | "baseUrl" | "token">,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    const base = new URL(config.baseUrl.href);
    if (
      !["http:", "https:"].includes(base.protocol) ||
      base.username ||
      base.password ||
      base.search ||
      base.hash ||
      !config.token ||
      /[\r\n]/u.test(config.token) ||
      (config.mode === "addon"
        ? base.href !== "http://supervisor/core/api"
        : config.mode !== "local" || base.pathname !== "/api")
    )
      throw failure("ha_endpoint_invalid");
    this.base = base;
    this.token = config.token;
  }

  async checkInstalledConfiguration(
    context: Phase3OperationContext,
  ): Promise<void> {
    const result = await this.request(
      "/config/core/check_config",
      "POST",
      context,
    );
    if (
      !isObject(result) ||
      result.result !== "valid" ||
      result.errors !== null ||
      (result.warnings !== undefined && result.warnings !== null)
    )
      throw failure("ha_configuration_invalid");
  }

  async automationStates(context: Phase3OperationContext): Promise<unknown[]> {
    const result = await this.request("/states", "GET", context);
    if (!Array.isArray(result)) throw failure("ha_response_invalid");
    return (result as unknown[]).filter(
      (entry) =>
        isObject(entry) &&
        typeof entry.entity_id === "string" &&
        entry.entity_id.startsWith("automation."),
    );
  }

  async reload(
    target: Phase3ReloadTarget,
    context: Phase3OperationContext,
  ): Promise<Phase3ReloadDispatchResult> {
    if (target !== "automation.reload" || !active(context))
      return Object.freeze({ status: "not_dispatched" });
    try {
      const result = await this.request(
        "/services/automation/reload",
        "POST",
        context,
      );
      if (!Array.isArray(result)) throw failure("ha_response_invalid");
      return Object.freeze({ status: "completed" });
    } catch {
      // Once dispatch was attempted, an HTTP error, disconnect or timeout cannot
      // prove that Core did not reload. Never retry this effect automatically.
      return Object.freeze({ status: "outcome_unknown" });
    }
  }

  private async request(
    path:
      | "/config/core/check_config"
      | "/services/automation/reload"
      | "/states",
    method: "POST" | "GET",
    context: Phase3OperationContext,
  ): Promise<unknown> {
    assertActive(context);
    const target = new URL(this.base);
    target.pathname += path;
    const signal = AbortSignal.any([
      context.signal,
      AbortSignal.timeout(
        Math.max(1, Math.ceil(context.deadlineAt - Date.now())),
      ),
    ]);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const chunks: Buffer[] = [];
    let joined: Buffer | undefined;
    try {
      const response = await this.fetcher(target, {
        method,
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: "application/json",
          ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
        },
        ...(method === "POST" ? { body: "{}" } : {}),
        redirect: "error",
        signal,
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw failure("ha_request_failed");
      }
      const declared = response.headers.get("content-length");
      if (
        declared &&
        (!/^\d+$/u.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)
      ) {
        await response.body?.cancel();
        throw failure("ha_response_invalid");
      }
      if (!response.body) throw failure("ha_response_invalid");
      reader = response.body.getReader();
      let total = 0;
      while (true) {
        assertActive(context);
        const chunk = await reader.read();
        if (chunk.done) break;
        total += chunk.value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          chunk.value.fill(0);
          throw failure("ha_response_invalid");
        }
        chunks.push(Buffer.from(chunk.value));
        chunk.value.fill(0);
      }
      assertActive(context);
      joined = Buffer.concat(chunks, total);
      return JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(joined),
      ) as unknown;
    } catch (error) {
      if (!active(context)) assertActive(context);
      if (error instanceof Phase3CoordinatorError) throw error;
      throw failure("ha_request_failed");
    } finally {
      try {
        await reader?.cancel();
      } catch {
        /* transport already closed */
      }
      reader?.releaseLock();
      for (const chunk of chunks) chunk.fill(0);
      joined?.fill(0);
    }
  }
}

/** Core validates the installed configuration after apply and after rollback.
 * Pre-apply parsing alone is not claimed as HA semantic validation. */
export class HomeAssistantPhase3Validation implements Phase3ValidationPort {
  private readonly yaml = new StrictYamlPhase3Validation();
  constructor(
    private readonly client: Pick<
      HomeAssistantPhase3Client,
      "checkInstalledConfiguration"
    >,
  ) {}
  async validate(
    bytes: Uint8Array,
    phase: Phase3ValidationPhase,
    context: Phase3OperationContext,
  ): Promise<void> {
    await this.yaml.validate(bytes, phase, context);
    if (
      phase === "candidate_post_apply" ||
      phase === "checkpoint_post_rollback"
    )
      await this.client.checkInstalledConfiguration(context);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function active(context: Phase3OperationContext): boolean {
  return (
    !context.signal.aborted &&
    Number.isFinite(context.deadlineAt) &&
    Date.now() < context.deadlineAt
  );
}
function assertActive(context: Phase3OperationContext): void {
  if (context.signal.aborted) throw failure("operation_cancelled");
  if (!Number.isFinite(context.deadlineAt) || Date.now() >= context.deadlineAt)
    throw failure("deadline_exceeded");
}
function failure(code: string): Phase3CoordinatorError {
  return new Phase3CoordinatorError(
    code,
    `Home Assistant Phase 3 operation failed: ${code}`,
  );
}
