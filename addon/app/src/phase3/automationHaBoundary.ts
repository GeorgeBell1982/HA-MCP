import { randomUUID } from "node:crypto";
import { parseDocument } from "yaml";
import type { Config } from "../config.js";
import { HaWebSocketClient, deriveWebSocketUrl } from "../ha/websocket.js";
import {
  validateAndProjectYaml,
  type ProjectedYamlNode,
} from "../yaml/strictYamlGate.js";
import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
  type Phase3SourcePort,
  type Phase3ValidationPort,
} from "./applyCoordinator.js";
import { canonicalJson, sha256 } from "./contracts.js";
import { HomeAssistantPhase3Client } from "./homeAssistantAdapter.js";
import type { Phase3ValidationPhase } from "./validationAdapter.js";
import type {
  Phase3TrustedVerificationProbePort,
  Phase3VerificationProbeRequest,
  Phase3VerificationProbeResult,
} from "./verificationAdapter.js";

type SocketFactory = NonNullable<
  ConstructorParameters<typeof HaWebSocketClient>[3]
>;
type Automation = Record<string, unknown> & { id: string; alias: string };
const MAX_AUTOMATIONS = 100;
const TOP_KEYS = new Set([
  "id",
  "alias",
  "description",
  "trigger",
  "triggers",
  "condition",
  "conditions",
  "action",
  "actions",
  "mode",
  "initial_state",
]);

/** One plain automation file, fixed validation/observation commands, no effects. */
export class HomeAssistantAutomationBoundary
  implements Phase3ValidationPort, Phase3TrustedVerificationProbePort
{
  private readonly http: HomeAssistantPhase3Client;
  private readonly websocketUrl: URL;
  private readonly token: string;
  constructor(
    config: Pick<Config, "mode" | "baseUrl" | "token">,
    private readonly source: Pick<Phase3SourcePort, "read">,
    fetcher: typeof fetch = fetch,
    private readonly socketFactory?: SocketFactory,
  ) {
    this.http = new HomeAssistantPhase3Client(config, fetcher);
    this.websocketUrl = deriveWebSocketUrl(new URL(config.baseUrl.href));
    this.token = config.token;
  }

  async validate(
    bytes: Uint8Array,
    phase: Phase3ValidationPhase,
    context: Phase3OperationContext,
  ): Promise<void> {
    if (
      ![
        "checkpoint_pre_apply",
        "candidate_pre_apply",
        "candidate_post_apply",
        "checkpoint_post_rollback",
      ].includes(phase)
    )
      throw fail("invalid_phase");
    const automations = await parseAutomations(bytes, context);
    await this.withSocket(context, async (socket) => {
      for (const automation of automations) {
        assertActive(context);
        const result = await socket.request("validate_config", {
          triggers: automation.triggers ?? automation.trigger,
          conditions: automation.conditions ?? automation.condition ?? [],
          actions: automation.actions ?? automation.action,
        });
        assertActive(context);
        if (
          !object(result) ||
          ["triggers", "conditions", "actions"].some(
            (key) =>
              !object(result[key]) ||
              result[key].valid !== true ||
              result[key].error !== null,
          )
        )
          throw fail("ha_automation_invalid");
      }
    });
    if (
      phase === "candidate_post_apply" ||
      phase === "checkpoint_post_rollback"
    )
      await this.http.checkInstalledConfiguration(context);
  }

  async probe(
    request: Phase3VerificationProbeRequest,
    context: Phase3OperationContext,
  ): Promise<Phase3VerificationProbeResult> {
    if (
      request.path !== "automations.yaml" ||
      request.reloadTarget !== "automation.reload"
    )
      throw fail("unsupported_automation");
    const source = await this.source.read(request.path, context);
    let automations: Automation[];
    try {
      if (
        source.sha256 !== request.expectedSha256 ||
        sha256(source.bytes) !== request.expectedSha256
      )
        throw fail("ha_source_changed");
      automations = await parseAutomations(source.bytes, context);
    } finally {
      source.bytes.fill(0);
    }
    await this.withSocket(context, async (socket) => {
      const loaded = await this.http.automationStates(context);
      if (loaded.length !== automations.length)
        throw fail("ha_loaded_config_mismatch");
      for (const automation of automations) {
        assertActive(context);
        const matches = loaded.filter(
          (state) =>
            object(state) &&
            object(state.attributes) &&
            state.attributes.id === automation.id,
        );
        const state = matches[0];
        if (
          matches.length !== 1 ||
          !object(state) ||
          !["on", "off"].includes(String(state.state))
        )
          throw fail("ha_loaded_config_mismatch");
        const result = await socket.request("automation/config", {
          entity_id: state.entity_id,
        });
        assertActive(context);
        if (
          !object(result) ||
          !object(result.config) ||
          canonicalJson(result.config) !== canonicalJson(automation)
        )
          throw fail("ha_loaded_config_mismatch");
      }
    });
    return Object.freeze({
      status: "verified",
      transactionId: request.transactionId,
      outcome: request.outcome,
      expectedSha256: request.expectedSha256,
    });
  }

  private async withSocket<T>(
    context: Phase3OperationContext,
    operation: (socket: HaWebSocketClient) => Promise<T>,
  ): Promise<T> {
    assertActive(context);
    const socket = new HaWebSocketClient(
      new URL(this.websocketUrl.href),
      this.token,
      Math.max(1, Math.min(8_000, context.deadlineAt - Date.now())),
      this.socketFactory,
    );
    const signal = AbortSignal.any([
      context.signal,
      AbortSignal.timeout(
        Math.max(1, Math.ceil(context.deadlineAt - Date.now())),
      ),
    ]);
    let rejectCancellation!: (reason: Error) => void;
    const cancelled = new Promise<never>((_, reject) => {
      rejectCancellation = reject;
    });
    const onAbort = () => {
      socket.close();
      rejectCancellation(
        fail(
          context.signal.aborted ? "operation_cancelled" : "deadline_exceeded",
        ),
      );
    };
    signal.addEventListener("abort", onAbort, { once: true });
    try {
      if (signal.aborted) onAbort();
      return await Promise.race([
        cancelled,
        (async () => {
          await socket.connect(0);
          assertActive(context);
          return await operation(socket);
        })(),
      ]);
    } catch (error) {
      assertActive(context);
      if (error instanceof Phase3CoordinatorError) throw error;
      throw fail("ha_automation_unavailable");
    } finally {
      signal.removeEventListener("abort", onAbort);
      socket.close();
    }
  }
}

async function parseAutomations(
  bytes: Uint8Array,
  context: Phase3OperationContext,
): Promise<Automation[]> {
  assertActive(context);
  const owned = Uint8Array.from(bytes);
  try {
    const projection = await validateAndProjectYaml(owned, {
      ...context,
      operationId: randomUUID(),
      requestId: randomUUID(),
    });
    if (
      projection.metadata.references.length ||
      projection.metadata.aliasReferences ||
      !plain(projection.root)
    )
      throw fail("unsupported_automation");
    const document = parseDocument(
      new TextDecoder("utf-8", { fatal: true }).decode(owned),
      { version: "1.2", schema: "core", uniqueKeys: true, merge: false },
    );
    if (document.errors.length || document.warnings.length)
      throw fail("unsupported_automation");
    const parsed: unknown = document.toJS({ maxAliasCount: 0 });
    assertActive(context);
    if (!Array.isArray(parsed) || parsed.length > MAX_AUTOMATIONS)
      throw fail("unsupported_automation");
    const ids = new Set<string>();
    const result: Automation[] = [];
    for (const entry of parsed as unknown[]) {
      assertActive(context);
      if (
        !object(entry) ||
        Object.keys(entry).some((key) => !TOP_KEYS.has(key)) ||
        typeof entry.id !== "string" ||
        !entry.id ||
        entry.id.length > 128 ||
        ids.has(entry.id) ||
        typeof entry.alias !== "string" ||
        !entry.alias ||
        entry.alias.length > 256 ||
        (entry.description !== undefined &&
          (typeof entry.description !== "string" ||
            entry.description.length > 1024)) ||
        (entry.mode !== undefined &&
          (typeof entry.mode !== "string" ||
            !["single", "restart", "queued", "parallel"].includes(
              entry.mode,
            ))) ||
        (entry.initial_state !== undefined &&
          typeof entry.initial_state !== "boolean") ||
        !exclusive(entry, "trigger", "triggers", true) ||
        !exclusive(entry, "action", "actions", true) ||
        !exclusive(entry, "condition", "conditions", false) ||
        Buffer.byteLength(JSON.stringify(entry)) > 100_000
      )
        throw fail("unsupported_automation");
      ids.add(entry.id);
      result.push(entry as Automation);
    }
    return result;
  } finally {
    owned.fill(0);
  }
}
function exclusive(
  entry: Record<string, unknown>,
  first: string,
  second: string,
  required: boolean,
): boolean {
  const count =
    Number(Object.hasOwn(entry, first)) + Number(Object.hasOwn(entry, second));
  return required ? count === 1 : count <= 1;
}
function plain(root: ProjectedYamlNode | null): boolean {
  if (root === null) return true;
  if (
    !["map", "sequence", "scalar"].includes(root.kind) ||
    !("anchored" in root) ||
    root.anchored
  )
    return false;
  if (root.kind === "map")
    return root.entries.every(
      (entry) => entry.keyType === "string" && plain(entry.value),
    );
  if (root.kind === "sequence") return root.items.every(plain);
  return true;
}
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function assertActive(context: Phase3OperationContext): void {
  if (context.signal.aborted) throw fail("operation_cancelled");
  if (!Number.isFinite(context.deadlineAt) || Date.now() >= context.deadlineAt)
    throw fail("deadline_exceeded");
}
function fail(code: string): Phase3CoordinatorError {
  return new Phase3CoordinatorError(
    code,
    `Automation HA boundary failed: ${code}`,
  );
}
