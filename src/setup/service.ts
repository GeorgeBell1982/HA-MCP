import { createHash } from "node:crypto";
import { z } from "zod";
import { SafeError } from "../domain.js";
import type { GuardedActionService, GuardedPlan } from "../guardedChanges.js";
import { redact } from "../redaction.js";
import type { SetupApiClient } from "./api.js";

const id = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,128}$/)
  .refine((s) => s !== "self");
const field = z.union([
  z.string().max(2048),
  z.number().finite(),
  z.boolean(),
  z.array(z.string().max(256)).max(100),
]);
const fields = z.record(field).refine((v) => Object.keys(v).length <= 64);
const githubRepository = z
  .string()
  .max(160)
  .regex(
    /^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/,
  )
  .refine((s) => !s.includes(".."));
export const setupChangeInput = z.discriminatedUnion("action", [
  z.object({ action: z.literal("core_restart") }).strict(),
  z.object({ action: z.literal("app_restart"), slug: id }).strict(),
  z
    .object({
      action: z.literal("hacs_add_repository"),
      repository: githubRepository,
      category: z.enum(["integration", "plugin"]),
    })
    .strict(),
  z
    .object({
      action: z.literal("app_add_repository"),
      repository: githubRepository,
    })
    .strict(),
  z.object({ action: z.literal("integration_start"), domain: id }).strict(),
  z
    .object({ action: z.literal("integration_submit"), flowId: id, fields })
    .strict(),
  z
    .object({
      action: z.literal("hacs_install"),
      repositoryId: id,
      version: z.string().min(1).max(128),
    })
    .strict(),
  z.object({ action: z.literal("app_install"), slug: id }).strict(),
  z
    .object({ action: z.literal("app_options"), slug: id, options: fields })
    .strict(),
  z.object({ action: z.literal("app_start"), slug: id }).strict(),
]);
type SetupChange = z.infer<typeof setupChangeInput>;
const payloadSchema = z
  .object({
    change: setupChangeInput,
    baseline: z.string().length(64),
    expectedVersion: z.string().optional(),
    expectedOptionsHash: z.string().length(64).optional(),
  })
  .strict();

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new SafeError("upstream_error", "Setup API object was invalid");
  return value as Record<string, unknown>;
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value))
    throw new SafeError("upstream_error", "Setup API list was invalid");
  return value;
}
function select(value: Record<string, unknown>, keys: readonly string[]) {
  return Object.fromEntries(
    keys.filter((k) => value[k] !== undefined).map((k) => [k, value[k]]),
  );
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, canonical(v)]),
    );
  return value;
}
function hash(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
}
const sensitive =
  /password|passwd|token|secret|credential|api.?key|private.?key|authorization|webhook|access.?key|client.?id|username|email|account|(^|_)pin($|_)|certificate|^(key|code|auth)$/i;
function sanitize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        sensitive.test(key) || /default|suggested_value/.test(key)
          ? "[REDACTED]"
          : sanitize(item),
      ]),
    );
  return redact(value);
}
function assertSafeFields(values: Record<string, unknown>) {
  for (const [key, value] of Object.entries(values)) {
    if (
      !/^[a-zA-Z0-9_]{1,80}$/.test(key) ||
      ["__proto__", "constructor", "prototype"].includes(key) ||
      sensitive.test(key) ||
      JSON.stringify(redact(value)) !== JSON.stringify(value)
    )
      throw new SafeError(
        "capability_unavailable",
        "Credential fields require secure Home Assistant authentication; never paste secrets into tool arguments",
      );
  }
}
function appTarget(slug: string) {
  if (slug.endsWith("_home_assistant_engineering_mcp"))
    throw new SafeError(
      "capability_unavailable",
      "The MCP app cannot manage itself through setup tools",
    );
}

export class SetupService {
  // A cached POST result is passive to read. Core flow GET is not passive.
  private readonly flows = new Map<string, Record<string, unknown>>();
  constructor(
    private readonly api: SetupApiClient,
    private readonly actions: GuardedActionService,
  ) {
    actions.register("setup", {
      inspect: (plan) => this.inspect(plan),
      execute: (plan) => this.execute(plan),
      verify: (plan, result) => this.verify(plan, result),
    });
  }

  async catalog(kind: "integration" | "hacs" | "app", query = "", limit = 100) {
    let result: unknown[];
    if (kind === "integration") {
      result = array(await this.api.flowHandlers()).map((domain) => {
        if (typeof domain !== "string" || !id.safeParse(domain).success)
          throw new SafeError("upstream_error", "Invalid integration domain");
        return { domain };
      });
    } else if (kind === "hacs") {
      result = (await this.hacsRepositories()).map((r) =>
        select(r, [
          "id",
          "full_name",
          "name",
          "category",
          "domain",
          "installed",
          "installed_version",
          "available_version",
          "can_download",
          "config_flow",
        ]),
      );
    } else {
      const raw = await this.api.appCatalog();
      result = array(Array.isArray(raw) ? raw : object(raw).addons).map((r) =>
        select(object(r), [
          "slug",
          "name",
          "description",
          "repository",
          "version",
          "version_latest",
          "installed",
          "state",
        ]),
      );
    }
    result = result.filter((v) =>
      JSON.stringify(v).toLowerCase().includes(query.toLowerCase()),
    );
    return {
      kind,
      items: redact(result.slice(0, limit)),
      total: result.length,
      truncated: result.length > limit,
    };
  }

  async status(kind: "integration" | "flow" | "hacs" | "app", target?: string) {
    if (kind === "integration")
      return {
        entries: redact(
          array(await this.api.entries()).map((v) =>
            select(object(v), [
              "entry_id",
              "domain",
              "state",
              "disabled_by",
              "source",
            ]),
          ),
        ),
      };
    if (!target)
      throw new SafeError("invalid_input", "Setup status requires a target");
    if (kind === "flow") return this.publicFlow(this.cachedFlow(target));
    if (kind === "hacs") return redact(await this.hacsRepository(target));
    const info = object(await this.api.appInfo(target));
    return sanitize(
      select(info, [
        "slug",
        "name",
        "version",
        "version_latest",
        "state",
        "repository",
        "schema",
        "options",
        "protected",
        "privileged",
        "full_access",
        "host_network",
        "host_pid",
        "docker_api",
        "hassio_role",
        "system_managed",
      ]),
    );
  }

  async propose(raw: unknown) {
    const change = setupChangeInput.parse(raw);
    if (change.action === "integration_submit") assertSafeFields(change.fields);
    if (change.action === "app_options") assertSafeFields(change.options);
    if ("slug" in change) appTarget(change.slug);
    const state = await this.state(change);
    this.validate(change, state);
    const target =
      "domain" in change
        ? change.domain
        : "flowId" in change
          ? change.flowId
          : "repositoryId" in change
            ? change.repositoryId
            : "slug" in change
              ? change.slug
              : "repository" in change
                ? change.repository
                : "system:core";
    const summary = {
      action: change.action,
      target,
      requested: change,
      before: sanitize(this.publicState(change, state)),
      impact:
        change.action === "core_restart"
          ? "Disruptive: restarts Home Assistant Core once, temporarily interrupting automations, integrations and UI. Verifies Core returns to RUNNING. Never retries the restart."
          : change.action === "app_restart"
            ? "Disruptive: restarts the specified app once and verifies it returns to started. Never retries the restart."
            : change.action === "hacs_install"
              ? "Downloads and installs third-party code through HACS. Integration code may require a separately approved Core restart. Frontend code runs in browsers."
              : change.action === "app_install"
                ? "Installs a third-party app with the displayed declared privileges; does not start it."
                : change.action === "integration_submit"
                  ? "Refreshes the current integration flow, then submits only the approved fields if the step and schema still match. A refresh can advance the flow."
                  : change.action === "app_start"
                    ? "Starts the specified app and its configured workloads."
                    : change.action === "app_options"
                      ? "Merges these non-secret options into existing options; preserves other options. Does not restart the app."
                      : change.action === "hacs_add_repository" ||
                          change.action === "app_add_repository"
                        ? "Registers the exact GitHub repository as a third-party setup source. Its code is untrusted; install requires a separate approved proposal."
                        : "Starts the selected integration's setup flow. The integration can create an entry or request authentication.",
    };
    return this.actions.propose({
      kind: "setup",
      target,
      summary,
      payload: {
        change,
        baseline: hash(state),
        ...(change.action === "app_install"
          ? {
              expectedVersion:
                object(state).version_latest ?? object(state).version,
            }
          : {}),
        ...(change.action === "app_options"
          ? {
              expectedOptionsHash: hash({
                ...object(object(state).options),
                ...change.options,
              }),
            }
          : {}),
      },
    });
  }

  private async hacsRepositories() {
    return array(await this.api.hacsCatalog())
      .map(object)
      .filter((r) => r.category === "integration" || r.category === "plugin");
  }
  private async hacsRepository(target: string) {
    const repo = (await this.hacsRepositories()).find(
      (r) => String(r.id) === target,
    );
    if (!repo)
      throw new SafeError(
        "not_found",
        "HACS repository not found in the configured catalog",
      );
    return select(repo, [
      "id",
      "full_name",
      "name",
      "category",
      "domain",
      "installed",
      "installed_version",
      "available_version",
      "can_download",
      "config_flow",
    ]);
  }
  private cachedFlow(target: string) {
    const flow = this.flows.get(target);
    if (!flow)
      throw new SafeError(
        "not_found",
        "Flow was not started in this runtime; inspect integration entries or resume securely in Home Assistant",
      );
    return flow;
  }
  private async state(change: SetupChange): Promise<unknown> {
    switch (change.action) {
      case "core_restart":
        return {
          core: select(object(await this.api.coreInfo()), [
            "version",
            "image",
            "boot",
            "ssl",
            "port",
          ]),
          readiness: select(object(await this.api.coreConfig()), [
            "version",
            "state",
          ]),
        };
      case "app_restart": {
        const info = object(await this.api.appInfo(change.slug));
        return select(info, [
          "slug",
          "version",
          "state",
          "options",
          "system_managed",
        ]);
      }
      case "hacs_add_repository":
        return (await this.hacsRepositories()).map((r) =>
          select(r, ["id", "full_name", "category"]),
        );
      case "app_add_repository":
        return this.api.appRepositories();
      case "integration_start":
        return {
          frontendOrigin: await this.api.setupFrontendOrigin(),
          handlers: array(await this.api.flowHandlers()),
          entries: await this.api.entries(),
        };
      case "integration_submit":
        return {
          ...this.cachedFlow(change.flowId),
          frontendOrigin: await this.api.setupFrontendOrigin(),
        };
      case "hacs_install":
        return this.hacsRepository(change.repositoryId);
      case "app_install":
        return this.api.appStoreInfo(change.slug);
      case "app_options":
        return this.api.appInfo(change.slug);
      case "app_start": {
        const info = object(await this.api.appInfo(change.slug));
        return select(info, [
          "slug",
          "version",
          "state",
          "options",
          "system_managed",
        ]);
      }
    }
  }
  private publicState(change: SetupChange, state: unknown) {
    if (change.action === "core_restart") return state;
    if (
      change.action === "hacs_add_repository" ||
      change.action === "app_add_repository"
    )
      return state;
    if (change.action === "integration_start")
      return {
        frontendOrigin: object(state).frontendOrigin,
        entries: array(object(state).entries).map((entry) =>
          select(object(entry), [
            "entry_id",
            "domain",
            "state",
            "disabled_by",
            "source",
          ]),
        ),
      };
    if (change.action === "integration_submit")
      return {
        flow: this.publicFlow(object(state)),
        frontendOrigin: object(state).frontendOrigin,
      };
    if (change.action === "hacs_install") return state;
    return select(object(state), [
      "slug",
      "name",
      "version",
      "version_latest",
      "installed",
      "state",
      "repository",
      "options",
      "schema",
      "privileged",
      "full_access",
      "host_network",
      "host_pid",
      "docker_api",
      "hassio_role",
      "signed",
      "protected",
      "system_managed",
    ]);
  }
  private validate(change: SetupChange, state: unknown) {
    if (change.action === "core_restart") {
      if (object(object(state).readiness).state !== "RUNNING")
        throw new SafeError(
          "invalid_input",
          "Core must be RUNNING before proposing a restart",
        );
      return;
    }
    if (change.action === "hacs_add_repository") {
      if (
        array(state)
          .map(object)
          .some(
            (r) =>
              String(r.full_name).toLowerCase() ===
              change.repository.toLowerCase(),
          )
      )
        throw new SafeError(
          "invalid_input",
          "HACS repository is already registered",
        );
      return;
    }
    if (change.action === "app_add_repository") {
      const raw = Array.isArray(state) ? state : object(state).repositories;
      if (
        array(raw)
          .map(object)
          .some((r) => r.source === `https://github.com/${change.repository}`)
      )
        throw new SafeError(
          "invalid_input",
          "App repository is already registered",
        );
      return;
    }
    const s = object(state);
    if (change.action === "integration_start") {
      if (!array(s.handlers).includes(change.domain))
        throw new SafeError(
          "not_found",
          "Integration has no loaded config-flow handler; installed custom code may require Core restart first",
        );
    } else if (change.action === "integration_submit") {
      if (s.type === "menu") {
        if (
          !Array.isArray(s.menu_options) ||
          s.menu_options.length > 64 ||
          !s.menu_options.every(
            (v) => typeof v === "string" && /^[a-zA-Z0-9_]{1,80}$/.test(v),
          ) ||
          Object.keys(change.fields).length !== 1 ||
          typeof change.fields.next_step_id !== "string" ||
          !s.menu_options.includes(change.fields.next_step_id)
        )
          throw new SafeError(
            "capability_unavailable",
            "Select exactly one offered integration menu step; unsupported menu requires secure Home Assistant handoff",
          );
        return;
      }
      if (s.type !== "form" || !Array.isArray(s.data_schema))
        throw new SafeError(
          "capability_unavailable",
          "This step requires secure authentication or an unsupported integration flow; use Home Assistant's integration screen",
        );
      const schema = s.data_schema.map(object);
      for (const key of Object.keys(change.fields)) {
        const entry = schema.find((f) => f.name === key);
        if (
          !entry ||
          sensitive.test(key) ||
          (entry.selector &&
            /password|secret|credential/.test(JSON.stringify(entry.selector)))
        )
          throw new SafeError(
            "capability_unavailable",
            "Field is unknown or requires secure authentication",
          );
      }
      if (
        schema.some(
          (f) =>
            f.required === true &&
            (sensitive.test(String(f.name)) ||
              /password|secret|credential/.test(
                JSON.stringify(f.selector ?? {}),
              )),
        )
      )
        throw new SafeError(
          "capability_unavailable",
          "Required credentials must be supplied through Home Assistant's secure integration form",
        );
    } else if (change.action === "hacs_install") {
      if (s.installed === true)
        throw new SafeError(
          "capability_unavailable",
          "HACS setup installs new repositories only; updates require a separate capability",
        );
      if (s.can_download !== true || s.available_version !== change.version)
        throw new SafeError(
          "invalid_input",
          "Requested HACS version is unavailable or changed",
        );
    } else {
      if (s.system_managed === true)
        throw new SafeError(
          "capability_unavailable",
          "System-managed apps cannot be changed through setup tools",
        );
      if (change.action === "app_install" && s.installed)
        throw new SafeError("invalid_input", "App is already installed");
      if (
        change.action === "app_install" &&
        typeof (s.version_latest ?? s.version) !== "string"
      )
        throw new SafeError(
          "upstream_error",
          "App catalog version is unavailable",
        );
      if (change.action === "app_start" && s.state !== "stopped")
        throw new SafeError(
          "invalid_input",
          "App must be stopped before a start proposal",
        );
      if (change.action === "app_options") {
        if (Object.keys(change.options).length === 0)
          throw new SafeError(
            "invalid_input",
            "App option change must include at least one field",
          );
        object(s.options);
        const schema = object(s.schema);
        for (const key of Object.keys(change.options)) {
          if (
            !(key in schema) ||
            sensitive.test(key) ||
            /password|secret|credential/i.test(JSON.stringify(schema[key]))
          )
            throw new SafeError(
              "capability_unavailable",
              "App option is unknown or requires secure authentication",
            );
        }
      }
      if (change.action === "app_restart" && s.state !== "started")
        throw new SafeError(
          "invalid_input",
          "App must be started before a restart proposal",
        );
    }
  }
  private async inspect(plan: GuardedPlan) {
    const { change, baseline } = payloadSchema.parse(plan.payload);
    const state = await this.state(change);
    this.validate(change, state);
    if (hash(state) !== baseline)
      throw new SafeError(
        "invalid_input",
        "Setup target changed after proposal; prepare a new proposal",
      );
  }
  private async execute(plan: GuardedPlan) {
    const { change } = payloadSchema.parse(plan.payload);
    switch (change.action) {
      case "core_restart":
        await this.api.restartCore();
        return { submitted: true };
      case "app_restart":
        await this.api.restartApp(change.slug);
        return { submitted: true };
      case "hacs_add_repository":
        await this.api.addHacsRepository(change.repository, change.category);
        return { submitted: true };
      case "app_add_repository":
        await this.api.addAppRepository(
          `https://github.com/${change.repository}`,
        );
        return { submitted: true };
      case "integration_start":
        return this.captureFlow(
          await this.api.startFlow(change.domain),
          change.domain,
        );
      case "integration_submit": {
        const previous = this.cachedFlow(change.flowId);
        const fresh = object(await this.api.refreshFlow(change.flowId));
        this.captureFlow(fresh, String(previous.handler), change.flowId);
        if (
          hash(
            select(fresh, ["type", "step_id", "data_schema", "menu_options"]),
          ) !==
          hash(
            select(previous, [
              "type",
              "step_id",
              "data_schema",
              "menu_options",
            ]),
          )
        ) {
          throw new SafeError(
            "upstream_error",
            "Integration flow advanced during approved refresh; inspect status before another proposal",
          );
        }
        return this.captureFlow(
          await this.api.submitFlow(change.flowId, change.fields),
          String(previous.handler),
          change.flowId,
        );
      }
      case "hacs_install":
        await this.api.installHacs(change.repositoryId, change.version);
        return { submitted: true };
      case "app_install":
        await this.api.installApp(change.slug);
        return { submitted: true };
      case "app_options": {
        const info = object(await this.api.appInfo(change.slug));
        const { baseline } = payloadSchema.parse(plan.payload);
        if (hash(info) !== baseline)
          throw new SafeError(
            "invalid_input",
            "App options changed before save",
          );
        await this.api.appOptions(change.slug, {
          ...object(info.options),
          ...change.options,
        });
        return { submitted: true };
      }
      case "app_start":
        await this.api.startApp(change.slug);
        return { submitted: true };
    }
  }
  private captureFlow(
    raw: unknown,
    expectedDomain: string,
    expectedFlowId?: string,
  ) {
    const flow = object(raw);
    const terminal = flow.type === "create_entry" || flow.type === "abort";
    if (
      typeof flow.type !== "string" ||
      ![
        "form",
        "menu",
        "external",
        "external_done",
        "show_progress",
        "show_progress_done",
        "create_entry",
        "abort",
      ].includes(flow.type) ||
      (!terminal &&
        (flow.handler !== expectedDomain ||
          typeof flow.flow_id !== "string" ||
          !id.safeParse(flow.flow_id).success)) ||
      (flow.handler !== undefined && flow.handler !== expectedDomain) ||
      (expectedFlowId !== undefined &&
        flow.flow_id !== undefined &&
        flow.flow_id !== expectedFlowId) ||
      (flow.type === "create_entry" &&
        object(flow.result).domain !== expectedDomain)
    )
      throw new SafeError(
        "upstream_error",
        "Integration flow response was invalid",
      );
    if (typeof flow.flow_id === "string") {
      if (this.flows.size >= 64 && !this.flows.has(flow.flow_id))
        this.flows.delete(this.flows.keys().next().value!);
      this.flows.set(flow.flow_id, flow);
    }
    return this.publicFlow(flow);
  }
  private publicFlow(flow: Record<string, unknown>) {
    const result = select(flow, [
      "type",
      "flow_id",
      "handler",
      "step_id",
      "reason",
      "errors",
    ]);
    const simpleMenu =
      flow.type === "menu" &&
      Array.isArray(flow.menu_options) &&
      flow.menu_options.length <= 64 &&
      flow.menu_options.every(
        (v) => typeof v === "string" && /^[a-zA-Z0-9_]{1,80}$/.test(v),
      );
    if (simpleMenu) result.menuOptions = flow.menu_options;
    if (Array.isArray(flow.data_schema))
      result.fields = flow.data_schema.map((raw) => {
        const f = object(raw);
        return {
          ...select(f, ["name", "required", "type", "selector"]),
          sensitive:
            sensitive.test(String(f.name)) ||
            /password|secret|credential/.test(JSON.stringify(f.selector ?? {})),
        };
      });
    if (flow.type === "create_entry")
      result.entry = select(object(flow.result), [
        "entry_id",
        "domain",
        "state",
      ]);
    if (
      [
        "external",
        "external_done",
        "show_progress",
        "show_progress_done",
      ].includes(String(flow.type)) ||
      (flow.type === "menu" && !simpleMenu) ||
      (flow.type === "form" && !Array.isArray(flow.data_schema)) ||
      (Array.isArray(result.fields) &&
        result.fields.some((f) => object(f).sensitive))
    )
      result.secureHandoff = {
        path: "/config/integrations",
        reason:
          "Complete provider authentication or secret input only inside Home Assistant. OAuth tokens and passwords are never returned to chat.",
      };
    return sanitize(result);
  }
  private async verify(plan: GuardedPlan, result: unknown) {
    const { change, expectedVersion, expectedOptionsHash } =
      payloadSchema.parse(plan.payload);
    if (change.action === "core_restart") {
      const config = await this.waitReady(
        () => this.api.coreConfig(),
        (v) => v.state === "RUNNING",
      );
      return { verified: true, core: select(config, ["version", "state"]) };
    }
    if (change.action === "hacs_add_repository") {
      const repository = (await this.hacsRepositories()).find(
        (r) =>
          String(r.full_name).toLowerCase() ===
            change.repository.toLowerCase() && r.category === change.category,
      );
      if (!repository)
        throw new SafeError(
          "upstream_error",
          "HACS repository registration verification failed",
        );
      return {
        verified: true,
        repository: select(repository, [
          "id",
          "full_name",
          "category",
          "available_version",
        ]),
      };
    }
    if (change.action === "app_add_repository") {
      const raw = await this.api.appRepositories();
      const repositories = array(
        Array.isArray(raw) ? raw : object(raw).repositories,
      ).map(object);
      const repository = repositories.find(
        (r) => r.source === `https://github.com/${change.repository}`,
      );
      if (!repository)
        throw new SafeError(
          "upstream_error",
          "App repository registration verification failed",
        );
      return {
        verified: true,
        repository: select(repository, ["slug", "name", "source"]),
      };
    }
    if (
      change.action === "integration_start" ||
      change.action === "integration_submit"
    ) {
      const flow = object(result);
      if (flow.type === "create_entry") {
        const entry = object(flow.entry);
        const entries = array(await this.api.entries()).map(object);
        if (!entries.some((e) => e.entry_id === entry.entry_id))
          throw new SafeError(
            "upstream_error",
            "Created integration entry was not found",
          );
      }
      return { verified: true, complete: flow.type === "create_entry", flow };
    }
    if (change.action === "hacs_install") {
      const repo = await this.hacsRepository(change.repositoryId);
      if (repo.installed !== true || repo.installed_version !== change.version)
        throw new SafeError(
          "upstream_error",
          "HACS installed version verification failed",
        );
      return {
        verified: true,
        repository: redact(repo),
        requireCoreRestart: repo.category === "integration",
      };
    }
    const app =
      change.action === "app_restart" || change.action === "app_start"
        ? await this.waitReady(
            () => this.api.appInfo(change.slug),
            (v) => v.state === "started",
          )
        : object(await this.api.appInfo(change.slug));
    if (change.action === "app_install" && app.version !== expectedVersion)
      throw new SafeError(
        "upstream_error",
        "App installation verification failed",
      );
    if (change.action === "app_install") {
      const rawInstalled = await this.api.installedApps();
      const installed = array(
        Array.isArray(rawInstalled)
          ? rawInstalled
          : object(rawInstalled).addons,
      ).map(object);
      if (
        !installed.some(
          (a) => a.slug === change.slug && a.version === expectedVersion,
        ) ||
        !["started", "stopped"].includes(String(app.state))
      )
        throw new SafeError(
          "upstream_error",
          "App was not proven installed by Supervisor's installed-only inventory",
        );
    }
    if (
      (change.action === "app_start" || change.action === "app_restart") &&
      app.state !== "started"
    )
      throw new SafeError("upstream_error", "App did not reach started state");
    if (change.action === "app_options") {
      const options = object(app.options);
      if (hash(options) !== expectedOptionsHash)
        throw new SafeError(
          "upstream_error",
          "App option preservation verification failed",
        );
      if (
        Object.entries(change.options).some(
          ([key, value]) =>
            options[key] === undefined || hash(options[key]) !== hash(value),
        )
      )
        throw new SafeError(
          "upstream_error",
          "App options verification failed",
        );
    }
    return {
      verified: true,
      app: redact(select(app, ["slug", "version", "state"])),
    };
  }
  private async waitReady(
    read: () => Promise<unknown>,
    ready: (value: Record<string, unknown>) => boolean,
  ): Promise<Record<string, unknown>> {
    // Six 15-second reads plus five 2-second intervals: bounded to 100 seconds.
    for (let attempt = 0; attempt < 6; attempt++) {
      try {
        const value = object(await read());
        if (ready(value)) return value;
      } catch (error) {
        if (error instanceof SafeError && error.code === "auth_failed")
          throw error;
      }
      if (attempt < 5)
        await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    throw new SafeError(
      "upstream_error",
      "Setup restart readiness verification failed; do not repeat the restart",
    );
  }
}
