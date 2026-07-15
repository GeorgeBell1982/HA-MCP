import { randomUUID } from "node:crypto";
import { JsonlAudit } from "./audit.js";
import { failure, SafeError, success, type Envelope } from "./domain.js";
import { HaRestClient, type HaState } from "./ha/rest.js";
import { redact } from "./redaction.js";
import { z } from "zod";
export interface ToolInput {
  entityId?: string | undefined;
  query?: string | undefined;
  domain?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}
export interface HaSystemLogClient {
  systemLogEntries(): Promise<unknown>;
}
const unsupported = new Set([
  "ha_list_dashboards",
  "ha_get_dashboard",
  "ha_list_blueprints",
]);
const domains: Record<string, string[]> = {
  ha_list_automations: ["automation"],
  ha_list_scripts: ["script"],
  ha_list_helpers: [
    "input_boolean",
    "input_number",
    "input_text",
    "input_select",
    "input_datetime",
    "counter",
    "timer",
    "schedule",
  ],
  ha_list_scenes: ["scene"],
};
const baseInput = z
  .object({
    query: z.string().max(200).optional(),
    domain: z
      .string()
      .regex(/^[a-z0-9_]+$/)
      .optional(),
    limit: z.number().int().min(1).max(500).optional(),
    cursor: z.string().max(100).optional(),
  })
  .strict();
const emptyInput = z.object({}).strict();
const entityInputs: Record<string, z.ZodType<ToolInput>> = {
  ha_get_entity_state: z
    .object({ entityId: z.string().regex(/^[a-z0-9_]+\.[a-z0-9_]+$/) })
    .strict(),
  ha_get_automation: z
    .object({ entityId: z.string().regex(/^automation\.[a-z0-9_]+$/) })
    .strict(),
  ha_get_script: z
    .object({ entityId: z.string().regex(/^script\.[a-z0-9_]+$/) })
    .strict(),
};
export class ReadTools {
  constructor(
    private readonly ha: HaRestClient,
    private readonly systemLog: HaSystemLogClient,
    private readonly audit: JsonlAudit,
  ) {}
  names(): string[] {
    return [
      "ha_get_system_info",
      "ha_list_entities",
      "ha_get_entity_state",
      "ha_search_entities",
      "ha_list_automations",
      "ha_get_automation",
      "ha_list_scripts",
      "ha_get_script",
      "ha_list_helpers",
      "ha_list_dashboards",
      "ha_get_dashboard",
      "ha_list_scenes",
      "ha_list_blueprints",
      "ha_get_config_status",
      "ha_get_recent_errors",
    ];
  }
  async call(name: string, rawInput: unknown): Promise<Envelope<unknown>> {
    const requestId = randomUUID();
    await this.audit.health();
    try {
      if (!this.names().includes(name))
        throw new SafeError("invalid_input", "Unknown tool");
      const schema =
        entityInputs[name] ??
        ([
          "ha_get_system_info",
          "ha_get_config_status",
          "ha_get_recent_errors",
          "ha_list_dashboards",
          "ha_list_blueprints",
        ].includes(name)
          ? emptyInput
          : baseInput);
      const parsed = schema.safeParse(rawInput);
      if (!parsed.success)
        throw new SafeError(
          "invalid_input",
          "Tool input failed schema validation",
        );
      const input = parsed.data as ToolInput;
      let data: unknown;
      let evidence = "Home Assistant documented REST API";
      if (unsupported.has(name))
        throw new SafeError(
          "capability_unavailable",
          "No documented Home Assistant API is available for this storage-backed resource",
        );
      if (name === "ha_get_system_info" || name === "ha_get_config_status")
        data = await this.ha.config();
      else if (
        name === "ha_get_entity_state" ||
        name === "ha_get_automation" ||
        name === "ha_get_script"
      ) {
        if (!input.entityId)
          throw new SafeError("invalid_input", "entityId is required");
        data = await this.ha.state(input.entityId);
      } else if (name === "ha_get_recent_errors") {
        data = summarizeSystemLogEntries(
          await this.systemLog.systemLogEntries(),
        );
        evidence = "Home Assistant system_log/list WebSocket API";
      } else {
        const all = await this.ha.states();
        const wanted = domains[name];
        const query = input.query?.toLowerCase();
        const matches = all.filter(
          (s) =>
            (!wanted || wanted.includes(s.entity_id.split(".")[0] ?? "")) &&
            (!input.domain || s.entity_id.startsWith(`${input.domain}.`)) &&
            (!query ||
              `${s.entity_id} ${typeof s.attributes.friendly_name === "string" ? s.attributes.friendly_name : ""}`
                .toLowerCase()
                .includes(query)),
        );
        data = paginate(matches, input);
      }
      const result = success(requestId, redact(data), [evidence]);
      await this.audit.append({
        timestamp: new Date().toISOString(),
        tool: name,
        requestId,
        result: "success",
        risk: "read-only",
      });
      return result;
    } catch (e) {
      const error =
        e instanceof SafeError
          ? e
          : new SafeError("upstream_error", "Request failed safely");
      await this.audit.append({
        timestamp: new Date().toISOString(),
        tool: name,
        requestId,
        result: "failure",
        risk: "read-only",
        error: error.message,
      });
      return failure(requestId, error);
    }
  }
}
function paginate(states: HaState[], input: ToolInput) {
  const limit = Math.min(Math.max(input.limit ?? 100, 1), 500);
  const offset = decodeCursor(input.cursor);
  const items = states.slice(offset, offset + limit);
  return {
    items,
    pagination: {
      truncated: offset + limit < states.length,
      nextCursor:
        offset + limit < states.length
          ? Buffer.from(String(offset + limit)).toString("base64url")
          : undefined,
    },
  };
}
function decodeCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  if (!/^[A-Za-z0-9_-]+$/.test(cursor))
    throw new SafeError("invalid_input", "Invalid cursor");
  const decoded = Buffer.from(cursor, "base64url").toString("utf8");
  if (!/^(0|[1-9]\d*)$/.test(decoded))
    throw new SafeError("invalid_input", "Invalid cursor");
  if (Buffer.from(decoded).toString("base64url") !== cursor)
    throw new SafeError("invalid_input", "Invalid cursor");
  const offset = Number(decoded);
  if (!Number.isSafeInteger(offset))
    throw new SafeError("invalid_input", "Invalid cursor");
  return offset;
}

export function summarizeSystemLogEntries(raw: unknown) {
  if (!Array.isArray(raw))
    throw new SafeError(
      "upstream_error",
      "Home Assistant system log response was invalid",
    );
  const summaries = raw.slice(0, 50).map((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new SafeError(
        "upstream_error",
        "Home Assistant system log response was invalid",
      );
    const entry = value as Record<string, unknown>;
    if (
      typeof entry.name !== "string" ||
      !Array.isArray(entry.message) ||
      entry.message.length > 5 ||
      !entry.message.every((message) => typeof message === "string") ||
      typeof entry.level !== "string" ||
      !Array.isArray(entry.source) ||
      entry.source.length !== 2 ||
      typeof entry.source[0] !== "string" ||
      !Number.isSafeInteger(entry.source[1]) ||
      (entry.source[1] as number) < 0 ||
      !Number.isSafeInteger(entry.count) ||
      (entry.count as number) < 1
    )
      throw new SafeError(
        "upstream_error",
        "Home Assistant system log response was invalid",
      );
    const timestamp = normalizeTimestamp(entry.timestamp);
    const firstOccurred = normalizeTimestamp(entry.first_occurred);
    return {
      name: entry.name.slice(0, 200),
      messages: entry.message.map((message) => message.slice(0, 500)),
      level: entry.level.slice(0, 50),
      source: entry.source[0].slice(0, 500) + ":" + entry.source[1],
      timestamp,
      firstOccurred,
      count: entry.count,
    };
  });
  return { count: summaries.length, summaries, truncated: raw.length > 50 };
}

function normalizeTimestamp(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value))
    throw new SafeError(
      "upstream_error",
      "Home Assistant system log response was invalid",
    );
  const milliseconds = value * 1000;
  if (
    !Number.isFinite(milliseconds) ||
    Math.abs(milliseconds) > 8_640_000_000_000_000
  )
    throw new SafeError(
      "upstream_error",
      "Home Assistant system log response was invalid",
    );
  const date = new Date(milliseconds);
  if (Number.isNaN(date.getTime()))
    throw new SafeError(
      "upstream_error",
      "Home Assistant system log response was invalid",
    );
  return date.toISOString();
}
