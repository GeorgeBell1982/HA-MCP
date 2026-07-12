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
      } else if (name === "ha_get_recent_errors")
        data = summarizeErrors(await this.ha.errors());
      else {
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
      const result = success(requestId, redact(data), [
        "Home Assistant documented REST API",
      ]);
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
  const offset = input.cursor
    ? Number(Buffer.from(input.cursor, "base64url").toString("utf8"))
    : 0;
  if (!Number.isSafeInteger(offset) || offset < 0)
    throw new SafeError("invalid_input", "Invalid cursor");
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
export function summarizeErrors(raw: string) {
  const cleaned = String(redact(raw))
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-50)
    .map((line) => line.slice(0, 500));
  return {
    count: cleaned.length,
    summaries: cleaned,
    truncated: raw.split(/\r?\n/).length > 50,
  };
}
