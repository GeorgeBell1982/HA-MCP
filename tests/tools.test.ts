import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonlAudit } from "../src/audit.js";
import { ReadTools } from "../src/application.js";
import type { HaRestClient } from "../src/ha/rest.js";
const ha = {
  config: async () => ({ version: "2026.7.1" }),
  states: async () => [
    {
      entity_id: "automation.test",
      state: "on",
      attributes: { friendly_name: "Test" },
      last_changed: "",
      last_updated: "",
    },
  ],
  state: async (id: string) => ({
    entity_id: id,
    state: "on",
    attributes: {},
    last_changed: "",
    last_updated: "",
  }),
  errors: async () => "ERROR password=canary",
} as unknown as HaRestClient;
describe("read tools", () => {
  it("paginates and filters", async () => {
    const audit = new JsonlAudit(
      join(await mkdtemp(join(tmpdir(), "tools-")), "a.jsonl"),
    );
    const result = await new ReadTools(ha, audit).call("ha_list_automations", {
      limit: 1,
    });
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).toContain("automation.test");
  });
  it("returns typed unavailable for dashboards", async () => {
    const audit = new JsonlAudit(
      join(await mkdtemp(join(tmpdir(), "tools-")), "a.jsonl"),
    );
    const result = await new ReadTools(ha, audit).call(
      "ha_list_dashboards",
      {},
    );
    expect(result.error?.code).toBe("capability_unavailable");
  });
  it("audits schema and wrong-domain failures", async () => {
    const root = await mkdtemp(join(tmpdir(), "tools-"));
    const path = join(root, "a.jsonl");
    const tools = new ReadTools(ha, new JsonlAudit(path));
    expect(
      (await tools.call("ha_get_script", { entityId: "automation.wrong" }))
        .error?.code,
    ).toBe("invalid_input");
    expect(
      (await tools.call("ha_list_entities", { limit: "bad" })).error?.code,
    ).toBe("invalid_input");
    const audit = await import("node:fs/promises").then((fs) =>
      fs.readFile(path, "utf8"),
    );
    expect(audit.trim().split("\n")).toHaveLength(2);
  });
});
