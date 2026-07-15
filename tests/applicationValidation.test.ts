import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonlAudit } from "../src/audit.js";
import { ReadTools, type HaSystemLogClient } from "../src/application.js";
import type { HaRestClient, HaState } from "../src/ha/rest.js";

const states: HaState[] = ["first", "second", "third"].map((id) => ({
  entity_id: `light.${id}`,
  state: "on",
  attributes: {},
  last_changed: "",
  last_updated: "",
}));

const ha = {
  config: async () => ({ version: "2026.7.2" }),
  states: async () => states,
  state: async (entityId: string) =>
    states.find((item) => item.entity_id === entityId),
} as unknown as HaRestClient;

async function toolsWith(systemLogEntries: () => Promise<unknown>) {
  const audit = new JsonlAudit(
    join(
      await mkdtemp(join(tmpdir(), "application-validation-")),
      "audit.jsonl",
    ),
  );
  return new ReadTools(
    ha,
    { systemLogEntries } satisfies HaSystemLogClient,
    audit,
  );
}

function entry(index = 0) {
  return {
    name: `component.${index}`,
    message: ["password=canary", "/api/webhook/canary", "x".repeat(600)],
    level: "ERROR",
    source: ["component/file.py", 42],
    timestamp: 1_700_000_000 + index,
    first_occurred: 1_699_999_000 + index,
    count: 2,
    exception: "must not be returned",
  };
}

describe("application input and upstream validation", () => {
  it("normalizes, bounds, redacts, and attributes system-log results", async () => {
    const tools = await toolsWith(async () => [entry()]);
    const result = await tools.call("ha_get_recent_errors", {});
    expect(result.ok).toBe(true);
    expect(result.evidence).toEqual([
      "Home Assistant system_log/list WebSocket API",
    ]);
    expect(result.data).toMatchObject({
      count: 1,
      truncated: false,
      summaries: [
        {
          name: "component.0",
          level: "ERROR",
          source: "component/file.py:42",
          timestamp: "2023-11-14T22:13:20.000Z",
          firstOccurred: "2023-11-14T21:56:40.000Z",
          count: 2,
        },
      ],
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("canary");
    expect(serialized).not.toContain("must not be returned");
    const messages = (
      result.data as { summaries: Array<{ messages: string[] }> }
    ).summaries[0]!.messages;
    expect(messages).toHaveLength(3);
    expect(messages[2]).toHaveLength(500);
  });

  it("rejects malformed system-log arrays and consumed fields", async () => {
    for (const raw of [
      {},
      [null],
      [{ ...entry(), message: ["a", "b", "c", "d", "e", "f"] }],
      [{ ...entry(), timestamp: Number.POSITIVE_INFINITY }],
      [{ ...entry(), source: ["file", -1] }],
      [{ ...entry(), count: 0 }],
    ]) {
      const tools = await toolsWith(async () => raw);
      const result = await tools.call("ha_get_recent_errors", {});
      expect(result.error?.code).toBe("upstream_error");
    }
  });

  it("keeps the newest 50 structured entries and reports truncation", async () => {
    const tools = await toolsWith(async () =>
      Array.from({ length: 51 }, (_, index) => entry(index)),
    );
    const result = await tools.call("ha_get_recent_errors", {});
    expect(result.data).toMatchObject({ count: 50, truncated: true });
    expect(
      (result.data as { summaries: Array<{ name: string }> }).summaries.at(-1)
        ?.name,
    ).toBe("component.49");
  });

  it.each([
    "",
    "!!!",
    "MR",
    Buffer.from("00").toString("base64url"),
    Buffer.from("-1").toString("base64url"),
    Buffer.from("1.5").toString("base64url"),
    Buffer.from("9007199254740992").toString("base64url"),
  ])("rejects invalid cursor %j", async (cursor) => {
    const tools = await toolsWith(async () => []);
    const result = await tools.call("ha_list_entities", { cursor });
    expect(result.error?.code).toBe("invalid_input");
  });

  it("accepts canonical cursors and generated next cursors", async () => {
    const tools = await toolsWith(async () => []);
    const zero = await tools.call("ha_list_entities", {
      cursor: "MA",
      limit: 1,
    });
    expect(zero.ok).toBe(true);
    const nextCursor = (zero.data as { pagination: { nextCursor: string } })
      .pagination.nextCursor;
    expect(nextCursor).toBe("MQ");
    const one = await tools.call("ha_list_entities", {
      cursor: nextCursor,
      limit: 1,
    });
    expect((one.data as { items: HaState[] }).items[0]?.entity_id).toBe(
      "light.second",
    );
  });
});
