import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ElicitRequestSchema,
  type ElicitResult,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { createServer } from "../src/transport/mcp.js";
import {
  ToolApprovalError,
  type ToolCallContext,
  type ToolRegistry,
} from "../src/toolRegistry.js";
import { bridgeCallMayRetry } from "../src/bridge.js";

const confirmation =
  "APPLY 11111111-1111-4111-8111-111111111111 " + "a".repeat(64);
async function fixture(
  response?: ElicitResult,
  options: {
    deadline?: number;
    delay?: number;
    oversized?: boolean;
    form?: boolean;
  } = {},
) {
  let effects = 0,
    prompts = 0;
  const tools: ToolRegistry = {
    names: () => ["ha_apply_proposal"],
    descriptor: () => tools.descriptors()[0],
    descriptors: () => [
      {
        name: "ha_apply_proposal",
        description: "Guarded fixture",
        inputSchema: z.object({}).strict(),
        annotations: { readOnlyHint: false, idempotentHint: false },
      },
    ],
    async call(_name, _input, context?: ToolCallContext) {
      try {
        if (!context?.requestApproval)
          throw new ToolApprovalError("approval_unsupported");
        const answer = await context.requestApproval({
          message: options.oversized
            ? "x".repeat(70_001)
            : "Exact redacted fixture diff",
          confirmation,
          signal: context.signal,
          deadlineAt: Date.now() + (options.deadline ?? 1000),
        });
        if (answer !== confirmation) throw new Error("unsafe confirmation");
        effects++;
        return { ok: true, requestId: "1" };
      } catch (error) {
        return {
          ok: false,
          requestId: "1",
          code: error instanceof ToolApprovalError ? error.code : "unexpected",
        };
      }
    },
  };
  const server = createServer(tools);
  const client = new Client(
    { name: "approval-test", version: "1" },
    options.form === false
      ? {}
      : { capabilities: { elicitation: { form: {} } } },
  );
  if (options.form !== false)
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      prompts++;
      expect(request.params.mode).toBe("form");
      expect(request.params.message).toContain(confirmation);
      expect(request.params).not.toHaveProperty("url");
      if (options.delay)
        await new Promise((resolve) => setTimeout(resolve, options.delay));
      return response ?? { action: "accept", content: { confirmation } };
    });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), client.connect(a)]);
  return {
    client,
    server,
    counts: () => ({ effects, prompts }),
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

describe("transport-owned form approval", () => {
  it("delivers exact form through the real SDK and exposes mutation annotations", async () => {
    const run = await fixture();
    try {
      expect(
        (await run.client.listTools()).tools[0]?.annotations,
      ).toMatchObject({ readOnlyHint: false, idempotentHint: false });
      expect(
        (
          await run.client.callTool({
            name: "ha_apply_proposal",
            arguments: {},
          })
        ).isError,
      ).toBe(false);
      expect(run.counts()).toEqual({ effects: 1, prompts: 1 });
    } finally {
      await run.close();
    }
  });
  it.each<ElicitResult>([
    { action: "decline" },
    { action: "cancel" },
    { action: "accept", content: { confirmation: "wrong" } },
    { action: "accept", content: { confirmation, approved: true } },
    { action: "accept" },
  ])("refuses non-exact acceptance %# before effects", async (response) => {
    const run = await fixture(response);
    try {
      expect(
        (
          await run.client.callTool({
            name: "ha_apply_proposal",
            arguments: {},
          })
        ).isError,
      ).toBe(true);
      expect(run.counts().effects).toBe(0);
    } finally {
      await run.close();
    }
  });
  it.each([
    { form: false },
    { deadline: -1 },
    { oversized: true },
    { deadline: 10, delay: 40 },
  ])(
    "fails closed for unsupported/inactive/oversized/late approval %#",
    async (options) => {
      const run = await fixture(undefined, options);
      try {
        expect(
          (
            await run.client.callTool({
              name: "ha_apply_proposal",
              arguments: {},
            })
          ).isError,
        ).toBe(true);
        expect(run.counts().effects).toBe(0);
      } finally {
        await run.close();
      }
    },
  );
  it("never retries declared or unknown mutations, retaining known read-only retries", () => {
    expect(bridgeCallMayRetry("ha_apply_proposal", true)).toBe(false);
    expect(bridgeCallMayRetry("ha_rotate_epoch", true)).toBe(false);
    expect(bridgeCallMayRetry("future_mutation", false)).toBe(false);
    expect(bridgeCallMayRetry("future_mutation")).toBe(false);
    expect(bridgeCallMayRetry("ha_get_system_info")).toBe(true);
  });
  it("propagates originating tool cancellation while approval is pending", async () => {
    const run = await fixture(undefined, { delay: 100 });
    const abort = new AbortController();
    try {
      const call = run.client.callTool(
        { name: "ha_apply_proposal", arguments: {} },
        undefined,
        { signal: abort.signal },
      );
      setTimeout(() => abort.abort(), 10);
      await expect(call).rejects.toThrow();
      await new Promise((resolve) => setTimeout(resolve, 130));
      expect(run.counts().effects).toBe(0);
    } finally {
      await run.close();
    }
  });
});
