import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "../src/transport/mcp.js";
import type { ReadTools } from "../src/application.js";
describe("MCP inventory", () => {
  it("constructs from read-only registry", () => {
    const tools = {
      names: () => ["ha_get_system_info"],
      call: async () => ({
        ok: true,
        requestId: "1",
        data: {},
        warnings: [],
        evidence: [],
      }),
    } as unknown as ReadTools;
    expect(createServer(tools)).toBeDefined();
    for (const forbidden of [
      "shell",
      "write_file",
      "service_call",
      "delete",
      "restart",
      "apply",
    ])
      expect(tools.names().join(" ")).not.toContain(forbidden);
  });
  it("invokes success and schema failure through the real protocol", async () => {
    const calls: unknown[] = [];
    const tools = {
      names: () => ["ha_get_entity_state"],
      call: async (_name: string, args: unknown) => {
        calls.push(args);
        const entityId = (args as { entityId?: unknown }).entityId;
        const valid = typeof entityId === "string";
        return entityId === "light.failure"
          ? {
              ok: false,
              requestId: "3",
              error: { code: "upstream_error", message: "safe failure" },
              warnings: [],
              evidence: [],
            }
          : valid
            ? { ok: true, requestId: "1", data: {}, warnings: [], evidence: [] }
            : {
                ok: false,
                requestId: "2",
                error: { code: "invalid_input", message: "invalid" },
                warnings: [],
                evidence: [],
              };
      },
    } as unknown as ReadTools;
    const server = createServer(tools);
    const client = new Client({ name: "test", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    expect(
      (
        await client.callTool({
          name: "ha_get_entity_state",
          arguments: { entityId: "light.test" },
        })
      ).isError,
    ).toBeFalsy();
    expect(
      (
        await client.callTool({
          name: "ha_get_entity_state",
          arguments: { entityId: 4 },
        })
      ).isError,
    ).toBe(true);
    expect(
      (
        await client.callTool({
          name: "ha_get_entity_state",
          arguments: { entityId: "light.failure" },
        })
      ).isError,
    ).toBe(true);
    expect(calls).toHaveLength(3);
    await client.close();
    await server.close();
  });
  it("starts the built server over actual stdio and lists tools", async () => {
    const root = await mkdtemp(join(tmpdir(), "mcp-stdio-"));
    const inherited = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/index.js")],
      env: {
        ...inherited,
        HA_MODE: "local",
        HA_BASE_URL: "http://127.0.0.1:8123",
        HA_ACCESS_TOKEN: "test-only",
        HA_AUDIT_LOG_PATH: join(root, "audit.jsonl"),
      },
    });
    const client = new Client({ name: "stdio-test", version: "1" });
    await client.connect(transport);
    const inventory = await client.listTools();
    expect(inventory.tools.map((tool) => tool.name)).toContain(
      "ha_get_system_info",
    );
    await client.close();
  });
});
