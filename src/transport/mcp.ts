import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ToolRegistry } from "../toolRegistry.js";
const fallbackInput = z.record(z.unknown());
export function createServer(tools: ToolRegistry) {
  const server = new McpServer({
    name: "home-assistant-engineering",
    version: "0.1.0",
  });
  const descriptors =
    tools.descriptors?.() ??
    tools.names().map((name) => ({
      name,
      description:
        "Read-only. No approval, reload, restart, file modification, or Git commit.",
      inputSchema: fallbackInput,
    }));
  for (const descriptor of descriptors)
    server.registerTool(
      descriptor.name,
      {
        description: descriptor.description,
        inputSchema: descriptor.inputSchema,
      },
      async (args, extra) => {
        const result = await tools.call(descriptor.name, args, {
          signal: extra.signal,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          isError: !result.ok,
        };
      },
    );
  return server;
}
export async function runStdio(tools: ToolRegistry) {
  await createServer(tools).connect(new StdioServerTransport());
}
