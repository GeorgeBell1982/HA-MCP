import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ReadTools } from "../application.js";
const input = z.record(z.unknown());
export function createServer(tools: ReadTools) {
  const server = new McpServer({
    name: "home-assistant-engineering",
    version: "0.1.0",
  });
  for (const name of tools.names())
    server.registerTool(
      name,
      {
        description:
          "Read-only. No approval, reload, restart, file modification, or Git commit.",
        inputSchema: input,
      },
      async (args) => {
        const result = await tools.call(name, args);
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          isError: !result.ok,
        };
      },
    );
  return server;
}
export async function runStdio(tools: ReadTools) {
  await createServer(tools).connect(new StdioServerTransport());
}
