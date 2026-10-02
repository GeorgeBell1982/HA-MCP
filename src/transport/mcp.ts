import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  ToolApprovalError,
  type ToolApprovalRequest,
  type ToolRegistry,
} from "../toolRegistry.js";
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
        ...(descriptor.annotations
          ? { annotations: descriptor.annotations }
          : {}),
      },
      async (args, extra) => {
        const result = await tools.call(descriptor.name, args, {
          signal: extra.signal,
          ...(server.server.getClientCapabilities()?.elicitation?.form
            ? {
                requestApproval: async (request: ToolApprovalRequest) => {
                  if (!server.server.getClientCapabilities()?.elicitation?.form)
                    throw new ToolApprovalError("approval_unsupported");
                  const remaining = Math.min(
                    120_000,
                    request.deadlineAt - Date.now(),
                  );
                  if (
                    !Number.isFinite(remaining) ||
                    remaining <= 0 ||
                    request.signal.aborted ||
                    extra.signal.aborted
                  )
                    throw new ToolApprovalError("approval_inactive");
                  if (
                    typeof request.message !== "string" ||
                    Buffer.byteLength(request.message, "utf8") > 70_000 ||
                    typeof request.confirmation !== "string" ||
                    Buffer.byteLength(request.confirmation, "utf8") > 256 ||
                    request.confirmation.length === 0
                  )
                    throw new ToolApprovalError("approval_invalid_request");
                  const signal = AbortSignal.any([
                    extra.signal,
                    request.signal,
                    AbortSignal.timeout(Math.ceil(remaining)),
                  ]);
                  let result;
                  try {
                    result = await server.server.elicitInput(
                      {
                        mode: "form",
                        message: `${request.message}\nType exactly ${request.confirmation}`,
                        requestedSchema: {
                          type: "object",
                          properties: {
                            confirmation: {
                              type: "string",
                              title: "Exact approval confirmation",
                              maxLength: 256,
                            },
                          },
                          required: ["confirmation"],
                        },
                      },
                      {
                        relatedRequestId: extra.requestId,
                        signal,
                        timeout: Math.ceil(remaining),
                        maxTotalTimeout: Math.ceil(remaining),
                      },
                    );
                  } catch {
                    throw new ToolApprovalError(
                      signal.aborted
                        ? "approval_inactive"
                        : "approval_unavailable",
                    );
                  }
                  if (signal.aborted)
                    throw new ToolApprovalError("approval_inactive");
                  if (result.action !== "accept")
                    throw new ToolApprovalError(
                      result.action === "decline"
                        ? "approval_declined"
                        : "approval_cancelled",
                    );
                  if (
                    !result.content ||
                    Object.keys(result.content).length !== 1 ||
                    result.content.confirmation !== request.confirmation
                  )
                    throw new ToolApprovalError(
                      "approval_confirmation_rejected",
                    );
                  return request.confirmation;
                },
              }
            : {}),
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
