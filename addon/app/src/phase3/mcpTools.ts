import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Config } from "../config.js";
import type { JsonlAudit } from "../audit.js";
import {
  ToolApprovalError,
  type ToolCallContext,
  type ToolDescriptor,
  type ToolRegistry,
} from "../toolRegistry.js";
import {
  phase3OperatorFailureDetails,
  runPhase3McpCommand,
} from "./operatorRuntime.js";

const proposalInput = z
  .object({
    proposalId: z
      .string()
      .uuid()
      .refine((v) => v === v.toLowerCase()),
  })
  .strict();
const emptyInput = z.object({}).strict();
const descriptors: readonly ToolDescriptor[] = Object.freeze([
  {
    name: "ha_apply_proposal",
    description:
      "Apply a pending automations.yaml proposal only after this client's human approves the exact displayed diff and confirmation. Performs validation, checkpoint, automation reload and verification. Never retry an uncertain result; inspect its transaction first.",
    inputSchema: proposalInput,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "ha_rotate_epoch",
    description:
      "Archive the completed Phase 3 transaction to prepare for another proposal. State-only: refuses incomplete or uncertain transactions; never changes Home Assistant configuration or reloads it.",
    inputSchema: emptyInput,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "ha_check_approval",
    description:
      "Check that this chat displays MCP human approval. Requests a harmless confirmation; never accesses configuration, issues an apply grant or changes Home Assistant.",
    inputSchema: emptyInput,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
]);

export function buildPhase3McpRegistry(
  config: Config,
  phase2Active: boolean,
  audit: Pick<JsonlAudit, "health" | "append">,
): ToolRegistry | undefined {
  if (
    config.mode !== "addon" ||
    !config.enablePhase2 ||
    !config.enableMcpWrites ||
    !phase2Active
  )
    return undefined;
  return {
    names: () => descriptors.map((d) => d.name),
    descriptors: () => descriptors,
    descriptor: (name) => descriptors.find((d) => d.name === name),
    async call(name: string, input: unknown, context?: ToolCallContext) {
      const requestId = randomUUID();
      const risk =
        name === "ha_check_approval"
          ? ("read-only" as const)
          : ("guarded-write" as const);
      const record = {
        timestamp: new Date().toISOString(),
        tool: descriptors.some((d) => d.name === name)
          ? name
          : "unknown_phase3_tool",
        requestId,
        risk,
      };
      try {
        await audit.health();
        await audit.append({ ...record, result: "attempt" });
      } catch {
        return {
          ok: false,
          requestId,
          error: {
            code: "audit_unavailable",
            message: "Audit unavailable; operation refused",
          },
        };
      }
      const result = await execute(name, input, context, requestId);
      try {
        await audit.append({
          ...record,
          timestamp: new Date().toISOString(),
          result: result.ok ? "success" : "failure",
        });
      } catch {
        return {
          ...result,
          ok: false,
          error: {
            ...("error" in result ? result.error : {}),
            code: "post_operation_audit_uncertain",
            message:
              "Audit outcome uncertain. Inspect transaction state; do not retry.",
          },
        };
      }
      return result;
    },
  };
  async function execute(
    name: string,
    input: unknown,
    context: ToolCallContext | undefined,
    requestId: string,
  ) {
    const descriptor = descriptors.find((d) => d.name === name);
    const parsed = descriptor?.inputSchema.safeParse(input);
    if (!parsed?.success)
      return {
        ok: false,
        requestId,
        error: { code: "invalid_input", message: "Invalid tool input" },
      };
    if (!context?.requestApproval)
      return {
        ok: false,
        requestId,
        error: {
          code: "chat_approval_unavailable",
          message: "This client must support MCP form elicitation",
        },
      };
    try {
      if (name === "ha_check_approval") {
        const confirmation = `CHECK ${requestId}`;
        const answer = await context.requestApproval({
          message:
            "Approval display check. This makes no Home Assistant changes.",
          confirmation,
          signal: context.signal,
          deadlineAt: Date.now() + 300_000,
        });
        if (answer !== confirmation || context.signal.aborted)
          return {
            ok: false,
            requestId,
            error: {
              code: "confirmation_rejected",
              message: "Approval check declined",
            },
          };
        return {
          ok: true,
          requestId,
          result: { approvalConfirmed: true, homeAssistantChanged: false },
        };
      }
      const command =
        name === "ha_apply_proposal"
          ? {
              operation: "apply-proposal" as const,
              proposalId: proposalInput.parse(input).proposalId,
            }
          : { operation: "rotate" as const };
      const result = await runPhase3McpCommand(command, config, context);
      return { ...result, requestId };
    } catch (error) {
      const details =
        error instanceof ToolApprovalError
          ? { code: error.code }
          : phase3OperatorFailureDetails(error);
      return {
        ok: false,
        requestId,
        error: {
          ...details,
          message:
            "Guarded operation refused or requires inspection. Do not blindly retry.",
        },
      };
    }
  }
}
