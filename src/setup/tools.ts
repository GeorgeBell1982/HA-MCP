import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { JsonlAudit } from "../audit.js";
import { failure, SafeError, success } from "../domain.js";
import type { ToolDescriptor, ToolRegistry } from "../toolRegistry.js";
import { SetupService, setupChangeInput } from "./service.js";
import type { SetupApiClient } from "./api.js";
import type { GuardedActionService } from "../guardedChanges.js";

const catalogInput = z
  .object({
    kind: z.enum(["integration", "hacs", "app"]),
    query: z.string().max(200).optional(),
    limit: z.number().int().min(1).max(200).default(100),
  })
  .strict();
const statusInput = z
  .object({
    kind: z.enum(["integration", "flow", "hacs", "app"]),
    target: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,128}$/)
      .optional(),
  })
  .strict();
const descriptors: readonly ToolDescriptor[] = [
  {
    name: "ha_list_setup_catalog",
    description:
      "List loaded integration config flows, configured HACS integration/frontend repositories, or Supervisor store apps. Returns catalog IDs; does not install or authenticate anything.",
    inputSchema: catalogInput,
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "ha_get_setup_status",
    description:
      "Read integration entries, a runtime-cached flow result, HACS catalog repository state, or app options/privileges with secrets redacted. Flow status never advances a flow.",
    inputSchema: statusInput,
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "ha_propose_setup_change",
    description:
      "Prepare a bounded integration setup step, pinned HACS install, app install/options/start for exact chat approval via ha_apply_change. Never paste credentials into inputs. Provider authentication requires a secure Home Assistant handoff. This tool itself does not mutate Home Assistant.",
    inputSchema: setupChangeInput,
    annotations: {
      readOnlyHint: false,
      idempotentHint: false,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
];

export function buildSetupRegistry(
  api: SetupApiClient,
  actions: GuardedActionService,
  audit: Pick<JsonlAudit, "health" | "append">,
): ToolRegistry {
  const service = new SetupService(api, actions);
  return {
    names: () => descriptors.map((d) => d.name),
    descriptors: () => descriptors,
    descriptor: (name) => descriptors.find((d) => d.name === name),
    async call(name, input, context) {
      const requestId = randomUUID();
      const descriptor = descriptors.find((d) => d.name === name);
      const record = {
        timestamp: new Date().toISOString(),
        tool: descriptor ? name : "unknown_setup_tool",
        requestId,
        risk: "read-only" as const,
      };
      try {
        await audit.health();
        await audit.append({ ...record, result: "attempt" });
      } catch {
        return failure(
          requestId,
          new SafeError("audit_unavailable", "Setup audit is unavailable"),
        );
      }
      try {
        if (!descriptor)
          throw new SafeError("invalid_input", "Unknown setup tool");
        if (context?.signal.aborted)
          throw new SafeError("timeout", "Setup request was cancelled");
        const parsed = descriptor.inputSchema.safeParse(input);
        if (!parsed.success)
          throw new SafeError("invalid_input", "Invalid setup input");
        let result: unknown;
        if (name === "ha_list_setup_catalog") {
          const p = catalogInput.parse(parsed.data);
          result = await service.catalog(p.kind, p.query, p.limit);
        } else if (name === "ha_get_setup_status") {
          const p = statusInput.parse(parsed.data);
          result = await service.status(p.kind, p.target);
        } else result = await service.propose(parsed.data);
        await audit.append({ ...record, result: "success" });
        return success(requestId, result);
      } catch (error) {
        const safe =
          error instanceof SafeError
            ? error
            : new SafeError(
                "upstream_error",
                "Setup operation failed safely; inspect its status before retrying",
              );
        try {
          await audit.append({
            ...record,
            result: "failure",
            error: safe.code,
          });
        } catch {
          return failure(
            requestId,
            new SafeError(
              "audit_unavailable",
              "Setup outcome audit is unavailable",
            ),
          );
        }
        return failure(requestId, safe);
      }
    },
  };
}
