import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { JsonlAudit } from "./audit.js";
import { SafeError } from "./domain.js";
import type { GuardedActionService, GuardedPlan } from "./guardedChanges.js";
import {
  HaDashboardClient,
  dashboardHash,
  dashboardPathSchema,
  canonicalJson,
  validateDashboardConfig,
} from "./ha/dashboards.js";
import { isSecretKey, redact } from "./redaction.js";
import type { ToolRegistry } from "./toolRegistry.js";

const operation = z.discriminatedUnion("op", [
  z
    .object({
      op: z.literal("add"),
      path: z.string().min(1).max(500),
      value: z.unknown(),
    })
    .strict(),
  z
    .object({
      op: z.literal("replace"),
      path: z.string().min(1).max(500),
      value: z.unknown(),
    })
    .strict(),
  z
    .object({ op: z.literal("remove"), path: z.string().min(1).max(500) })
    .strict(),
]);
const inputSchema = z
  .object({
    urlPath: dashboardPathSchema.unwrap(),
    expectedSha256: z.string().regex(/^[a-f0-9]{64}$/),
    patch: z.array(operation).min(1).max(50),
  })
  .strict();
interface Payload {
  urlPath: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  beforeSha256: string;
  afterSha256: string;
}

export function applyDashboardPatch(
  before: Record<string, unknown>,
  patch: z.infer<typeof inputSchema>["patch"],
) {
  const after = JSON.parse(canonicalJson(before)) as Record<string, unknown>;
  const diff: unknown[] = [];
  for (const op of patch) {
    if (!op.path.startsWith("/") || /~(?![01])/u.test(op.path))
      throw new SafeError("invalid_input", "Invalid JSON pointer");
    const segments = op.path
      .slice(1)
      .split("/")
      .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    if (
      segments.length > 64 ||
      segments.some(
        (s) => !s || ["__proto__", "constructor", "prototype"].includes(s),
      )
    )
      throw new SafeError("invalid_input", "Unsafe JSON pointer");
    let parent: unknown = after;
    for (const key of segments.slice(0, -1)) {
      if (!parent || typeof parent !== "object" || !Object.hasOwn(parent, key))
        throw new SafeError("invalid_input", "Patch parent does not exist");
      parent = (parent as Record<string, unknown>)[key];
    }
    if (!parent || typeof parent !== "object")
      throw new SafeError("invalid_input", "Patch parent is not a container");
    const key = segments.at(-1)!;
    const array = Array.isArray(parent);
    if (array && key !== "-" && !/^(0|[1-9]\d*)$/.test(key))
      throw new SafeError("invalid_input", "Invalid array index");
    const exists = Object.hasOwn(parent, key);
    if (op.op !== "add" && !exists)
      throw new SafeError("invalid_input", "Patch target does not exist");
    if (!array && op.op === "add" && exists)
      throw new SafeError("invalid_input", "Use replace for an existing field");
    const old = exists ? (parent as Record<string, unknown>)[key] : undefined;
    const value = op.op === "remove" ? undefined : op.value;
    // Keep existing credentials untouched in the server-held snapshot. A patch
    // must not introduce placeholders or alter a secret-bearing subtree.
    for (const v of [old, value])
      if (v !== undefined) {
        const text = canonicalJson(v);
        if (
          text.includes("[REDACTED]") ||
          canonicalJson(redact(v)) !== text ||
          text.length > 16_000
        )
          throw new SafeError(
            "invalid_input",
            "Patch must not change secret-bearing or oversized fields",
          );
      }
    if (isSecretKey(key))
      throw new SafeError(
        "invalid_input",
        "Secret fields cannot be changed through dashboard patches",
      );
    diff.push({
      op: op.op,
      path: op.path,
      beforeExists: exists,
      ...(exists ? { before: old } : {}),
      ...(op.op !== "remove" ? { after: value } : {}),
    });
    if (Array.isArray(parent)) {
      const index = key === "-" ? parent.length : Number(key);
      if (index > parent.length || (op.op !== "add" && index >= parent.length))
        throw new SafeError("invalid_input", "Array index out of bounds");
      if (op.op === "add") parent.splice(index, 0, value);
      else if (op.op === "remove") parent.splice(index, 1);
      else parent[index] = value;
    } else if (op.op === "remove")
      delete (parent as Record<string, unknown>)[key];
    else (parent as Record<string, unknown>)[key] = value;
  }
  validateDashboardConfig(after);
  if (dashboardHash(before) === dashboardHash(after))
    throw new SafeError("invalid_input", "Patch makes no change");
  return { after, diff };
}

export function buildDashboardChangeRegistry(
  ha: HaDashboardClient,
  actions: GuardedActionService,
  audit: Pick<JsonlAudit, "health" | "append">,
): ToolRegistry {
  const payload = (plan: GuardedPlan) => plan.payload as Payload;
  actions.register("dashboard", {
    async inspect(plan) {
      const p = payload(plan);
      await ha.assertStorage(p.urlPath);
      if (dashboardHash(await ha.read(p.urlPath)) !== p.beforeSha256)
        throw new SafeError(
          "capability_unavailable",
          "Dashboard changed since proposal; prepare a fresh diff",
        );
    },
    async execute(plan) {
      const p = payload(plan);
      await ha.save(p.urlPath, p.after);
    },
    async verify(plan) {
      const p = payload(plan);
      if (dashboardHash(await ha.read(p.urlPath)) !== p.afterSha256)
        throw new SafeError(
          "upstream_error",
          "Dashboard save verification failed",
        );
      return {
        urlPath: p.urlPath,
        sha256: p.afterSha256,
        homeAssistantRestarted: false,
      };
    },
  });
  const descriptor = {
    name: "ha_propose_dashboard_change",
    description:
      "Propose bounded JSON pointer edits to an existing storage dashboard. Requires current unredacted source hash from ha_get_dashboard; preserves untouched secrets. No live save until ha_apply_change and human diff approval.",
    inputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  };
  return {
    names: () => [descriptor.name],
    descriptors: () => [descriptor],
    descriptor: (name) => (name === descriptor.name ? descriptor : undefined),
    async call(name, input) {
      const requestId = randomUUID();
      const record = {
        timestamp: new Date().toISOString(),
        tool: descriptor.name,
        requestId,
        risk: "read-only" as const,
      };
      try {
        await audit.health();
        await audit.append({ ...record, result: "attempt" });
        const parsed = inputSchema.safeParse(input);
        if (name !== descriptor.name || !parsed.success)
          throw new SafeError("invalid_input", "Invalid dashboard proposal");
        const { urlPath, expectedSha256, patch } = parsed.data;
        await ha.assertStorage(urlPath);
        const before = await ha.read(urlPath);
        if (dashboardHash(before) !== expectedSha256)
          throw new SafeError(
            "capability_unavailable",
            "Dashboard source hash is stale",
          );
        const { after, diff } = applyDashboardPatch(before, patch);
        const result = await actions.propose({
          kind: "dashboard",
          target: `dashboard:${urlPath}`,
          summary: { urlPath, diff, restartRequired: false },
          payload: {
            urlPath,
            before,
            after,
            beforeSha256: expectedSha256,
            afterSha256: dashboardHash(after),
          },
        });
        await audit.append({ ...record, result: "success" });
        return { ok: true, requestId, result };
      } catch (error) {
        await audit.append({ ...record, result: "failure" });
        return {
          ok: false,
          requestId,
          error: {
            code: error instanceof SafeError ? error.code : "upstream_error",
            message:
              error instanceof SafeError
                ? error.message
                : "Dashboard proposal failed safely",
          },
        };
      }
    },
  };
}
