import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { z } from "zod";
import type { JsonlAudit } from "./audit.js";
import { SafeError } from "./domain.js";
import { redact, redactText } from "./redaction.js";
import {
  ToolApprovalError,
  type ToolCallContext,
  type ToolRegistry,
} from "./toolRegistry.js";

export interface GuardedPlan {
  readonly kind: string;
  readonly target: string;
  readonly summary: unknown;
  readonly payload: unknown;
}
export interface GuardedHandler {
  inspect(plan: GuardedPlan): Promise<void>;
  execute(plan: GuardedPlan): Promise<unknown>;
  verify(plan: GuardedPlan, result: unknown): Promise<unknown>;
}
type Lease = { assertHeld(): Promise<void>; release(): Promise<void> };
type Pending = {
  plan: GuardedPlan;
  expires: number;
  state: "pending" | "applying" | "settled";
};
const MAX_BYTES = 400_000;
const TTL = 30 * 60_000;
const idSchema = z.object({ proposalId: z.string().uuid() }).strict();

/** API changes have no conditional-write primitive. Recheck immediately before
 * the single send, retain a private checkpoint, and never replay an uncertain send.
 * Pending proposals are deliberately process-local and expire after restart. */
export class GuardedActionService {
  private readonly handlers = new Map<string, GuardedHandler>();
  private readonly pending = new Map<string, Pending>();
  private readonly busy = new Set<string>();
  constructor(
    private readonly root: string,
    private readonly audit: Pick<JsonlAudit, "health" | "append">,
    private readonly acquireLease?: () => Promise<Lease>,
  ) {
    this.register("history_archive", {
      inspect: async (plan) => {
        const ids = plan.payload as string[];
        await this.ensureArchive();
        const active = new Set(await readdir(this.root));
        const archived = new Set(await readdir(join(this.root, "archive")));
        if (
          (await readdir(join(this.root, "archive"))).length + ids.length >
          1024
        )
          throw new SafeError(
            "capability_unavailable",
            "Protected archive capacity reached",
          );
        for (const id of ids) {
          if (!active.has(`${id}.jsonl`) || archived.has(`${id}.jsonl`))
            throw new SafeError(
              "capability_unavailable",
              "Archive source changed or destination exists",
            );
          const record = await this.readRecord(id);
          if (
            !record ||
            !["verified", "not_sent"].includes(String(record.status))
          )
            throw new SafeError(
              "capability_unavailable",
              "Only settled records can be archived",
            );
        }
      },
      execute: async (plan) => {
        for (const id of plan.payload as string[])
          await rename(
            join(this.root, `${id}.jsonl`),
            join(this.root, "archive", `${id}.jsonl`),
          );
        await this.syncRoot();
        await this.syncRoot(join(this.root, "archive"));
        return { archived: (plan.payload as string[]).length };
      },
      verify: async (plan, result) => {
        const names = await readdir(join(this.root, "archive"));
        if (
          !(plan.payload as string[]).every((id) =>
            names.includes(`${id}.jsonl`),
          )
        )
          throw new SafeError("upstream_error", "Archive verification failed");
        return result;
      },
    });
  }
  async proposeArchive() {
    await this.ensureRoot();
    const ids: string[] = [];
    for (const name of await readdir(this.root)) {
      if (name === "archive") continue;
      const record = await this.readRecord(name.slice(0, -6));
      if (record && ["verified", "not_sent"].includes(String(record.status)))
        ids.push(name.slice(0, -6));
    }
    if (!ids.length)
      throw new SafeError("not_found", "No settled records to archive");
    if (ids.length > 128)
      throw new SafeError(
        "capability_unavailable",
        "History exceeds its bounded capacity",
      );
    return this.propose({
      kind: "history_archive",
      target: `history:${randomUUID()}`,
      payload: ids.sort(),
      summary: {
        recordCount: ids.length,
        homeAssistantChanged: false,
        privateCheckpointsRetained: true,
      },
    });
  }
  register(kind: string, handler: GuardedHandler): void {
    if (this.handlers.has(kind))
      throw new Error("Duplicate guarded action kind");
    this.handlers.set(kind, handler);
  }
  async propose(plan: GuardedPlan) {
    await this.audit.health();
    if (
      !this.handlers.has(plan.kind) ||
      !plan.target ||
      plan.target.length > 200
    )
      throw new SafeError("invalid_input", "Unsupported change target");
    const text = JSON.stringify(plan);
    if (Buffer.byteLength(text) > MAX_BYTES)
      throw new SafeError("invalid_input", "Change exceeds the size limit");
    const copy = JSON.parse(text) as GuardedPlan;
    // Approval summaries are exact and never silently truncated.
    redactText(JSON.stringify(redact(copy.summary), null, 2), {
      maximumBytes: 60_000,
      truncate: false,
    });
    for (const [id, item] of this.pending)
      if (item.expires < Date.now() && item.state !== "applying")
        this.pending.delete(id);
    if (this.pending.size >= 32)
      throw new SafeError(
        "capability_unavailable",
        "Pending change capacity reached",
      );
    const proposalId = randomUUID();
    const item: Pending = {
      plan: copy,
      expires: Date.now() + TTL,
      state: "pending",
    };
    this.pending.set(proposalId, item);
    return this.publicPlan(proposalId, item);
  }
  async get(proposalId: string): Promise<unknown> {
    const item = this.pending.get(proposalId);
    const record = await this.readRecord(proposalId);
    if (record)
      return {
        proposalId,
        ...(redact(record) as object),
        ...(record.status === "prepared"
          ? { status: "uncertain", checkpointStatus: "prepared" }
          : {}),
      };
    if (item) return this.publicPlan(proposalId, item);
    throw new SafeError(
      "not_found",
      "Change was not found; pending changes expire on restart",
    );
  }
  async apply(proposalId: string, context: ToolCallContext): Promise<unknown> {
    const item = this.pending.get(proposalId);
    if (!item || item.expires <= Date.now() || item.state !== "pending")
      throw new SafeError(
        "not_found",
        "Change is absent, expired or already attempted",
      );
    if (!context.requestApproval)
      throw new SafeError(
        "capability_unavailable",
        "This client must support human form approval",
      );
    const handler = this.handlers.get(item.plan.kind)!;
    const target = item.plan.target;
    if (this.busy.has(target))
      throw new SafeError("capability_unavailable", "Target is busy");
    this.busy.add(target);
    item.state = "applying";
    let lease: Lease | undefined;
    let journal: Awaited<ReturnType<typeof open>> | undefined;
    let sent = false;
    let settled = false;
    let outcome: unknown;
    let primary: unknown;
    const active = () => {
      if (context.signal.aborted || Date.now() >= item.expires)
        throw new ToolApprovalError("approval_inactive");
    };
    try {
      active();
      await this.audit.health();
      await this.audit.append({
        timestamp: new Date().toISOString(),
        tool: "guarded_change_execution",
        requestId: proposalId,
        result: "attempt",
        risk: "guarded-write",
      });
      lease = await this.acquireLease?.();
      await this.ensureRoot();
      await this.assertTargetSettled(
        target,
        item.plan.kind === "history_archive",
      );
      await handler.inspect(item.plan);
      active();
      const digest = createHash("sha256")
        .update(JSON.stringify(item.plan))
        .digest("hex");
      const confirmation = `APPLY ${proposalId} ${digest}`;
      const answer = await context.requestApproval({
        message: `Change ${item.plan.kind} on ${target}\n${JSON.stringify(redact(item.plan.summary), null, 2)}\nOnly this proposed operation is approved; no automatic restart or additional installation.`,
        confirmation,
        signal: context.signal,
        deadlineAt: Math.min(item.expires, Date.now() + 120_000),
      });
      active();
      if (answer !== confirmation)
        throw new ToolApprovalError("approval_confirmation_rejected");
      await lease?.assertHeld();
      await handler.inspect(item.plan);
      active();
      journal = await open(
        join(this.root, `${proposalId}.jsonl`),
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW,
        0o600,
      );
      await journal.writeFile(
        JSON.stringify({
          proposalId,
          ...item.plan,
          status: "prepared",
          createdAt: new Date().toISOString(),
        }) + "\n",
      );
      await journal.sync();
      await this.syncRoot();
      active();
      await lease?.assertHeld();
      // Check again after checkpoint fsyncs; slow storage must not widen the
      // stale-source window. Home Assistant still has no atomic compare/save API.
      await handler.inspect(item.plan);
      active();
      // The checkpoint precedes this send. Even a thrown send may have committed.
      sent = true;
      const result = await handler.execute(item.plan);
      const verified = await handler.verify(item.plan, result);
      await journal.writeFile(
        JSON.stringify({
          status: "verified",
          completedAt: new Date().toISOString(),
        }) + "\n",
      );
      await journal.sync();
      settled = true;
      item.state = "settled";
      await this.audit.append({
        timestamp: new Date().toISOString(),
        tool: "guarded_change_execution",
        requestId: proposalId,
        result: "success",
        risk: "guarded-write",
      });
      outcome = { proposalId, status: "verified", result: redact(verified) };
    } catch (error) {
      try {
        if (journal && !sent) {
          await journal.writeFile(
            JSON.stringify({ status: "not_sent" }) + "\n",
          );
          await journal.sync();
          settled = true;
        }
      } catch {
        /* Preserve the primary failure; incomplete checkpoints stay uncertain. */
      }
      item.state = sent || journal ? "settled" : "pending";
      if (sent)
        primary = new SafeError(
          "upstream_error",
          settled
            ? "Change verified but outcome reporting failed. Inspect change status; do not retry."
            : "Change outcome uncertain. Inspect change status and live target; do not retry or restore blindly.",
        );
      else primary = error;
      try {
        await this.audit.append({
          timestamp: new Date().toISOString(),
          tool: "guarded_change_execution",
          requestId: proposalId,
          result: "failure",
          risk: "guarded-write",
        });
      } catch {
        /* The original refusal/uncertainty remains authoritative. */
      }
    } finally {
      // Release all resources even if one cleanup fails.
      const cleanup = await Promise.allSettled([
        journal?.close() ?? Promise.resolve(),
      ]);
      cleanup.push(
        ...(await Promise.allSettled([lease?.release() ?? Promise.resolve()])),
      );
      this.busy.delete(target);
      if (cleanup.some((r) => r.status === "rejected"))
        primary ??= new SafeError(
          "upstream_error",
          "Change cleanup uncertain. Inspect status before retrying.",
        );
    }
    if (primary !== undefined) throw primary;
    return outcome;
  }
  private publicPlan(proposalId: string, item: Pending) {
    return {
      proposalId,
      kind: item.plan.kind,
      target: item.plan.target,
      summary: redact(item.plan.summary),
      expiresAt: new Date(item.expires).toISOString(),
      status: item.state,
    };
  }
  private async ensureRoot() {
    await mkdir(this.root, { mode: 0o700, recursive: true });
    const stat = await lstat(this.root);
    if (
      !stat.isDirectory() ||
      (await realpath(this.root)) !== resolve(this.root) ||
      (process.platform !== "win32" &&
        (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0))
    )
      throw new SafeError(
        "capability_unavailable",
        "Protected change state is unsafe",
      );
  }
  private async ensureArchive() {
    await this.ensureRoot();
    const path = join(this.root, "archive");
    await mkdir(path, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") throw error;
    });
    await this.validateArchive(path);
  }
  private async validateArchive(path: string) {
    const stat = await lstat(path);
    if (
      !stat.isDirectory() ||
      (await realpath(path)) !== resolve(path) ||
      (process.platform !== "win32" &&
        (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0))
    )
      throw new SafeError(
        "capability_unavailable",
        "Protected archive is unsafe",
      );
    const names = await readdir(path);
    if (
      names.length > 1024 ||
      names.some((name) => !/^[0-9a-f-]{36}\.jsonl$/.test(name))
    )
      throw new SafeError(
        "capability_unavailable",
        "Protected archive contents are invalid",
      );
    for (const name of names) {
      const entry = await lstat(join(path, name));
      if (
        !entry.isFile() ||
        entry.nlink !== 1 ||
        (process.platform !== "win32" &&
          (entry.uid !== process.getuid!() || (entry.mode & 0o077) !== 0))
      )
        throw new SafeError(
          "capability_unavailable",
          "Protected archive record is unsafe",
        );
    }
  }
  private async syncRoot(path = this.root) {
    if (process.platform === "win32") return;
    const h = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      await h.sync();
    } finally {
      await h.close();
    }
  }
  private async readRecord(
    id: string,
  ): Promise<Record<string, unknown> | undefined> {
    if (!z.string().uuid().safeParse(id).success)
      throw new SafeError("invalid_input", "Invalid proposal ID");
    await this.ensureRoot();
    let h;
    try {
      h = await open(
        join(this.root, `${id}.jsonl`),
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        try {
          await this.validateArchive(join(this.root, "archive"));
          h = await open(
            join(this.root, "archive", `${id}.jsonl`),
            constants.O_RDONLY | constants.O_NOFOLLOW,
          );
        } catch (archivedError) {
          if ((archivedError as NodeJS.ErrnoException).code === "ENOENT")
            return;
          throw archivedError;
        }
      } else throw error;
    }
    try {
      const stat = await h.stat();
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.size > MAX_BYTES + 2000 ||
        (process.platform !== "win32" &&
          (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0))
      )
        throw new SafeError(
          "capability_unavailable",
          "Protected change record is unsafe",
        );
      const lines = (await h.readFile("utf8")).trim().split("\n");
      const header = JSON.parse(lines[0]!) as Record<string, unknown>;
      if (
        header.proposalId !== id ||
        typeof header.target !== "string" ||
        !["dashboard", "setup", "history_archive"].includes(String(header.kind))
      )
        throw new SafeError(
          "capability_unavailable",
          "Protected change record is invalid",
        );
      const last = JSON.parse(lines.at(-1)!) as Record<string, unknown>;
      return {
        kind: header.kind,
        target: header.target,
        summary: header.summary,
        status: last.status,
      };
    } finally {
      await h.close();
    }
  }
  private async assertTargetSettled(target: string, archival = false) {
    const entries = await readdir(this.root);
    if (!archival && entries.filter((name) => name !== "archive").length >= 128)
      throw new SafeError(
        "capability_unavailable",
        "Change history capacity reached; propose and approve a change-history archive",
      );
    for (const name of entries) {
      if (name === "archive") {
        await this.validateArchive(join(this.root, name));
        continue;
      }
      if (!/^[0-9a-f-]{36}\.jsonl$/.test(name))
        throw new SafeError(
          "capability_unavailable",
          "Unknown protected change artifact",
        );
      const record = await this.readRecord(name.slice(0, -6));
      if (
        record?.target === target &&
        !["verified", "not_sent"].includes(String(record.status))
      )
        throw new SafeError(
          "capability_unavailable",
          "An earlier change is uncertain; inspect before another operation",
        );
    }
  }
}

export function buildGuardedChangeRegistry(
  actions: GuardedActionService,
  audit: Pick<JsonlAudit, "health" | "append">,
): ToolRegistry {
  const descriptors = [
    {
      name: "ha_propose_change_archive",
      description:
        "Propose archiving settled operation records to private bounded storage; approve through ha_apply_change. Preserves checkpoints and uncertain records. No Home Assistant changes.",
      inputSchema: z.object({}).strict(),
      annotations: { readOnlyHint: false, idempotentHint: false },
    },
    {
      name: "ha_apply_change",
      description:
        "Apply exactly one pending dashboard or setup proposal after this chat's human approval. Never replay; inspect status after uncertainty.",
      inputSchema: idSchema,
      annotations: {
        readOnlyHint: false,
        idempotentHint: false,
        destructiveHint: true,
      },
    },
    {
      name: "ha_get_change_status",
      description:
        "Read the redacted proposal or durable operation status. No live changes.",
      inputSchema: idSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ];
  return {
    names: () => descriptors.map((d) => d.name),
    descriptors: () => descriptors,
    descriptor: (name) => descriptors.find((d) => d.name === name),
    async call(name, input, context) {
      const requestId = randomUUID();
      const risk =
        name === "ha_get_change_status" ? "read-only" : "guarded-write";
      const append = (result: "attempt" | "success" | "failure") =>
        audit.append({
          timestamp: new Date().toISOString(),
          tool: name,
          requestId,
          result,
          risk,
        });
      try {
        await audit.health();
        await append("attempt");
      } catch {
        return {
          ok: false,
          requestId,
          error: {
            code: "audit_unavailable",
            message: "Durable audit is unavailable; operation was not started",
          },
        };
      }
      let completed = false;
      try {
        if (name === "ha_propose_change_archive") {
          z.object({}).strict().parse(input);
          const result = await actions.proposeArchive();
          completed = true;
          await append("success");
          return { ok: true, requestId, result };
        }
        const parsed = idSchema.safeParse(input);
        if (!parsed.success || !descriptors.some((d) => d.name === name))
          throw new SafeError("invalid_input", "Invalid change input");
        const result =
          name === "ha_get_change_status"
            ? await actions.get(parsed.data.proposalId)
            : context
              ? await actions.apply(parsed.data.proposalId, context)
              : (() => {
                  throw new SafeError(
                    "capability_unavailable",
                    "Human approval context required",
                  );
                })();
        completed = true;
        await append("success");
        return { ok: true, requestId, result };
      } catch (e) {
        try {
          await append("failure");
        } catch {
          /* Preserve refusal. */
        }
        if (completed)
          return {
            ok: false,
            requestId,
            error: {
              code: "upstream_error",
              message:
                "Operation completed but outcome audit failed; inspect change status, do not retry",
            },
          };
        return {
          ok: false,
          requestId,
          error: {
            code:
              e instanceof ToolApprovalError
                ? e.code
                : e instanceof SafeError
                  ? e.code
                  : "upstream_error",
            message:
              e instanceof SafeError
                ? e.message
                : "Change refused; inspect status before retrying",
          },
        };
      }
    },
  };
}
