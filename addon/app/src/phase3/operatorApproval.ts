import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { ReadStream, WriteStream } from "node:tty";
import type { ProtectedProposalStore } from "../proposals/storage.js";
import type { ProtectedIdentityRegistry } from "../security/repositoryBoundary.js";
import type { DurablePhase3ApprovalGrants } from "./durableApproval.js";
import type { ProtectedPhase3ProposalAdapter } from "./proposalAdapter.js";
import type {
  Phase3ApplyCoordinator,
  Phase3OperationContext,
} from "./applyCoordinator.js";
import {
  canonicalJson,
  phase3ProposalSnapshotSchema,
  sha256,
  type Phase3ProposalSnapshot,
  type Phase3TransactionRecord,
} from "./contracts.js";

export interface Phase3OperatorTerminal {
  readonly inputIsTTY: boolean;
  readonly outputIsTTY: boolean;
  write(text: string): Promise<void>;
  readConfirmation(context: Phase3OperationContext): Promise<string>;
}

export interface Phase3OperatorAuditRecord {
  readonly attemptId: string;
  readonly event:
    | "attempt"
    | "displayed"
    | "confirmed"
    | "grant_issued"
    | "settled"
    | "failed"
    | "audit_uncertain"
    | "recovery_attempt"
    | "recovery_displayed"
    | "recovery_confirmed"
    | "recovery_settled"
    | "recovery_failed"
    | "recovery_uncertain";
  readonly proposalId?: string;
  readonly proposalStorageSha256?: string;
  readonly displayedSha256?: string;
  readonly grantId?: string;
  readonly transactionId?: string;
  readonly state?: string;
}

export interface Phase3OperatorApprovalPorts {
  readonly terminal: Phase3OperatorTerminal;
  readonly store: Pick<ProtectedProposalStore, "readExact">;
  readonly proposals: Pick<ProtectedPhase3ProposalAdapter, "load">;
  readonly registry: Pick<
    ProtectedIdentityRegistry,
    "assertFresh" | "redactWholeText"
  >;
  readonly approvals: Pick<DurablePhase3ApprovalGrants, "issueApplyGrant">;
  readonly coordinator: Pick<Phase3ApplyCoordinator, "apply">;
  readonly audit: { append(record: Phase3OperatorAuditRecord): Promise<void> };
}

export class Phase3OperatorError extends Error {
  constructor(public readonly code: string) {
    super(`Phase 3 operator approval failed: ${code}`);
    this.name = "Phase3OperatorError";
  }
}

export class Phase3OperatorAuditUncertain extends Phase3OperatorError {
  constructor(
    public readonly transactionId: string,
    public readonly state: Phase3TransactionRecord["state"],
  ) {
    super("post_settlement_audit_uncertain");
  }
}

/** One local interactive approval. Grant IDs are never accepted from CLI/MCP input. */
export async function approveAndApplyProposal(
  proposalId: string,
  ports: Phase3OperatorApprovalPorts,
  context: Phase3OperationContext,
) {
  if (!ports.terminal.inputIsTTY || !ports.terminal.outputIsTTY)
    throw new Phase3OperatorError("interactive_terminal_required");
  active(context);
  z.string().uuid().parse(proposalId);
  const attemptId = randomUUID();
  const evidence: Omit<Phase3OperatorAuditRecord, "event"> = {
    attemptId,
    proposalId,
  };
  let displayEvidence = evidence;
  let grantId: string | undefined;
  let settled: Phase3TransactionRecord | undefined;
  try {
    await ports.audit.append({ ...evidence, event: "attempt" });
    const first = await displaySnapshot(proposalId, ports, context);
    displayEvidence = {
      ...evidence,
      proposalStorageSha256: first.proposal.proposalStorageSha256,
      displayedSha256: sha256(Buffer.from(first.display, "utf8")),
    };
    active(context);
    const confirmation = `APPLY ${proposalId} ${first.proposal.proposalStorageSha256}`;
    await ports.terminal.write(
      `${first.display}\nType exactly ${confirmation}\n> `,
    );
    await ports.audit.append({ ...displayEvidence, event: "displayed" });
    active(context);
    const answer = await ports.terminal.readConfirmation(context);
    active(context);
    if (answer !== confirmation)
      throw new Phase3OperatorError("confirmation_rejected");
    const second = await displaySnapshot(proposalId, ports, context);
    if (
      canonicalJson(first.proposal) !== canonicalJson(second.proposal) ||
      first.display !== second.display
    )
      throw new Phase3OperatorError("proposal_changed_after_display");
    await ports.audit.append({ ...displayEvidence, event: "confirmed" });
    active(context);
    const grant = await ports.approvals.issueApplyGrant(second.proposal, {
      now: Date.now(),
      signal: context.signal,
    });
    grantId = grant.grantId;
    await ports.audit.append({
      ...displayEvidence,
      event: "grant_issued",
      grantId,
    });
    active(context);
    const record = await ports.coordinator.apply(
      { proposalId, grantId },
      context,
    );
    settled = record;
    await ports.audit.append({
      ...displayEvidence,
      event: "settled",
      grantId,
      transactionId: record.transactionId,
      state: record.state,
    });
    return record;
  } catch (error) {
    // A failed final audit can follow a settled effect. Never retry the apply here.
    if (settled) {
      await ports.audit
        .append({
          ...displayEvidence,
          event: "audit_uncertain",
          grantId: grantId!,
          transactionId: settled.transactionId,
          state: settled.state,
        })
        .catch(() => undefined);
      throw new Phase3OperatorAuditUncertain(
        settled.transactionId,
        settled.state,
      );
    }
    await ports.audit.append({
      ...displayEvidence,
      event: "failed",
      ...(grantId ? { grantId } : {}),
    });
    throw error;
  }
}

async function displaySnapshot(
  proposalId: string,
  ports: Phase3OperatorApprovalPorts,
  context: Phase3OperationContext,
) {
  active(context);
  const operation = {
    ...context,
    requestId: randomUUID(),
    operationId: randomUUID(),
  };
  await ports.registry.assertFresh(operation);
  const proposal = phase3ProposalSnapshotSchema.parse(
    await ports.proposals.load(proposalId),
  );
  if (
    proposal.proposalId !== proposalId ||
    proposal.state !== "pending" ||
    Date.now() >= Date.parse(proposal.expiresAt)
  )
    throw new Phase3OperatorError("proposal_unavailable");
  if (
    proposal.path !== "automations.yaml" ||
    proposal.impact !== "domain_reload" ||
    proposal.reloadTarget !== "automation.reload"
  )
    throw new Phase3OperatorError("unsupported_proposal");
  const stored = await ports.store.readExact(proposalId);
  if (stored.storageSha256 !== proposal.proposalStorageSha256)
    throw new Phase3OperatorError("proposal_changed_after_display");
  const diff = ports.registry.redactWholeText(
    stored.public.redactedDiff,
    operation,
    65_536,
  );
  await ports.registry.assertFresh(operation);
  active(context);
  const display = `${JSON.stringify(proposal, null, 2)}\nRedacted diff:\n${escapePhase3Terminal(diff)}`;
  if (Buffer.byteLength(display, "utf8") > 70_000)
    throw new Phase3OperatorError("display_limit_exceeded");
  return {
    proposal: Object.freeze(proposal) as Phase3ProposalSnapshot,
    display,
  };
}

export function escapePhase3Terminal(text: string): string {
  return Array.from(text, (character) => {
    const code = character.codePointAt(0)!;
    const escaped =
      (code < 0x20 && code !== 0x0a) ||
      (code >= 0x7f && code <= 0x9f) ||
      [0x061c, 0x200e, 0x200f].includes(code) ||
      (code >= 0x2028 && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069);
    return escaped ? `\\u${code.toString(16).padStart(4, "0")}` : character;
  }).join("");
}

function active(context: Phase3OperationContext): void {
  if (context.signal.aborted || Date.now() >= context.deadlineAt)
    throw new Phase3OperatorError("operation_inactive");
}

/** Uses the inherited terminal, with no environment/argument confirmation path. */
export function createPhase3OperatorTerminal(
  input: ReadStream,
  output: WriteStream,
): Phase3OperatorTerminal {
  return {
    inputIsTTY: input.isTTY === true,
    outputIsTTY: output.isTTY === true,
    write: async (text) =>
      await new Promise<void>((resolve, reject) => {
        output.write(text, (error) =>
          error
            ? reject(new Phase3OperatorError("terminal_write_failed"))
            : resolve(),
        );
      }),
    readConfirmation: async (context) =>
      await new Promise<string>((resolve, reject) => {
        active(context);
        let answer = "";
        const finish = (error?: Error, value?: string) => {
          clearTimeout(timer);
          input.off("data", data);
          input.off("end", ended);
          input.off("error", ended);
          context.signal.removeEventListener("abort", cancelled);
          input.pause();
          if (error) reject(error);
          else resolve(value!);
        };
        const cancelled = () =>
          finish(new Phase3OperatorError("operation_inactive"));
        const ended = () => finish(new Phase3OperatorError("terminal_closed"));
        const data = (chunk: Buffer | string) => {
          answer += chunk.toString();
          if (Buffer.byteLength(answer, "utf8") > 256)
            return finish(
              new Phase3OperatorError("confirmation_limit_exceeded"),
            );
          if (answer.includes("\n")) {
            if (!/^[^\r\n]*\r?\n$/u.test(answer))
              return finish(new Phase3OperatorError("confirmation_rejected"));
            finish(undefined, answer.replace(/\r?\n$/u, ""));
          }
        };
        const timer = setTimeout(
          cancelled,
          Math.max(1, context.deadlineAt - Date.now()),
        );
        input.on("data", data);
        input.once("end", ended);
        input.once("error", ended);
        context.signal.addEventListener("abort", cancelled, { once: true });
        input.resume();
        if (context.signal.aborted) cancelled();
      }),
  };
}
