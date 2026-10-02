import { randomUUID } from "node:crypto";
import type {
  Phase3ApplyCoordinator,
  Phase3OperationContext,
} from "./applyCoordinator.js";
import {
  canonicalJson,
  phase3TransactionRecordSchema,
  sha256,
  type Phase3JournalPort,
  type Phase3RecoveryResult,
} from "./contracts.js";
import {
  escapePhase3Terminal,
  Phase3OperatorAuditUncertain,
  Phase3OperatorError,
  type Phase3OperatorAuditRecord,
  type Phase3OperatorTerminal,
} from "./operatorApproval.js";

export interface Phase3OperatorRecoveryPorts {
  readonly terminal: Phase3OperatorTerminal;
  readonly journal: Pick<Phase3JournalPort, "listRecoverable" | "load">;
  readonly coordinator: Pick<Phase3ApplyCoordinator, "recover">;
  readonly audit: { append(record: Phase3OperatorAuditRecord): Promise<void> };
}

export class Phase3OperatorRecoveryUncertain extends Phase3OperatorError {
  constructor(public readonly transactionId?: string) {
    super("recovery_outcome_uncertain");
  }
}

/** Recovery can write the live file and reload HA; it requires its own exact review. */
export async function approveAndRecoverPhase3(
  ports: Phase3OperatorRecoveryPorts,
  context: Phase3OperationContext,
): Promise<readonly Phase3RecoveryResult[]> {
  if (!ports.terminal.inputIsTTY || !ports.terminal.outputIsTTY)
    throw new Phase3OperatorError("interactive_terminal_required");
  active(context);
  const attemptId = randomUUID();
  let evidence: Omit<Phase3OperatorAuditRecord, "event"> = { attemptId };
  let dispatchStarted = false;
  let unexpectedResult = false;
  let returned: readonly Phase3RecoveryResult[] | undefined;
  try {
    await ports.audit.append({ ...evidence, event: "recovery_attempt" });
    const first = await snapshot(ports, context);
    const record = first.record;
    evidence = {
      ...evidence,
      ...(record
        ? {
            transactionId: record.transactionId,
            proposalId: record.proposalId,
            proposalStorageSha256: record.proposalStorageSha256,
          }
        : {}),
      displayedSha256: first.digest,
    };
    const confirmation = record
      ? `RECOVER ${record.transactionId} ${first.digest}`
      : "RECOVER EMPTY";
    await ports.terminal.write(
      `${first.display}\nType exactly ${confirmation}\n> `,
    );
    await ports.audit.append({ ...evidence, event: "recovery_displayed" });
    active(context);
    const answer = await ports.terminal.readConfirmation(context);
    active(context);
    if (Buffer.byteLength(answer, "utf8") > 256)
      throw new Phase3OperatorError("confirmation_limit_exceeded");
    if (answer !== confirmation)
      throw new Phase3OperatorError("confirmation_rejected");
    const second = await snapshot(ports, context);
    if (first.identity !== second.identity)
      throw new Phase3OperatorError("recovery_changed_after_display");
    if (record) {
      const exact = await ports.journal.load(record.transactionId);
      if (
        exact === null ||
        canonicalJson(phase3TransactionRecordSchema.parse(exact)) !==
          first.identity
      )
        throw new Phase3OperatorError("recovery_changed_after_display");
    }
    active(context);
    await ports.audit.append({ ...evidence, event: "recovery_confirmed" });
    active(context);
    dispatchStarted = true;
    returned = await ports.coordinator.recover();
    if (
      returned.length !== (record ? 1 : 0) ||
      (record && returned[0]?.transactionId !== record.transactionId)
    ) {
      unexpectedResult = true;
      throw new Phase3OperatorRecoveryUncertain(record?.transactionId);
    }
    const outcome = returned[0];
    await ports.audit.append({
      ...evidence,
      event: "recovery_settled",
      ...(outcome
        ? {
            transactionId: outcome.record.transactionId,
            state: outcome.record.state,
            proposalId: outcome.record.proposalId,
            proposalStorageSha256: outcome.record.proposalStorageSha256,
          }
        : {}),
    });
    return returned;
  } catch (error) {
    if (dispatchStarted) {
      const outcome = returned?.[0];
      await ports.audit
        .append({
          ...evidence,
          event: "recovery_uncertain",
          ...(outcome
            ? {
                transactionId: outcome.record.transactionId,
                state: outcome.record.state,
                proposalId: outcome.record.proposalId,
                proposalStorageSha256: outcome.record.proposalStorageSha256,
              }
            : {}),
        })
        .catch(() => undefined);
      if (unexpectedResult)
        throw new Phase3OperatorRecoveryUncertain(evidence.transactionId);
      if (outcome)
        throw new Phase3OperatorAuditUncertain(
          outcome.record.transactionId,
          outcome.record.state,
        );
      throw new Phase3OperatorRecoveryUncertain(evidence.transactionId);
    }
    try {
      await ports.audit.append({ ...evidence, event: "recovery_failed" });
    } catch {
      throw new Phase3OperatorError("recovery_audit_failed");
    }
    if (error instanceof Phase3OperatorError && safeCodes.has(error.code))
      throw error;
    throw new Phase3OperatorError("recovery_failed");
  }
}

const safeCodes = new Set([
  "operation_inactive",
  "confirmation_rejected",
  "confirmation_limit_exceeded",
  "terminal_closed",
  "terminal_write_failed",
  "recovery_changed_after_display",
  "recovery_multiple_transactions",
  "display_limit_exceeded",
]);

async function snapshot(
  ports: Phase3OperatorRecoveryPorts,
  context: Phase3OperationContext,
) {
  active(context);
  const records = await ports.journal.listRecoverable();
  if (records.length > 1)
    throw new Phase3OperatorError("recovery_multiple_transactions");
  const record = records[0]
    ? phase3TransactionRecordSchema.parse(records[0])
    : undefined;
  const identity = record ? canonicalJson(record) : "[]";
  const digest = sha256(identity);
  // Failure messages/codes are intentionally absent: they can contain upstream secrets.
  const display = escapePhase3Terminal(
    record
      ? JSON.stringify(
          {
            transactionId: record.transactionId,
            proposalId: record.proposalId,
            proposalStorageSha256: record.proposalStorageSha256,
            approvalGrantId: record.approvalGrantId,
            state: record.state,
            version: record.version,
            path: record.path,
            expectedSha256: record.expectedSha256,
            candidateSha256: record.candidateSha256,
            checkpointId: record.checkpointId,
            checkpointSha256: record.checkpointSha256,
            impact: record.impact,
            reloadTarget: record.reloadTarget,
            rollbackReloadRequired: record.rollbackReloadRequired,
          },
          null,
          2,
        )
      : "No active Phase 3 transaction.",
  );
  if (Buffer.byteLength(display, "utf8") > 70_000)
    throw new Phase3OperatorError("display_limit_exceeded");
  active(context);
  return { record, identity, digest, display };
}

function active(context: Phase3OperationContext): void {
  if (context.signal.aborted || Date.now() >= context.deadlineAt)
    throw new Phase3OperatorError("operation_inactive");
}
