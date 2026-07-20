import { randomUUID } from "node:crypto";
import {
  InjectedApprovalGrantPort,
  type Phase3ApprovalPort,
} from "./approval.js";
import {
  assertPhase3TransactionRecord,
  phase3CanTransition,
  phase3NonTerminalStates,
  sha256,
  type Phase3CommitStatus,
  type Phase3JournalPort,
  type Phase3ProposalSnapshot,
  type Phase3RecoveryDisposition,
  type Phase3RecoveryResult,
  type Phase3StructuredFailure,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "./contracts.js";
import {
  Phase3ResourceLocks,
  canonicalPhase3Path,
  type Phase3LockContext,
} from "./resourceLocks.js";

export class Phase3CoordinatorError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "Phase3CoordinatorError";
  }
}

export type Phase3OperationContext = Phase3LockContext;

export interface Phase3ProposalPort {
  load(proposalId: string): Promise<Phase3ProposalSnapshot>;
  loadCandidate(proposalId: string): Promise<Uint8Array>;
}

export interface Phase3PolicyPort {
  evaluate(proposal: Phase3ProposalSnapshot): Promise<
    | { readonly allowed: true }
    | {
        readonly allowed: false;
        readonly code: string;
        readonly message: string;
      }
  >;
}

export class GuardedPhase3PolicyPort implements Phase3PolicyPort {
  constructor(
    private readonly options: Readonly<{
      writesEnabled?: boolean;
      applyCapability?: boolean;
      domainReloadCapability?: boolean;
      now?: () => number;
    }> = {},
  ) {}

  async evaluate(proposal: Phase3ProposalSnapshot): Promise<
    | { readonly allowed: true }
    | {
        readonly allowed: false;
        readonly code: string;
        readonly message: string;
      }
  > {
    await Promise.resolve();
    if (this.options.writesEnabled !== true)
      return deny("writes_disabled", "Live writes are disabled");
    if (this.options.applyCapability !== true)
      return deny("missing_capability", "Apply capability is unavailable");
    if (proposal.state !== "pending")
      return deny("proposal_not_pending", "Proposal is not pending");
    if ((this.options.now ?? Date.now)() >= Date.parse(proposal.expiresAt))
      return deny("proposal_expired", "Proposal has expired");
    if (proposal.impact === "restart_required")
      return deny("restart_required", "Restart-required changes are denied");
    if (
      proposal.impact === "domain_reload" &&
      this.options.domainReloadCapability !== true
    )
      return deny(
        "missing_capability",
        "Domain reload capability is unavailable",
      );
    if (proposal.impact !== "none" && proposal.impact !== "domain_reload")
      return deny("invalid_impact", "Proposal impact is invalid");
    return { allowed: true };
  }
}

export interface Phase3SourcePort {
  read(
    path: string,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ bytes: Uint8Array; sha256: string }>>;
  readDigest(path: string): Promise<string | null>;
}

export interface Phase3ValidationPort {
  validate(
    bytes: Uint8Array,
    phase:
      | "candidate_pre_apply"
      | "candidate_post_apply"
      | "checkpoint_post_rollback",
    context: Phase3OperationContext,
  ): Promise<void>;
}

export interface Phase3CheckpointPort {
  create(
    path: string,
    bytes: Uint8Array,
    expectedSha256: string,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ checkpointId: string; checkpointSha256: string }>>;
  load(checkpointId: string): Promise<Uint8Array>;
}

export interface Phase3AtomicApplyPort {
  replace(
    input: Readonly<{
      path: string;
      expectedSha256: string;
      content: Uint8Array;
      contentSha256: string;
    }>,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ status: Phase3CommitStatus }>>;
}

export interface Phase3ReloadPort {
  reloadDomain(path: string, context: Phase3OperationContext): Promise<void>;
}

export interface Phase3VerificationPort {
  verify(
    record: Phase3TransactionRecord,
    outcome: "candidate" | "checkpoint",
    context: Phase3OperationContext,
  ): Promise<void>;
}

export interface Phase3ApplyCoordinatorPorts {
  readonly proposals: Phase3ProposalPort;
  readonly policy: Phase3PolicyPort;
  readonly approvals: Phase3ApprovalPort;
  readonly locks: Phase3ResourceLocks;
  readonly source: Phase3SourcePort;
  readonly validation: Phase3ValidationPort;
  readonly checkpoints: Phase3CheckpointPort;
  readonly atomicApply: Phase3AtomicApplyPort;
  readonly reload: Phase3ReloadPort;
  readonly verification: Phase3VerificationPort;
  readonly journal: Phase3JournalPort;
  readonly now?: () => number;
}

type RecoveryDigestClass =
  | "expected_or_checkpoint"
  | "candidate"
  | "other_or_missing";

export class Phase3ApplyCoordinator {
  constructor(private readonly ports: Phase3ApplyCoordinatorPorts) {}

  async apply(
    input: Readonly<{ proposalId: string; grantId: string }>,
    context: Phase3OperationContext,
  ): Promise<Phase3TransactionRecord> {
    assertPrecommitActive(context);
    const first = await this.ports.proposals.load(input.proposalId);
    await this.assertPolicy(first);
    const canonicalPath = canonicalPhase3Path(first.path);
    const lease = await this.ports.locks.acquire(canonicalPath, context);
    try {
      assertPrecommitActive(context);
      const proposal = await this.ports.proposals.load(input.proposalId);
      this.assertSameProposal(first, proposal);
      await this.assertPolicy(proposal);
      const source = await this.ports.source.read(canonicalPath, context);
      let candidate: Uint8Array | undefined;
      try {
        if (
          source.sha256 !== proposal.expectedSha256 ||
          sha256(source.bytes) !== proposal.expectedSha256
        )
          throw new Phase3CoordinatorError(
            "source_digest_drift",
            "Source digest does not match proposal expectation",
          );
        candidate = await this.ports.proposals.loadCandidate(
          proposal.proposalId,
        );
        if (sha256(candidate) !== proposal.candidateSha256)
          throw new Phase3CoordinatorError(
            "candidate_digest_drift",
            "Candidate bytes do not match proposal identity",
          );
        await this.ports.validation.validate(
          candidate,
          "candidate_pre_apply",
          context,
        );
        await this.ports.approvals.consumeApplyGrant(input.grantId, proposal, {
          now: this.now(),
          signal: context.signal,
        });
        const checkpoint = await this.ports.checkpoints.create(
          canonicalPath,
          source.bytes,
          proposal.expectedSha256,
          context,
        );
        if (checkpoint.checkpointSha256 !== proposal.expectedSha256)
          throw new Phase3CoordinatorError(
            "checkpoint_digest_mismatch",
            "Checkpoint metadata does not match the source digest",
          );
        const record = await this.ports.journal.createIntent(
          this.intentRecord(proposal, checkpoint),
        );
        const committed = await this.applyCandidate(record, candidate, context);
        return await this.finishPostCommit(committed, candidate, context);
      } finally {
        candidate?.fill(0);
        source.bytes.fill(0);
      }
    } finally {
      lease.release();
    }
  }

  async recover(): Promise<readonly Phase3RecoveryResult[]> {
    const recovered: Phase3RecoveryResult[] = [];
    const records = await this.ports.journal.listRecoverable();
    for (const record of records) recovered.push(await this.recoverOne(record));
    return Object.freeze(recovered);
  }

  private async applyCandidate(
    record: Phase3TransactionRecord,
    candidate: Uint8Array,
    context: Phase3OperationContext,
  ): Promise<Phase3TransactionRecord> {
    let status: Phase3CommitStatus;
    try {
      status = (
        await this.ports.atomicApply.replace(
          {
            path: record.path,
            expectedSha256: record.expectedSha256,
            content: candidate,
            contentSha256: record.candidateSha256,
          },
          context,
        )
      ).status;
    } catch (error) {
      status = commitStatus(error);
      if (status === "before_commit") throw error;
    }
    if (status === "before_commit")
      throw new Phase3CoordinatorError(
        "apply_before_commit",
        "Apply failed before the atomic commit point",
      );
    if (status === "commit_unknown") {
      const current = await this.ports.source.readDigest(record.path);
      if (
        current === record.checkpointSha256 ||
        current === record.expectedSha256
      ) {
        const rollbackIntent = await this.ports.journal.transition(
          record.transactionId,
          record.version,
          "rollback_intent",
          {
            failure: this.failure(
              "apply",
              "commit_unknown_checkpoint",
              "Commit was unknown and live digest is checkpoint",
              "commit_unknown",
              current,
            ),
          },
        );
        return await this.completeRollbackValidation(rollbackIntent);
      }
      if (current !== record.candidateSha256)
        return await this.manual(
          record,
          "apply",
          "commit_unknown_digest",
          "Commit was unknown and live digest is neither candidate nor checkpoint",
          "commit_unknown",
          current ?? undefined,
        );
    }
    return await this.ports.journal.transition(
      record.transactionId,
      record.version,
      "apply_committed",
      status === "commit_unknown"
        ? {
            failure: this.failure(
              "apply",
              "commit_unknown_candidate",
              "Commit was unknown and live digest is candidate",
              "commit_unknown",
              record.candidateSha256,
            ),
          }
        : undefined,
    );
  }

  private async finishPostCommit(
    record: Phase3TransactionRecord,
    candidate: Uint8Array,
    callerContext: Phase3OperationContext,
  ): Promise<Phase3TransactionRecord> {
    if (isTerminal(record.state)) return record;
    const context = internalContext(callerContext);
    let current = record;
    try {
      await this.ports.validation.validate(
        candidate,
        "candidate_post_apply",
        context,
      );
      current = await this.transition(current, "post_validation_succeeded");
      if (current.impact === "domain_reload")
        await this.ports.reload.reloadDomain(current.path, context);
      current = await this.transition(current, "reload_succeeded");
      await this.ports.verification.verify(current, "candidate", context);
      return await this.transition(current, "verification_succeeded");
    } catch (error) {
      return await this.rollbackAfterCommit(current, error);
    }
  }

  private async rollbackAfterCommit(
    record: Phase3TransactionRecord,
    cause: unknown,
  ): Promise<Phase3TransactionRecord> {
    const context = internalContext();
    let current = record;
    try {
      if (current.state !== "rollback_intent")
        current = await this.ports.journal.transition(
          current.transactionId,
          current.version,
          "rollback_intent",
          {
            failure: this.failure(
              "rollback",
              errorCode(cause),
              errorMessage(cause),
            ),
          },
        );
      const checkpoint = await this.ports.checkpoints.load(
        current.checkpointId,
      );
      try {
        this.assertCheckpointIntegrity(current, checkpoint);
        return await this.restoreCheckpointAfterRollbackIntent(
          current,
          checkpoint,
          context,
        );
      } finally {
        checkpoint.fill(0);
      }
    } catch (rollbackError) {
      return await this.manual(
        current,
        rollbackError instanceof Phase3CoordinatorError &&
          rollbackError.code === "checkpoint_digest_mismatch"
          ? "checkpoint"
          : "rollback",
        errorCode(rollbackError),
        errorMessage(rollbackError),
      );
    }
  }

  private async restoreCheckpointAfterRollbackIntent(
    record: Phase3TransactionRecord,
    checkpoint: Uint8Array,
    context: Phase3OperationContext,
  ): Promise<Phase3TransactionRecord> {
    let status: Phase3CommitStatus;
    let restoreError: unknown;
    try {
      status = (
        await this.ports.atomicApply.replace(
          {
            path: record.path,
            expectedSha256: record.candidateSha256,
            content: checkpoint,
            contentSha256: record.checkpointSha256,
          },
          context,
        )
      ).status;
    } catch (error) {
      restoreError = error;
      status = commitStatus(error);
    }
    if (status === "before_commit")
      return await this.manual(
        record,
        "rollback",
        "rollback_before_commit",
        restoreError instanceof Error
          ? restoreError.message
          : "Rollback failed before commit",
      );
    if (status === "commit_unknown") {
      const currentDigest = await this.ports.source.readDigest(record.path);
      if (
        currentDigest !== record.expectedSha256 &&
        currentDigest !== record.checkpointSha256
      )
        return await this.manual(
          record,
          "rollback",
          "rollback_commit_unknown_digest",
          "Rollback commit was unknown and live digest is not checkpoint",
          "commit_unknown",
          currentDigest ?? undefined,
        );
    }
    const committed = await this.transition(record, "rollback_committed");
    return await this.completeRollbackValidationWithCheckpoint(
      committed,
      checkpoint,
      context,
    );
  }

  private async recoverOne(
    record: Phase3TransactionRecord,
  ): Promise<Phase3RecoveryResult> {
    const observedSha256 = await this.ports.source.readDigest(record.path);
    const digestCase = classifyDigest(record, observedSha256);
    if (record.state === "manual_recovery_required")
      return recoveryResult(
        record,
        digestCase,
        observedSha256,
        "manual_attention_required",
      );
    if (record.state === "verification_succeeded")
      return recoveryResult(
        record,
        digestCase,
        observedSha256,
        digestCase === "candidate" ? "verified" : "manual_attention_required",
      );
    if (record.state === "rollback_verification_succeeded")
      return recoveryResult(
        record,
        digestCase,
        observedSha256,
        digestCase === "expected_or_checkpoint"
          ? "rolled_back"
          : "manual_attention_required",
      );
    if (digestCase === "other_or_missing") {
      const manual = await this.manual(
        record,
        "recovery",
        "digest_unknown",
        "Startup recovery found an unknown or missing live digest",
        undefined,
        observedSha256 ?? undefined,
      );
      return recoveryResult(
        manual,
        digestCase,
        observedSha256,
        "manual_attention_required",
      );
    }
    if (
      (record.state === "rollback_committed" ||
        record.state === "rollback_validation_succeeded") &&
      digestCase !== "expected_or_checkpoint"
    ) {
      const manual = await this.manual(
        record,
        "recovery",
        "rollback_digest_drift",
        "Rollback recovery state does not have checkpoint digest live",
        undefined,
        observedSha256 ?? undefined,
      );
      return recoveryResult(
        manual,
        digestCase,
        observedSha256,
        "manual_attention_required",
      );
    }
    const recovered =
      digestCase === "expected_or_checkpoint"
        ? await this.completeRollbackValidation(record)
        : await this.rollbackAfterCommit(record, "startup recovery rollback");
    return recoveryResult(
      recovered,
      digestCase,
      observedSha256,
      dispositionForRecord(recovered),
    );
  }

  private async completeRollbackValidation(
    record: Phase3TransactionRecord,
  ): Promise<Phase3TransactionRecord> {
    const context = internalContext();
    let current = record;
    try {
      if (
        current.state !== "rollback_intent" &&
        current.state !== "rollback_committed" &&
        current.state !== "rollback_validation_succeeded"
      )
        current = await this.ports.journal.transition(
          current.transactionId,
          current.version,
          "rollback_intent",
          {
            failure: this.failure(
              "recovery",
              "checkpoint_live",
              "Checkpoint digest is already live during recovery",
            ),
          },
        );
      if (current.state === "rollback_intent")
        current = await this.transition(current, "rollback_committed");
      const checkpoint = await this.ports.checkpoints.load(
        current.checkpointId,
      );
      try {
        this.assertCheckpointIntegrity(current, checkpoint);
        return await this.completeRollbackValidationWithCheckpoint(
          current,
          checkpoint,
          context,
        );
      } finally {
        checkpoint.fill(0);
      }
    } catch (error) {
      return await this.manual(
        current,
        error instanceof Phase3CoordinatorError &&
          error.code === "checkpoint_digest_mismatch"
          ? "checkpoint"
          : "recovery",
        errorCode(error),
        errorMessage(error),
      );
    }
  }

  private async completeRollbackValidationWithCheckpoint(
    record: Phase3TransactionRecord,
    checkpoint: Uint8Array,
    context: Phase3OperationContext,
  ): Promise<Phase3TransactionRecord> {
    let current = record;
    try {
      this.assertCheckpointIntegrity(current, checkpoint);
      if (current.state === "rollback_committed") {
        await this.ports.validation.validate(
          checkpoint,
          "checkpoint_post_rollback",
          context,
        );
        current = await this.transition(
          current,
          "rollback_validation_succeeded",
        );
      }
      if (current.state === "rollback_validation_succeeded") {
        await this.ports.verification.verify(current, "checkpoint", context);
        current = await this.transition(
          current,
          "rollback_verification_succeeded",
        );
      }
      return current;
    } catch (error) {
      return await this.manual(
        current,
        error instanceof Phase3CoordinatorError &&
          error.code === "checkpoint_digest_mismatch"
          ? "checkpoint"
          : "rollback",
        errorCode(error),
        errorMessage(error),
      );
    }
  }

  private assertCheckpointIntegrity(
    record: Phase3TransactionRecord,
    checkpoint: Uint8Array,
  ): void {
    const observedSha256 = sha256(checkpoint);
    if (observedSha256 !== record.checkpointSha256)
      throw new Phase3CoordinatorError(
        "checkpoint_digest_mismatch",
        "Checkpoint bytes do not match the transaction checkpoint digest",
      );
  }
  private intentRecord(
    proposal: Phase3ProposalSnapshot,
    checkpoint: Readonly<{ checkpointId: string; checkpointSha256: string }>,
  ): Phase3TransactionRecord {
    const now = new Date(this.now()).toISOString();
    return assertPhase3TransactionRecord({
      schemaVersion: 1,
      transactionId: randomUUID(),
      proposalId: proposal.proposalId,
      proposalStorageSha256: proposal.proposalStorageSha256,
      path: proposal.path,
      expectedSha256: proposal.expectedSha256,
      candidateSha256: proposal.candidateSha256,
      diffSha256: proposal.diffSha256,
      checkpointId: checkpoint.checkpointId,
      checkpointSha256: checkpoint.checkpointSha256,
      impact: proposal.impact,
      state: "intent_prepared",
      priorState: null,
      version: 0,
      createdAt: now,
      updatedAt: now,
      failure: null,
    });
  }

  private assertSameProposal(
    first: Phase3ProposalSnapshot,
    second: Phase3ProposalSnapshot,
  ): void {
    if (
      first.proposalId !== second.proposalId ||
      first.proposalStorageSha256 !== second.proposalStorageSha256 ||
      first.state !== second.state ||
      first.path !== second.path ||
      first.expectedSha256 !== second.expectedSha256 ||
      first.candidateSha256 !== second.candidateSha256 ||
      first.diffSha256 !== second.diffSha256 ||
      first.risk !== second.risk ||
      first.impact !== second.impact ||
      first.expiresAt !== second.expiresAt
    )
      throw new Phase3CoordinatorError(
        "proposal_identity_drift",
        "Proposal identity changed while acquiring the path lock",
      );
  }

  private async assertPolicy(proposal: Phase3ProposalSnapshot): Promise<void> {
    const decision = await this.ports.policy.evaluate(proposal);
    if (!decision.allowed)
      throw new Phase3CoordinatorError(decision.code, decision.message);
  }

  private async transition(
    record: Phase3TransactionRecord,
    state: Phase3TransactionState,
  ): Promise<Phase3TransactionRecord> {
    return await this.ports.journal.transition(
      record.transactionId,
      record.version,
      state,
    );
  }

  private async manual(
    record: Phase3TransactionRecord,
    stage: Phase3StructuredFailure["stage"],
    code: string,
    message: string,
    commitStatus?: Phase3CommitStatus,
    observedSha256?: string,
  ): Promise<Phase3TransactionRecord> {
    const failure = this.failure(
      stage,
      code,
      message,
      commitStatus,
      observedSha256,
    );
    let current = record;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      if (isTerminal(current.state)) return current;
      try {
        return await this.ports.journal.transition(
          current.transactionId,
          current.version,
          "manual_recovery_required",
          { failure },
        );
      } catch (error) {
        if (errorCode(error) !== "journal_cas_conflict") throw error;
        const latest = await this.ports.journal.load(current.transactionId);
        if (!latest || !sameTransactionIdentity(record, latest))
          throw new Phase3CoordinatorError(
            "manual_recovery_reconciliation_failed",
            "Manual recovery is required but the latest durable transaction identity could not be reconciled",
          );
        current = latest;
      }
    }
    throw new Phase3CoordinatorError(
      "manual_recovery_persistence_conflict",
      "Manual recovery is required but durable transaction state kept changing",
    );
  }

  private failure(
    stage: Phase3StructuredFailure["stage"],
    code: string,
    message: string,
    commitStatus?: Phase3CommitStatus,
    observedSha256?: string,
  ): Phase3StructuredFailure {
    const value: Phase3StructuredFailure = {
      stage,
      code,
      message,
      at: new Date(this.now()).toISOString(),
    };
    if (commitStatus) value.commitStatus = commitStatus;
    if (observedSha256) value.observedSha256 = observedSha256;
    return value;
  }

  private now(): number {
    return (this.ports.now ?? Date.now)();
  }
}

export function defaultPhase3Ports(
  grants: readonly unknown[],
  ports: Omit<Phase3ApplyCoordinatorPorts, "approvals">,
): Phase3ApplyCoordinatorPorts {
  return { ...ports, approvals: new InjectedApprovalGrantPort(grants) };
}

function deny(
  code: string,
  message: string,
): {
  readonly allowed: false;
  readonly code: string;
  readonly message: string;
} {
  return { allowed: false, code, message };
}

function assertPrecommitActive(context: Phase3OperationContext): void {
  if (context.signal.aborted)
    throw new Phase3CoordinatorError(
      "operation_cancelled",
      "Operation was cancelled before commit",
    );
  if (Date.now() >= context.deadlineAt)
    throw new Phase3CoordinatorError(
      "deadline_exceeded",
      "Operation deadline expired before commit",
    );
}

function internalContext(
  caller?: Pick<Phase3OperationContext, "deadlineAt">,
): Phase3OperationContext {
  return {
    signal: new AbortController().signal,
    deadlineAt: Math.max(Date.now() + 60_000, caller?.deadlineAt ?? 0),
  };
}

function commitStatus(error: unknown): Phase3CommitStatus {
  if (
    typeof error === "object" &&
    error !== null &&
    "commitStatus" in error &&
    (error as { readonly commitStatus?: unknown }).commitStatus !== undefined
  ) {
    const status = (error as { readonly commitStatus: unknown }).commitStatus;
    if (
      status === "before_commit" ||
      status === "committed" ||
      status === "commit_unknown"
    )
      return status;
  }
  return "before_commit";
}

function errorCode(error: unknown): string {
  if (error instanceof Phase3CoordinatorError) return error.code;
  return error instanceof Error ? error.name : "unknown_failure";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function classifyDigest(
  record: Phase3TransactionRecord,
  current: string | null,
): RecoveryDigestClass {
  if (current === null) return "other_or_missing";
  if (current === record.candidateSha256) return "candidate";
  if (current === record.expectedSha256 || current === record.checkpointSha256)
    return "expected_or_checkpoint";
  return "other_or_missing";
}

function recoveryResult(
  record: Phase3TransactionRecord,
  observedDigest: RecoveryDigestClass,
  observedSha256: string | null,
  disposition: Phase3RecoveryDisposition,
): Phase3RecoveryResult {
  return Object.freeze({
    transactionId: record.transactionId,
    terminalState: record.state,
    observedDigest,
    observedSha256,
    disposition,
    manualAttentionRequired: disposition === "manual_attention_required",
    record,
  });
}

function dispositionForRecord(
  record: Phase3TransactionRecord,
): Phase3RecoveryDisposition {
  if (record.state === "verification_succeeded") return "verified";
  if (record.state === "rollback_verification_succeeded") return "rolled_back";
  return "manual_attention_required";
}
function sameTransactionIdentity(
  expected: Phase3TransactionRecord,
  actual: Phase3TransactionRecord,
): boolean {
  return (
    expected.transactionId === actual.transactionId &&
    expected.proposalId === actual.proposalId &&
    expected.proposalStorageSha256 === actual.proposalStorageSha256 &&
    expected.path === actual.path &&
    expected.expectedSha256 === actual.expectedSha256 &&
    expected.candidateSha256 === actual.candidateSha256 &&
    expected.diffSha256 === actual.diffSha256 &&
    expected.checkpointId === actual.checkpointId &&
    expected.checkpointSha256 === actual.checkpointSha256 &&
    expected.impact === actual.impact &&
    expected.createdAt === actual.createdAt
  );
}

function isTerminal(state: Phase3TransactionState): boolean {
  return (
    state === "verification_succeeded" ||
    state === "rollback_verification_succeeded" ||
    state === "manual_recovery_required"
  );
}

export class InMemoryPhase3Journal implements Phase3JournalPort {
  private readonly records = new Map<string, Phase3TransactionRecord>();

  async createIntent(
    record: Phase3TransactionRecord,
  ): Promise<Phase3TransactionRecord> {
    await Promise.resolve();
    if (record.state !== "intent_prepared" || record.version !== 0)
      throw new Phase3CoordinatorError(
        "journal_illegal_initial_state",
        "Transaction journal must start at intent_prepared version 0",
      );
    if (this.records.has(record.transactionId))
      throw new Phase3CoordinatorError(
        "journal_conflict",
        "Transaction already exists",
      );
    this.records.set(record.transactionId, Object.freeze({ ...record }));
    return this.records.get(record.transactionId)!;
  }

  async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{ failure?: Phase3StructuredFailure | null }> = {},
  ): Promise<Phase3TransactionRecord> {
    await Promise.resolve();
    const current = this.records.get(transactionId);
    if (!current)
      throw new Phase3CoordinatorError(
        "journal_missing",
        "Transaction is missing",
      );
    if (current.version !== expectedVersion)
      throw new Phase3CoordinatorError(
        "journal_cas_conflict",
        "Transaction version changed",
      );
    if (!phase3CanTransition(current.state, state))
      throw new Phase3CoordinatorError(
        "journal_illegal_transition",
        `Illegal Phase 3A transition ${current.state} -> ${state}`,
      );
    const next = assertPhase3TransactionRecord({
      ...current,
      state,
      priorState: current.state,
      version: current.version + 1,
      updatedAt: new Date().toISOString(),
      failure: Object.hasOwn(patch, "failure")
        ? patch.failure
        : current.failure,
    });
    this.records.set(transactionId, Object.freeze(next));
    return next;
  }

  async load(transactionId: string): Promise<Phase3TransactionRecord | null> {
    await Promise.resolve();
    return this.records.get(transactionId) ?? null;
  }

  async listRecoverable(): Promise<readonly Phase3TransactionRecord[]> {
    await Promise.resolve();
    return Object.freeze(
      [...this.records.values()].filter(
        (record) =>
          phase3NonTerminalStates.includes(
            record.state as (typeof phase3NonTerminalStates)[number],
          ) ||
          record.state === "verification_succeeded" ||
          record.state === "rollback_verification_succeeded" ||
          record.state === "manual_recovery_required",
      ),
    );
  }

  get(transactionId: string): Phase3TransactionRecord | undefined {
    return this.records.get(transactionId);
  }
}
