import { describe, expect, it } from "vitest";
import {
  GuardedPhase3PolicyPort,
  InMemoryPhase3Journal,
  Phase3ApplyCoordinator,
  Phase3CoordinatorError,
  type Phase3ApplyCoordinatorPorts,
  type Phase3OperationContext,
} from "../src/phase3/applyCoordinator.js";
import {
  InjectedApprovalGrantPort,
  type Phase3ApprovalPort,
} from "../src/phase3/approval.js";
import {
  sha256,
  type Phase3ProposalSnapshot,
  type Phase3StructuredFailure,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "../src/phase3/contracts.js";
import {
  Phase3ResourceLocks,
  type Phase3LockLease,
} from "../src/phase3/resourceLocks.js";

const oldBytes = Buffer.from("old: true\n");
const newBytes = Buffer.from("old: false\n");
const corruptCheckpointBytes = Buffer.from("old: corrupt\n");
const oldSha = sha256(oldBytes);
const newSha = sha256(newBytes);
const unknownSha = sha256("unknown");
const now = Date.parse("2026-07-20T00:00:00.000Z");

function proposal(
  patch: Partial<Phase3ProposalSnapshot> = {},
): Phase3ProposalSnapshot {
  return {
    proposalId: "11111111-1111-4111-8111-111111111111",
    proposalStorageSha256: sha256("proposal"),
    state: "pending",
    path: "automations/lights.yaml",
    expectedSha256: oldSha,
    candidateSha256: newSha,
    diffSha256: sha256("diff"),
    risk: "high",
    impact: "domain_reload",
    expiresAt: "2026-07-20T00:01:00.000Z",
    ...patch,
  };
}

function grant(snapshot = proposal()) {
  return {
    grantId: "22222222-2222-4222-8222-222222222222",
    proposalId: snapshot.proposalId,
    proposalStorageSha256: snapshot.proposalStorageSha256,
    candidateSha256: snapshot.candidateSha256,
    diffSha256: snapshot.diffSha256,
    operation: "apply",
    risk: snapshot.risk,
    issuedAt: "2026-07-20T00:00:00.000Z",
    expiresAt: "2026-07-20T00:01:00.000Z",
  };
}

class LoggingLocks extends Phase3ResourceLocks {
  constructor(private readonly log: string[]) {
    super();
  }
  override async acquire(
    path: string,
    context: Phase3OperationContext,
  ): Promise<Phase3LockLease> {
    this.log.push("lock");
    return await super.acquire(path, context);
  }
}

class LoggingJournal extends InMemoryPhase3Journal {
  readonly transitions: string[] = [];
  readonly failureCodes: (string | null)[] = [];

  override async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{ failure?: Phase3StructuredFailure | null }> = {},
  ): Promise<Phase3TransactionRecord> {
    const before = this.get(transactionId);
    const next = await super.transition(
      transactionId,
      expectedVersion,
      state,
      patch,
    );
    this.transitions.push(`${before?.state ?? "missing"}->${state}`);
    this.failureCodes.push(patch.failure?.code ?? null);
    return next;
  }
}

class AdvancingConflictJournal extends LoggingJournal {
  private conflict = true;

  override async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{ failure?: Phase3StructuredFailure | null }> = {},
  ): Promise<Phase3TransactionRecord> {
    if (state === "rollback_intent" && this.conflict) {
      this.conflict = false;
      await super.transition(transactionId, expectedVersion, state, patch);
      throw new Phase3CoordinatorError(
        "journal_cas_conflict",
        "Concurrent reconciler advanced rollback intent",
      );
    }
    return await super.transition(transactionId, expectedVersion, state, patch);
  }
}

class PersistentManualConflictJournal extends AdvancingConflictJournal {
  override async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{ failure?: Phase3StructuredFailure | null }> = {},
  ): Promise<Phase3TransactionRecord> {
    if (state === "manual_recovery_required")
      throw new Phase3CoordinatorError(
        "journal_cas_conflict",
        "Concurrent reconciler kept changing manual recovery state",
      );
    return await super.transition(transactionId, expectedVersion, state, patch);
  }
}

type FakeCommitStatus = "before_commit" | "committed" | "commit_unknown";

interface FakeOptions {
  readonly snapshots?: Phase3ProposalSnapshot[];
  readonly validationFailure?: string;
  readonly reloadFailure?: boolean;
  readonly verificationFailure?: "candidate" | "checkpoint";
  readonly abortOnApply?: AbortController;
  readonly applyStatus?: FakeCommitStatus;
  readonly applyUnknownDigest?: string | null;
  readonly rollbackStatus?: FakeCommitStatus;
  readonly rollbackUnknownDigest?: string | null;
  readonly throwApplyStatus?: boolean;
  readonly throwRollbackStatus?: boolean;
  readonly checkpointCreateSha?: string;
  readonly checkpointLoadBytes?: Buffer;
  readonly loadCandidateFailure?: boolean;
  readonly journal?: LoggingJournal;
}

function ports(
  log: string[],
  options: FakeOptions = {},
): Phase3ApplyCoordinatorPorts & {
  readonly live: { bytes: Buffer };
  readonly journal: LoggingJournal;
  readonly restoreCount: () => number;
  readonly candidateBuffer: () => Buffer | undefined;
  readonly sourceBuffer: () => Buffer | undefined;
} {
  const snapshots = [...(options.snapshots ?? [proposal(), proposal()])];
  const live = { bytes: Buffer.from(oldBytes) };
  const journal = options.journal ?? new LoggingJournal();
  let restoreCalls = 0;
  let readDigestOverride: string | null | undefined;
  let candidateBuffer: Buffer | undefined;
  let sourceBuffer: Buffer | undefined;
  const approvals: Phase3ApprovalPort = {
    async consumeApplyGrant(grantId, snapshot, context) {
      log.push("approval");
      return await new InjectedApprovalGrantPort([
        grant(snapshot),
      ]).consumeApplyGrant(grantId, snapshot, context);
    },
  };
  return {
    live,
    journal,
    restoreCount: () => restoreCalls,
    candidateBuffer: () => candidateBuffer,
    sourceBuffer: () => sourceBuffer,
    now: () => now,
    proposals: {
      async load() {
        log.push("proposal");
        return snapshots.shift() ?? proposal();
      },
      async loadCandidate() {
        log.push("candidate");
        if (options.loadCandidateFailure)
          throw new Error("candidate load failed");
        candidateBuffer = Buffer.from(newBytes);
        return candidateBuffer;
      },
    },
    policy: {
      async evaluate(snapshot) {
        log.push("policy");
        return await new GuardedPhase3PolicyPort({
          writesEnabled: true,
          applyCapability: true,
          domainReloadCapability: true,
          now: () => now,
        }).evaluate(snapshot);
      },
    },
    approvals,
    locks: new LoggingLocks(log),
    source: {
      async read() {
        log.push("source");
        sourceBuffer = Buffer.from(live.bytes);
        return { bytes: sourceBuffer, sha256: sha256(live.bytes) };
      },
      async readDigest() {
        if (readDigestOverride !== undefined) return readDigestOverride;
        return sha256(live.bytes);
      },
    },
    validation: {
      async validate(_bytes, phase, context) {
        log.push(`validate:${phase}:${context.signal.aborted}`);
        if (phase === options.validationFailure)
          throw new Error(`validation failed at ${phase}`);
      },
    },
    checkpoints: {
      async create(_path, bytes) {
        log.push("checkpoint");
        return {
          checkpointId: "33333333-3333-4333-8333-333333333333",
          checkpointSha256: options.checkpointCreateSha ?? sha256(bytes),
        };
      },
      async load() {
        log.push("checkpoint-load");
        return Buffer.from(options.checkpointLoadBytes ?? oldBytes);
      },
    },
    atomicApply: {
      async replace(input) {
        log.push(`apply:${input.contentSha256}`);
        const isRollback = input.contentSha256 === oldSha;
        if (isRollback) restoreCalls += 1;
        if (options.abortOnApply && !isRollback) options.abortOnApply.abort();
        const status = isRollback
          ? (options.rollbackStatus ?? "committed")
          : (options.applyStatus ?? "committed");
        const unknownDigest = isRollback
          ? options.rollbackUnknownDigest
          : options.applyUnknownDigest;
        const shouldThrow = isRollback
          ? options.throwRollbackStatus
          : options.throwApplyStatus;
        if (status === "before_commit") {
          if (shouldThrow) throw classifiedCommitError(status);
          return { status };
        }
        if (status === "commit_unknown") {
          readDigestOverride = unknownDigest ?? null;
          if (unknownDigest === newSha) live.bytes = Buffer.from(newBytes);
          else if (unknownDigest === oldSha) live.bytes = Buffer.from(oldBytes);
          if (shouldThrow) throw classifiedCommitError(status);
          return { status };
        }
        live.bytes = Buffer.from(input.content);
        if (shouldThrow) throw classifiedCommitError(status);
        return { status };
      },
    },
    reload: {
      async reloadDomain() {
        log.push("reload");
        if (options.reloadFailure) throw new Error("reload failed");
      },
    },
    verification: {
      async verify(_record, outcome, context) {
        log.push(`verify:${outcome}:${context.signal.aborted}`);
        if (outcome === options.verificationFailure)
          throw new Error(`${outcome} verification failed`);
      },
    },
  };
}

function context(controller = new AbortController()): Phase3OperationContext {
  return { signal: controller.signal, deadlineAt: Date.now() + 10_000 };
}

function classifiedCommitError(status: FakeCommitStatus): Error & {
  commitStatus: FakeCommitStatus;
} {
  const error = new Error(`classified ${status}`) as Error & {
    commitStatus: FakeCommitStatus;
  };
  error.commitStatus = status;
  return error;
}
function expectRollbackTerminal(fake: ReturnType<typeof ports>): void {
  expect(fake.journal.transitions).toContain(
    "apply_committed->rollback_intent",
  );
  expect(fake.journal.transitions).toContain(
    "rollback_intent->rollback_committed",
  );
  expect(fake.journal.transitions).toContain(
    "rollback_committed->rollback_validation_succeeded",
  );
  expect(fake.journal.transitions).toContain(
    "rollback_validation_succeeded->rollback_verification_succeeded",
  );
}

describe("Phase 3A apply coordinator", () => {
  it("orders guarded apply policy, locking, approval, checkpoint, apply, reload, and verification", async () => {
    const log: string[] = [];
    const fake = ports(log);
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("verification_succeeded");
    expect(sha256(fake.live.bytes)).toBe(newSha);
    expect(log).toEqual([
      "proposal",
      "policy",
      "lock",
      "proposal",
      "policy",
      "source",
      "candidate",
      "validate:candidate_pre_apply:false",
      "approval",
      "checkpoint",
      `apply:${newSha}`,
      "validate:candidate_post_apply:false",
      "reload",
      "verify:candidate:false",
    ]);
    expect(fake.candidateBuffer()?.every((byte) => byte === 0)).toBe(true);
  });

  it("fails closed on identity drift before source, approval, or apply effects", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      snapshots: [
        proposal(),
        proposal({ proposalStorageSha256: sha256("drift") }),
      ],
    });
    await expect(
      new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      ),
    ).rejects.toMatchObject({ code: "proposal_identity_drift" });
    expect(log).toEqual(["proposal", "policy", "lock", "proposal"]);
    expect(sha256(fake.live.bytes)).toBe(oldSha);
  });

  it("zeros source bytes when candidate loading fails before journal or apply", async () => {
    const log: string[] = [];
    const fake = ports(log, { loadCandidateFailure: true });
    await expect(
      new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      ),
    ).rejects.toThrow("candidate load failed");
    expect(fake.sourceBuffer()?.every((byte) => byte === 0)).toBe(true);
    expect(fake.journal.transitions).toEqual([]);
    expect(log).not.toContain(`apply:${newSha}`);
  });

  it("fails precommit when checkpoint metadata does not bind the source digest", async () => {
    const log: string[] = [];
    const fake = ports(log, { checkpointCreateSha: sha256("wrong") });
    await expect(
      new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      ),
    ).rejects.toMatchObject({ code: "checkpoint_digest_mismatch" });
    expect(fake.journal.transitions).toEqual([]);
    expect(log).not.toContain(`apply:${newSha}`);
    expect(sha256(fake.live.bytes)).toBe(oldSha);
  });

  it("rolls back post-validation failure with the latest durable record", async () => {
    const log: string[] = [];
    const fake = ports(log, { validationFailure: "candidate_post_apply" });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("rollback_verification_succeeded");
    expect(sha256(fake.live.bytes)).toBe(oldSha);
    expectRollbackTerminal(fake);
    expect(log).not.toContain("reload");
  });

  it("rolls back reload failure without stale-CAS escape", async () => {
    const log: string[] = [];
    const fake = ports(log, { reloadFailure: true });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("rollback_verification_succeeded");
    expect(fake.journal.transitions).toContain(
      "post_validation_succeeded->rollback_intent",
    );
    expect(fake.journal.transitions).not.toContain(
      "apply_committed->rollback_intent",
    );
    expect(sha256(fake.live.bytes)).toBe(oldSha);
  });

  it("rolls back candidate verification failure after reload without stale-CAS escape", async () => {
    const log: string[] = [];
    const fake = ports(log, { verificationFailure: "candidate" });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("rollback_verification_succeeded");
    expect(fake.journal.transitions).toContain(
      "reload_succeeded->rollback_intent",
    );
    expect(fake.journal.transitions).not.toContain(
      "apply_committed->rollback_intent",
    );
    expect(sha256(fake.live.bytes)).toBe(oldSha);
  });

  it("continues commit_unknown candidate and safely rolls back a later failure", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      applyStatus: "commit_unknown",
      applyUnknownDigest: newSha,
      validationFailure: "candidate_post_apply",
    });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("rollback_verification_succeeded");
    expect(fake.journal.transitions[0]).toBe(
      "intent_prepared->apply_committed",
    );
    expectRollbackTerminal(fake);
    expect(fake.journal.failureCodes).toContain("commit_unknown_candidate");
  });

  it("routes commit_unknown expected through rollback validation and verification", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      applyStatus: "commit_unknown",
      applyUnknownDigest: oldSha,
    });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("rollback_verification_succeeded");
    expect(fake.restoreCount()).toBe(0);
    expect(fake.journal.transitions).toEqual([
      "intent_prepared->rollback_intent",
      "rollback_intent->rollback_committed",
      "rollback_committed->rollback_validation_succeeded",
      "rollback_validation_succeeded->rollback_verification_succeeded",
    ]);
    expect(log).toContain("validate:checkpoint_post_rollback:false");
    expect(log).toContain("verify:checkpoint:false");
  });

  it("requires manual recovery for commit_unknown other or missing digest without restore", async () => {
    for (const digest of [unknownSha, null]) {
      const log: string[] = [];
      const fake = ports(log, {
        applyStatus: "commit_unknown",
        applyUnknownDigest: digest,
      });
      const record = await new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      );
      expect(record.state).toBe("manual_recovery_required");
      expect(record.failure?.code).toBe("commit_unknown_digest");
      expect(fake.restoreCount()).toBe(0);
    }
  });

  it("manuals corrupt checkpoint during ordinary rollback without restore", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      validationFailure: "candidate_post_apply",
      checkpointLoadBytes: corruptCheckpointBytes,
    });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("manual_recovery_required");
    expect(record.failure?.code).toBe("checkpoint_digest_mismatch");
    expect(fake.restoreCount()).toBe(0);
    expect(sha256(fake.live.bytes)).toBe(newSha);
  });

  it("manuals checkpoint verification failure from the latest rollback validation record", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      validationFailure: "candidate_post_apply",
      verificationFailure: "checkpoint",
    });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("manual_recovery_required");
    expect(fake.journal.transitions).toContain(
      "rollback_committed->rollback_validation_succeeded",
    );
    expect(fake.journal.transitions).toContain(
      "rollback_validation_succeeded->manual_recovery_required",
    );
    expect(fake.journal.failureCodes).not.toContain("journal_cas_conflict");
  });

  it("reconciles a rollback-intent CAS conflict before durable manual recovery", async () => {
    const log: string[] = [];
    const journal = new AdvancingConflictJournal();
    const fake = ports(log, {
      validationFailure: "candidate_post_apply",
      journal,
    });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(),
    );
    expect(record.state).toBe("manual_recovery_required");
    expect(journal.transitions).toContain("apply_committed->rollback_intent");
    expect(journal.transitions).toContain(
      "rollback_intent->manual_recovery_required",
    );
  });

  it("surfaces repeated manual-recovery CAS conflicts with a distinct fail-closed error", async () => {
    const log: string[] = [];
    const fake = ports(log, {
      validationFailure: "candidate_post_apply",
      journal: new PersistentManualConflictJournal(),
    });
    await expect(
      new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      ),
    ).rejects.toMatchObject({
      code: "manual_recovery_persistence_conflict",
    });
  });

  it.each([
    {
      name: "returned committed",
      options: { rollbackStatus: "committed" as const },
      expectedState: "rollback_verification_succeeded" as const,
      expectedDigest: oldSha,
      expectRollbackCommitted: true,
      expectRollbackValidation: true,
    },
    {
      name: "returned before_commit",
      options: { rollbackStatus: "before_commit" as const },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
    {
      name: "returned commit_unknown checkpoint",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: oldSha,
      },
      expectedState: "rollback_verification_succeeded" as const,
      expectedDigest: oldSha,
      expectRollbackCommitted: true,
      expectRollbackValidation: true,
    },
    {
      name: "returned commit_unknown candidate",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: newSha,
      },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
    {
      name: "returned commit_unknown other",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: unknownSha,
      },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
    {
      name: "returned commit_unknown missing",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: null,
      },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
    {
      name: "thrown committed",
      options: {
        rollbackStatus: "committed" as const,
        throwRollbackStatus: true,
      },
      expectedState: "rollback_verification_succeeded" as const,
      expectedDigest: oldSha,
      expectRollbackCommitted: true,
      expectRollbackValidation: true,
    },
    {
      name: "thrown before_commit",
      options: {
        rollbackStatus: "before_commit" as const,
        throwRollbackStatus: true,
      },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
    {
      name: "thrown commit_unknown checkpoint",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: oldSha,
        throwRollbackStatus: true,
      },
      expectedState: "rollback_verification_succeeded" as const,
      expectedDigest: oldSha,
      expectRollbackCommitted: true,
      expectRollbackValidation: true,
    },
    {
      name: "thrown commit_unknown noncheckpoint",
      options: {
        rollbackStatus: "commit_unknown" as const,
        rollbackUnknownDigest: unknownSha,
        throwRollbackStatus: true,
      },
      expectedState: "manual_recovery_required" as const,
      expectedDigest: newSha,
      expectRollbackCommitted: false,
      expectRollbackValidation: false,
    },
  ])(
    "handles rollback atomic replace status: $name",
    async ({
      options,
      expectedState,
      expectedDigest,
      expectRollbackCommitted,
      expectRollbackValidation,
    }) => {
      const log: string[] = [];
      const fake = ports(log, {
        validationFailure: "candidate_post_apply",
        ...options,
      });
      const record = await new Phase3ApplyCoordinator(fake).apply(
        { proposalId: proposal().proposalId, grantId: grant().grantId },
        context(),
      );
      expect(record.state).toBe(expectedState);
      expect(fake.restoreCount()).toBe(1);
      expect(sha256(fake.live.bytes)).toBe(expectedDigest);
      expect(fake.journal.transitions).toContain(
        "apply_committed->rollback_intent",
      );
      if (expectRollbackCommitted) {
        expect(fake.journal.transitions).toContain(
          "rollback_intent->rollback_committed",
        );
      } else {
        expect(fake.journal.transitions).not.toContain(
          "rollback_intent->rollback_committed",
        );
      }
      if (expectRollbackValidation) {
        expect(log).toContain("validate:checkpoint_post_rollback:false");
        expect(log).toContain("verify:checkpoint:false");
      } else {
        expect(log).not.toContain("validate:checkpoint_post_rollback:false");
        expect(log).not.toContain("verify:checkpoint:false");
      }
    },
  );
  it("ignores caller cancellation after commit and still verifies", async () => {
    const log: string[] = [];
    const controller = new AbortController();
    const fake = ports(log, { abortOnApply: controller });
    const record = await new Phase3ApplyCoordinator(fake).apply(
      { proposalId: proposal().proposalId, grantId: grant().grantId },
      context(controller),
    );
    expect(record.state).toBe("verification_succeeded");
    expect(log).toContain("validate:candidate_post_apply:false");
    expect(log).toContain("verify:candidate:false");
  });
});
