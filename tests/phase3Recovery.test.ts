import { describe, expect, it } from "vitest";
import {
  InMemoryPhase3Journal,
  Phase3ApplyCoordinator,
  type Phase3ApplyCoordinatorPorts,
} from "../src/phase3/applyCoordinator.js";
import {
  assertPhase3TransactionRecord,
  phase3CanTransition,
  sha256,
  type Phase3JournalPort,
  type Phase3StructuredFailure,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "../src/phase3/contracts.js";
import { Phase3ResourceLocks } from "../src/phase3/resourceLocks.js";

const oldBytes = Buffer.from("old: true\n");
const newBytes = Buffer.from("old: false\n");
const corruptCheckpointBytes = Buffer.from("old: corrupt\n");
const oldSha = sha256(oldBytes);
const newSha = sha256(newBytes);

function record(
  state: Phase3TransactionRecord["state"],
): Phase3TransactionRecord {
  return {
    schemaVersion: 1,
    transactionId: "11111111-1111-4111-8111-111111111111",
    proposalId: "22222222-2222-4222-8222-222222222222",
    proposalStorageSha256: sha256("proposal"),
    path: "automations/lights.yaml",
    expectedSha256: oldSha,
    candidateSha256: newSha,
    diffSha256: sha256("diff"),
    checkpointId: "33333333-3333-4333-8333-333333333333",
    checkpointSha256: oldSha,
    impact: "none",
    state,
    priorState: null,
    version: 0,
    createdAt: "2026-07-20T00:00:00.000Z",
    updatedAt: "2026-07-20T00:00:00.000Z",
    failure: null,
  };
}

class LoggingJournal implements Phase3JournalPort {
  readonly transitions: string[] = [];
  private current: Phase3TransactionRecord;

  constructor(initial: Phase3TransactionRecord) {
    this.current = Object.freeze({ ...initial });
  }

  async createIntent(): Promise<Phase3TransactionRecord> {
    throw new Error("recovery tests seed existing durable records");
  }

  async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{ failure?: Phase3StructuredFailure | null }> = {},
  ): Promise<Phase3TransactionRecord> {
    await Promise.resolve();
    if (transactionId !== this.current.transactionId)
      throw new Error("transaction mismatch");
    if (expectedVersion !== this.current.version)
      throw new Error("version mismatch");
    if (!phase3CanTransition(this.current.state, state))
      throw new Error(`illegal transition ${this.current.state}->${state}`);
    const before = this.current;
    this.current = Object.freeze(
      assertPhase3TransactionRecord({
        ...before,
        state,
        priorState: before.state,
        version: before.version + 1,
        updatedAt: "2026-07-20T00:00:01.000Z",
        failure: Object.hasOwn(patch, "failure")
          ? patch.failure
          : before.failure,
      }),
    );
    this.transitions.push(`${before.state}->${state}`);
    return this.current;
  }

  async load(transactionId: string): Promise<Phase3TransactionRecord | null> {
    await Promise.resolve();
    return transactionId === this.current.transactionId ? this.current : null;
  }

  async listRecoverable(): Promise<readonly Phase3TransactionRecord[]> {
    await Promise.resolve();
    return [this.current];
  }
}

function recoveryPorts(
  live: { bytes: Buffer | null },
  journal: LoggingJournal,
  options: Readonly<{ checkpointBytes?: Buffer }> = {},
): Phase3ApplyCoordinatorPorts & {
  readonly log: readonly string[];
  readonly restoreCount: () => number;
} {
  const log: string[] = [];
  let restores = 0;
  return {
    log,
    restoreCount: () => restores,
    now: () => Date.parse("2026-07-20T00:00:00.000Z"),
    proposals: {
      async load() {
        throw new Error("recovery must not load proposal");
      },
      async loadCandidate() {
        throw new Error("recovery must never reapply candidate");
      },
    },
    policy: {
      async evaluate() {
        throw new Error("recovery must not evaluate policy");
      },
    },
    approvals: {
      async consumeApplyGrant() {
        throw new Error("recovery must not consume approvals");
      },
    },
    locks: new Phase3ResourceLocks(),
    source: {
      async read() {
        throw new Error("recovery must not read source bytes");
      },
      async readDigest() {
        return live.bytes ? sha256(live.bytes) : null;
      },
    },
    validation: {
      async validate() {
        log.push("validate");
      },
    },
    checkpoints: {
      async create() {
        throw new Error("recovery must not create checkpoints");
      },
      async load() {
        log.push("checkpoint-load");
        return Buffer.from(options.checkpointBytes ?? oldBytes);
      },
    },
    atomicApply: {
      async replace(input) {
        log.push(`restore:${input.contentSha256}`);
        restores += 1;
        live.bytes = Buffer.from(input.content);
        return { status: "committed" };
      },
    },
    reload: {
      async reloadDomain() {
        throw new Error("recovery must not restart or reload implicitly");
      },
    },
    verification: {
      async verify() {
        log.push("verify");
      },
    },
    journal,
  };
}

async function recover(
  state: Phase3TransactionRecord["state"],
  liveBytes: Buffer | null,
  options: Readonly<{ checkpointBytes?: Buffer }> = {},
) {
  const journal = new LoggingJournal(record(state));
  const live = { bytes: liveBytes ? Buffer.from(liveBytes) : null };
  const fake = recoveryPorts(live, journal, options);
  const [recovered] = await new Phase3ApplyCoordinator(fake).recover();
  return { recovered, live, journal, fake };
}

describe("Phase 3A startup recovery", () => {
  it("uses no-live-effect rollback completion for intent_prepared checkpoint digest", async () => {
    const { recovered, live, journal, fake } = await recover(
      "intent_prepared",
      oldBytes,
    );
    expect(recovered?.record.state).toBe("rollback_verification_succeeded");
    expect(journal.transitions).toEqual([
      "intent_prepared->rollback_intent",
      "rollback_intent->rollback_committed",
      "rollback_committed->rollback_validation_succeeded",
      "rollback_validation_succeeded->rollback_verification_succeeded",
    ]);
    expect(fake.restoreCount()).toBe(0);
    expect(sha256(live.bytes!)).toBe(oldSha);
  });

  it("rolls back intent_prepared candidate digest and never reapplies candidate", async () => {
    const { recovered, live, journal, fake } = await recover(
      "intent_prepared",
      newBytes,
    );
    expect(recovered?.record.state).toBe("rollback_verification_succeeded");
    expect(journal.transitions).toContain("intent_prepared->rollback_intent");
    expect(fake.restoreCount()).toBe(1);
    expect(sha256(live.bytes!)).toBe(oldSha);
  });

  it("manuals intent_prepared unknown and missing digests", async () => {
    for (const liveBytes of [Buffer.from("unknown: true\n"), null]) {
      const { recovered, fake } = await recover("intent_prepared", liveBytes);
      expect(recovered?.record.state).toBe("manual_recovery_required");
      expect(recovered?.record.failure?.code).toBe("digest_unknown");
      expect(fake.restoreCount()).toBe(0);
    }
  });

  it.each([
    "apply_committed",
    "post_validation_succeeded",
    "reload_succeeded",
    "rollback_intent",
  ] as const)("rolls back %s when candidate is live", async (state) => {
    const { recovered, live, journal, fake } = await recover(state, newBytes);
    expect(recovered?.record.state).toBe("rollback_verification_succeeded");
    if (state !== "rollback_intent")
      expect(journal.transitions).toContain(`${state}->rollback_intent`);
    expect(fake.restoreCount()).toBe(1);
    expect(sha256(live.bytes!)).toBe(oldSha);
  });

  it.each([
    "apply_committed",
    "post_validation_succeeded",
    "reload_succeeded",
    "rollback_intent",
  ] as const)(
    "completes rollback validation for %s when checkpoint is live",
    async (state) => {
      const { recovered, journal, fake } = await recover(state, oldBytes);
      expect(recovered?.record.state).toBe("rollback_verification_succeeded");
      if (state !== "rollback_intent")
        expect(journal.transitions).toContain(`${state}->rollback_intent`);
      expect(journal.transitions).toContain(
        "rollback_intent->rollback_committed",
      );
      expect(fake.restoreCount()).toBe(0);
      expect(fake.log).toEqual(["checkpoint-load", "validate", "verify"]);
    },
  );

  it.each([
    "apply_committed",
    "post_validation_succeeded",
    "reload_succeeded",
    "rollback_intent",
  ] as const)("manuals %s for other or missing live digest", async (state) => {
    for (const liveBytes of [Buffer.from("unknown: true\n"), null]) {
      const { recovered, fake } = await recover(state, liveBytes);
      expect(recovered?.record.state).toBe("manual_recovery_required");
      expect(recovered?.record.failure?.code).toBe("digest_unknown");
      expect(fake.restoreCount()).toBe(0);
    }
  });

  it("completes rollback_committed without moving backward", async () => {
    const { recovered, journal, fake } = await recover(
      "rollback_committed",
      oldBytes,
    );
    expect(recovered?.record.state).toBe("rollback_verification_succeeded");
    expect(journal.transitions).toEqual([
      "rollback_committed->rollback_validation_succeeded",
      "rollback_validation_succeeded->rollback_verification_succeeded",
    ]);
    expect(fake.restoreCount()).toBe(0);
  });

  it("completes rollback_validation_succeeded without moving backward", async () => {
    const { recovered, journal, fake } = await recover(
      "rollback_validation_succeeded",
      oldBytes,
    );
    expect(recovered?.record.state).toBe("rollback_verification_succeeded");
    expect(journal.transitions).toEqual([
      "rollback_validation_succeeded->rollback_verification_succeeded",
    ]);
    expect(fake.log).toEqual(["checkpoint-load", "verify"]);
    expect(fake.restoreCount()).toBe(0);
  });

  it.each(["rollback_committed", "rollback_validation_succeeded"] as const)(
    "manuals %s for non-checkpoint digest",
    async (state) => {
      const { recovered, fake } = await recover(state, newBytes);
      expect(recovered?.record.state).toBe("manual_recovery_required");
      expect(recovered?.record.failure?.code).toBe("rollback_digest_drift");
      expect(fake.restoreCount()).toBe(0);
    },
  );

  it("manuals corrupt checkpoint during startup recovery without restore", async () => {
    const { recovered, fake, live } = await recover(
      "apply_committed",
      newBytes,
      {
        checkpointBytes: corruptCheckpointBytes,
      },
    );
    expect(recovered?.record.state).toBe("manual_recovery_required");
    expect(recovered?.record.failure?.code).toBe("checkpoint_digest_mismatch");
    expect(fake.restoreCount()).toBe(0);
    expect(sha256(live.bytes!)).toBe(newSha);
  });

  it("returns terminal verified disposition only when candidate remains live", async () => {
    const verified = await recover("verification_succeeded", newBytes);
    expect(verified.recovered?.record.state).toBe("verification_succeeded");
    expect(verified.recovered?.disposition).toBe("verified");
    expect(verified.recovered?.manualAttentionRequired).toBe(false);
    expect(verified.recovered?.observedDigest).toBe("candidate");
    expect(verified.journal.transitions).toEqual([]);
  });

  it.each([
    {
      name: "expected/checkpoint",
      liveBytes: oldBytes,
      observed: "expected_or_checkpoint" as const,
    },
    {
      name: "other",
      liveBytes: Buffer.from("unknown: true\n"),
      observed: "other_or_missing" as const,
    },
    { name: "missing", liveBytes: null, observed: "other_or_missing" as const },
  ])(
    "surfaces manual attention for drifted verified terminal: $name",
    async ({ liveBytes, observed }) => {
      const verified = await recover("verification_succeeded", liveBytes);
      expect(verified.recovered?.record.state).toBe("verification_succeeded");
      expect(verified.recovered?.disposition).toBe("manual_attention_required");
      expect(verified.recovered?.manualAttentionRequired).toBe(true);
      expect(verified.recovered?.observedDigest).toBe(observed);
      expect(verified.journal.transitions).toEqual([]);
    },
  );

  it("returns terminal rolled-back disposition only when checkpoint remains live", async () => {
    const rolledBack = await recover(
      "rollback_verification_succeeded",
      oldBytes,
    );
    expect(rolledBack.recovered?.record.state).toBe(
      "rollback_verification_succeeded",
    );
    expect(rolledBack.recovered?.disposition).toBe("rolled_back");
    expect(rolledBack.recovered?.manualAttentionRequired).toBe(false);
    expect(rolledBack.recovered?.observedDigest).toBe("expected_or_checkpoint");
    expect(rolledBack.journal.transitions).toEqual([]);
  });

  it.each([
    { name: "candidate", liveBytes: newBytes, observed: "candidate" as const },
    {
      name: "other",
      liveBytes: Buffer.from("unknown: true\n"),
      observed: "other_or_missing" as const,
    },
    { name: "missing", liveBytes: null, observed: "other_or_missing" as const },
  ])(
    "surfaces manual attention for drifted rolled-back terminal: $name",
    async ({ liveBytes, observed }) => {
      const rolledBack = await recover(
        "rollback_verification_succeeded",
        liveBytes,
      );
      expect(rolledBack.recovered?.record.state).toBe(
        "rollback_verification_succeeded",
      );
      expect(rolledBack.recovered?.disposition).toBe(
        "manual_attention_required",
      );
      expect(rolledBack.recovered?.manualAttentionRequired).toBe(true);
      expect(rolledBack.recovered?.observedDigest).toBe(observed);
      expect(rolledBack.journal.transitions).toEqual([]);
    },
  );

  it("reports manual terminal records without mutation", async () => {
    const manual = await recover("manual_recovery_required", null);
    expect(manual.recovered?.record.state).toBe("manual_recovery_required");
    expect(manual.recovered?.disposition).toBe("manual_attention_required");
    expect(manual.recovered?.manualAttentionRequired).toBe(true);
    expect(manual.journal.transitions).toEqual([]);
  });

  it("rejects illegal and terminal journal transitions", async () => {
    const journal = new InMemoryPhase3Journal();
    const created = await journal.createIntent(record("intent_prepared"));
    await expect(
      journal.transition(
        created.transactionId,
        created.version,
        "reload_succeeded",
      ),
    ).rejects.toMatchObject({ code: "journal_illegal_transition" });
    const applied = await journal.transition(
      created.transactionId,
      created.version,
      "apply_committed",
    );
    const postValidated = await journal.transition(
      applied.transactionId,
      applied.version,
      "post_validation_succeeded",
    );
    const reloaded = await journal.transition(
      postValidated.transactionId,
      postValidated.version,
      "reload_succeeded",
    );
    const terminal = await journal.transition(
      reloaded.transactionId,
      reloaded.version,
      "verification_succeeded",
    );
    await expect(
      journal.transition(
        terminal.transactionId,
        terminal.version,
        "manual_recovery_required",
      ),
    ).rejects.toMatchObject({ code: "journal_illegal_transition" });

    const rollbackJournal = new InMemoryPhase3Journal();
    const start = await rollbackJournal.createIntent(record("intent_prepared"));
    const rollbackIntent = await rollbackJournal.transition(
      start.transactionId,
      start.version,
      "rollback_intent",
    );
    const rollbackCommitted = await rollbackJournal.transition(
      rollbackIntent.transactionId,
      rollbackIntent.version,
      "rollback_committed",
    );
    const rollbackValidated = await rollbackJournal.transition(
      rollbackCommitted.transactionId,
      rollbackCommitted.version,
      "rollback_validation_succeeded",
    );
    await expect(
      rollbackJournal.transition(
        rollbackValidated.transactionId,
        rollbackValidated.version,
        "rollback_committed",
      ),
    ).rejects.toMatchObject({ code: "journal_illegal_transition" });
  });
});
