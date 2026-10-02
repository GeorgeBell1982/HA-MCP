import { createHmac } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
  link,
  rename,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  Phase3OfflineRetention,
  type Phase3EpochStores,
  type Phase3RetentionStage,
} from "../src/phase3/retention.js";
import {
  canonicalJson,
  sha256,
  type Phase3TransactionRecord,
  type Phase3RecoveryResult,
  type Phase3ProposalSnapshot,
} from "../src/phase3/contracts.js";
import {
  DurablePhase3ApprovalGrants,
  PHASE3_APPROVAL_DOMAINS,
} from "../src/phase3/durableApproval.js";

const roots: string[] = [];
const durability = {
  privateMode: () => true,
  syncDirectory: async () => undefined,
};
const lease = { assertHeld: async () => undefined };
const key = Buffer.alloc(32, 0x31);
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(
  options: ConstructorParameters<typeof Phase3OfflineRetention>[2] = {},
) {
  const parent = await mkdtemp(join(tmpdir(), "phase3-retention-"));
  roots.push(parent);
  const retention = new Phase3OfflineRetention(parent, key, {
    durability,
    ...options,
  });
  const stores = await retention.initialize(lease);
  await stores.approvals.close();
  return { parent, retention, stores };
}
function record(index = 1): Phase3TransactionRecord {
  const id = (value: number) =>
    `00000000-0000-4000-8000-${value.toString(16).padStart(12, "0")}`;
  return {
    schemaVersion: 2,
    transactionId: id(index),
    proposalId: id(index + 100),
    proposalStorageSha256: sha256("storage"),
    path: "automations.yaml",
    expectedSha256: sha256("old"),
    candidateSha256: sha256("new"),
    diffSha256: sha256("diff"),
    checkpointId: id(index + 200),
    checkpointSha256: sha256("old"),
    impact: "domain_reload",
    reloadTarget: "automation.reload",
    rollbackReloadRequired: false,
    state: "intent_prepared",
    priorState: null,
    version: 0,
    createdAt: "2026-10-02T00:00:00.000Z",
    updatedAt: "2026-10-02T00:00:00.000Z",
    failure: null,
  };
}
async function terminal(
  stores: Phase3EpochStores,
  rollback = false,
  index = 1,
  patch: Partial<Phase3TransactionRecord> = {},
) {
  const checkpoint = await stores.checkpoints.create(
    "automations.yaml",
    Buffer.from("old"),
    sha256("old"),
    { signal: new AbortController().signal, deadlineAt: Date.now() + 60_000 },
  );
  let item = await stores.journal.createIntent({
    ...record(index),
    checkpointId: checkpoint.checkpointId,
    checkpointSha256: checkpoint.checkpointSha256,
    ...patch,
  });
  const states = rollback
    ? ([
        "rollback_intent",
        "rollback_committed",
        "rollback_validation_succeeded",
        "rollback_verification_succeeded",
      ] as const)
    : ([
        "apply_committed",
        "post_validation_succeeded",
        "reload_intent",
        "reload_succeeded",
        "verification_succeeded",
      ] as const);
  for (const state of states)
    item = await stores.journal.transition(
      item.transactionId,
      item.version,
      state,
    );
  return item;
}
async function proof(
  stores: Phase3EpochStores,
): Promise<readonly Phase3RecoveryResult[]> {
  return (await stores.journal.listRecoverable()).map((record) => ({
    transactionId: record.transactionId,
    terminalState: record.state,
    observedDigest:
      record.state === "verification_succeeded"
        ? "candidate"
        : "expected_or_checkpoint",
    observedSha256:
      record.state === "verification_succeeded"
        ? record.candidateSha256
        : record.checkpointSha256,
    disposition:
      record.state === "verification_succeeded" ? "verified" : "rolled_back",
    manualAttentionRequired: false,
    record,
  }));
}

describe("Phase 3 offline epoch retention", () => {
  it("re-proves current digest after the durable marker before rename", async () => {
    let drifted = false;
    const { parent, retention, stores } = await fixture({
      afterStage: async (stage) => {
        if (stage === "marker_synced") drifted = true;
      },
    });
    await terminal(stores);
    const dynamicProof = async (epoch: Phase3EpochStores) =>
      (await proof(epoch)).map((row) =>
        drifted ? { ...row, observedSha256: sha256("drift") } : row,
      );
    await expect(retention.rotate(lease, dynamicProof)).rejects.toThrow(
      "digest",
    );
    expect(await readdir(parent)).toEqual(["active", "rotation.json"]);
    drifted = false;
    await new Phase3OfflineRetention(parent, key, { durability }).resume(
      lease,
      dynamicProof,
    );
  });
  it("requires checkpoint bytes matching both immutable transaction digests", async () => {
    const missing = await fixture();
    const missingRecord = await terminal(missing.stores);
    await rm(
      join(missing.stores.root, "checkpoints", missingRecord.checkpointId),
    );
    await expect(missing.retention.rotate(lease, proof)).rejects.toThrow(
      "missing",
    );
    const wrong = await fixture();
    await terminal(wrong.stores, false, 1, {
      expectedSha256: sha256("different"),
    });
    await expect(wrong.retention.rotate(lease, proof)).rejects.toThrow(
      "checkpoint binding",
    );
    const wrongCheckpoint = await fixture();
    await terminal(wrongCheckpoint.stores, false, 1, {
      checkpointSha256: sha256("different"),
    });
    await expect(
      wrongCheckpoint.retention.rotate(lease, proof),
    ).rejects.toThrow("checkpoint binding");
  });
  it.each(["absent", "unconsumed", "mismatched", "valid"] as const)(
    "cross-binds authenticated approval consumption (%s)",
    async (kind) => {
      const { retention, stores } = await fixture();
      let grantId = record(700).transactionId;
      if (kind !== "absent") {
        const now = Date.now() - 600_000;
        const snapshot: Phase3ProposalSnapshot = {
          proposalId: record().proposalId,
          proposalStorageSha256: sha256(
            kind === "mismatched" ? "other-proposal-including-risk" : "storage",
          ),
          state: "pending",
          path: "automations.yaml",
          expectedSha256: sha256("old"),
          candidateSha256: sha256("new"),
          diffSha256: sha256("diff"),
          risk: "high",
          impact: "domain_reload",
          reloadTarget: "automation.reload",
          expiresAt: new Date(now + 600_000).toISOString(),
        };
        const approvals = new DurablePhase3ApprovalGrants(
          join(stores.root, "approvals"),
          key,
          { durability, now: () => now },
        );
        await approvals.initialize();
        const grant = await approvals.issueApplyGrant(snapshot, {
          now,
          signal: new AbortController().signal,
        });
        grantId = grant.grantId;
        if (kind !== "unconsumed")
          await approvals.consumeApplyGrant(grantId, snapshot, {
            now,
            signal: new AbortController().signal,
          });
        await approvals.close();
      }
      await terminal(stores, false, 1, { approvalGrantId: grantId });
      if (kind === "valid")
        await expect(retention.rotate(lease, proof)).resolves.toContain(
          "archive-",
        );
      else
        await expect(retention.rotate(lease, proof)).rejects.toThrow(
          "Consumed approval evidence",
        );
    },
  );
  it("validates committed audit rows and preserves a recognized torn tail unchanged", async () => {
    const bad = await fixture();
    await terminal(bad.stores);
    await writeFile(join(bad.stores.root, "operator.jsonl"), "{}\n");
    await expect(bad.retention.rotate(lease, proof)).rejects.toThrow();
    const good = await fixture();
    await terminal(good.stores);
    const audit = Buffer.from(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        attemptId: record(90).transactionId,
        event: "attempt",
        proposalId: record().proposalId,
      }) +
        "\n" +
        '{"timestamp":',
    );
    await writeFile(join(good.stores.root, "operator.jsonl"), audit);
    const archive = await good.retention.rotate(lease, proof);
    expect(await readFile(join(archive, "operator.jsonl"))).toEqual(audit);
    await writeFile(join(archive, "operator.jsonl"), "{malformed}\n");
    await expect(good.retention.rotate(lease, proof)).rejects.toThrow();
  });
  it("continues beyond 64 terminal transactions across bounded preserved epochs", async () => {
    const { parent, retention } = await fixture();
    let firstArchive: string | undefined;
    for (let index = 1; index <= 65; index += 1) {
      const epoch = await retention.open(lease);
      await terminal(epoch, false, index);
      await epoch.approvals.close();
      const archived = await retention.rotate(lease, proof);
      firstArchive ??= archived;
    }
    expect(
      (await readdir(parent)).filter((name) => name.startsWith("archive-"))
        .length,
    ).toBe(65);
    expect((await readdir(join(firstArchive!, "journal"))).length).toBe(6);
    const final = await retention.open(lease);
    await final.approvals.close();
  }, 120_000);
  it("resets 128 checkpoint and 256 authenticated expired grant capacity without deleting evidence", async () => {
    const { retention, stores } = await fixture();
    const bytes = Buffer.from("old");
    const context = {
      signal: new AbortController().signal,
      deadlineAt: Date.now() + 120_000,
    };
    for (let index = 0; index < 128; index += 1)
      await stores.checkpoints.create(
        "automations.yaml",
        bytes,
        sha256(bytes),
        context,
      );
    await expect(
      stores.checkpoints.create(
        "automations.yaml",
        bytes,
        sha256(bytes),
        context,
      ),
    ).rejects.toThrow();
    const now = Date.now() - 600_000;
    const snapshot: Phase3ProposalSnapshot = {
      proposalId: record().proposalId,
      proposalStorageSha256: sha256("storage"),
      state: "pending",
      path: "automations.yaml",
      expectedSha256: sha256("old"),
      candidateSha256: sha256("new"),
      diffSha256: sha256("diff"),
      risk: "high",
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      expiresAt: new Date(now + 600_000).toISOString(),
    };
    const approvals = new DurablePhase3ApprovalGrants(
      join(stores.root, "approvals"),
      key,
      { durability, now: () => now },
    );
    await approvals.initialize();
    const seed = await approvals.issueApplyGrant(snapshot, {
      now,
      signal: context.signal,
    });
    await approvals.close();
    // Valid signed fixtures exercise the authenticated full-store scanner without 256 quadratic issue scans.
    for (let index = 1; index < 256; index += 1) {
      const slot = join(
        stores.root,
        "approvals",
        `slot-${index.toString().padStart(3, "0")}`,
      );
      await mkdir(slot, { mode: 0o700 });
      const core = {
        schemaVersion: 1,
        grant: { ...seed, grantId: record(index + 1000).transactionId },
      };
      const grantHmac = createHmac("sha256", key)
        .update(PHASE3_APPROVAL_DOMAINS.grant)
        .update(canonicalJson(core))
        .digest("hex");
      await writeFile(
        join(slot, "grant.json"),
        canonicalJson({ ...core, grantHmac }),
        { mode: 0o600 },
      );
    }
    const full = new DurablePhase3ApprovalGrants(
      join(stores.root, "approvals"),
      key,
      { durability, now: () => now },
    );
    await full.initialize();
    expect(await full.retentionSummary()).toEqual({
      consumed: 0,
      expired: 0,
      liveUnused: 256,
    });
    await expect(
      full.issueApplyGrant(snapshot, { now, signal: context.signal }),
    ).rejects.toMatchObject({ code: "approval_capacity_exhausted" });
    await full.close();
    const archive = await retention.rotate(lease, proof);
    expect((await readdir(join(archive, "checkpoints"))).length).toBe(128);
    expect((await readdir(join(archive, "approvals"))).length).toBe(257);
    const fresh = await retention.open(lease);
    await fresh.checkpoints.create("automations.yaml", bytes, sha256(bytes), {
      ...context,
      deadlineAt: Date.now() + 60_000,
    });
    await fresh.approvals.issueApplyGrant(
      { ...snapshot, expiresAt: new Date(Date.now() + 600_000).toISOString() },
      { now: Date.now(), signal: context.signal },
    );
    await fresh.approvals.close();
  }, 120_000);
  it.each([false, true])(
    "preserves terminal archive bytes and initializes fresh stores (rollback=%s)",
    async (rollback) => {
      const { parent, retention, stores } = await fixture();
      await terminal(stores, rollback);
      const entries = await readdir(join(stores.root, "journal"));
      const before = await readFile(join(stores.root, "journal", entries[0]!));
      const archive = await retention.rotate(lease, proof);
      expect(await readFile(join(archive, "journal", entries[0]!))).toEqual(
        before,
      );
      const fresh = await retention.open(lease);
      expect(await fresh.journal.listRecoverable()).toEqual([]);
      await fresh.approvals.close();
      expect(await readdir(parent)).toContain(archive.slice(parent.length + 1));
    },
  );
  it("refuses manual, nonterminal, multiple transactions and mismatched live proof before rename", async () => {
    const { parent, retention, stores } = await fixture();
    const item = await stores.journal.createIntent(record());
    await expect(retention.rotate(lease, proof)).rejects.toThrow("terminal");
    let current = await stores.journal.transition(
      item.transactionId,
      item.version,
      "rollback_intent",
    );
    current = await stores.journal.transition(
      current.transactionId,
      current.version,
      "manual_recovery_required",
    );
    await expect(retention.rotate(lease, proof)).rejects.toThrow("terminal");
    expect(await readdir(parent)).toEqual(["active"]);
    const second = await fixture();
    await terminal(second.stores);
    await expect(
      second.retention.rotate(lease, async (epoch) =>
        (await proof(epoch)).map((row) => ({
          ...row,
          observedSha256: sha256("drift"),
        })),
      ),
    ).rejects.toThrow("digest");
    await terminal(second.stores, false, 2);
    await expect(second.retention.open(lease)).rejects.toThrow("multiple");
    await expect(second.retention.rotate(lease, proof)).rejects.toThrow("sole");
  });
  it.each([
    "marker_synced",
    "archive_renamed",
    "archive_parent_synced",
    "active_created",
    "stores_initialized",
  ] satisfies Phase3RetentionStage[])(
    "requires explicit resume after %s interruption",
    async (stage) => {
      const { parent, retention, stores } = await fixture({
        afterStage: async (at) => {
          if (at === stage) throw new Error("crash");
        },
      });
      await terminal(stores);
      await expect(retention.rotate(lease, proof)).rejects.toThrow("crash");
      const restart = new Phase3OfflineRetention(parent, key, { durability });
      await expect(restart.open(lease)).rejects.toThrow("resume");
      await restart.resume(lease, proof);
      const fresh = await restart.open(lease);
      await fresh.approvals.close();
      expect(await readdir(parent)).not.toContain("rotation.json");
    },
  );
  it("blocks resume when archived live proof drifted or identity was replaced", async () => {
    const { parent, retention, stores } = await fixture({
      afterStage: async (stage) => {
        if (stage === "archive_renamed") throw new Error("crash");
      },
    });
    await terminal(stores);
    await expect(retention.rotate(lease, proof)).rejects.toThrow();
    const restart = new Phase3OfflineRetention(parent, key, { durability });
    await expect(
      restart.resume(lease, async (epoch) =>
        (await proof(epoch)).map((row) => ({
          ...row,
          manualAttentionRequired: true,
        })),
      ),
    ).rejects.toThrow("digest");
    const archive = (await readdir(parent)).find((name) =>
      name.startsWith("archive-"),
    )!;
    await rename(join(parent, archive), join(parent, "old"));
    await rename(join(parent, "old"), join(parent, "active"));
    // Wrong archive target cannot be introduced through marker traversal.
    await writeFile(
      join(parent, "rotation.json"),
      JSON.stringify({
        version: 1,
        archive: "../active",
        device: "1",
        inode: "1",
      }),
    );
    await expect(restart.resume(lease, proof)).rejects.toThrow();
  });
  it("bounds archive count and bytes before creating a marker", async () => {
    const { parent, retention } = await fixture({ maximumArchives: 1 });
    await retention.rotate(lease, proof);
    await expect(retention.rotate(lease, proof)).rejects.toThrow(
      "count budget",
    );
    expect(await readdir(parent)).not.toContain("rotation.json");
    const small = await fixture({ maximumArchiveBytes: 1 });
    await expect(small.retention.rotate(lease, proof)).rejects.toThrow(
      "byte budget",
    );
    expect(await readdir(small.parent)).toEqual(["active"]);
  });
  it("refuses absent or partial startup, unknown entries, hardlinked metadata and lost lease", async () => {
    const { parent, retention } = await fixture();
    await expect(
      retention.open({
        assertHeld: async () => {
          throw new Error("lease lost");
        },
      }),
    ).rejects.toThrow("lease lost");
    await writeFile(join(parent, "active", "operator.jsonl"), "{}\n");
    await link(
      join(parent, "active", "operator.jsonl"),
      join(parent, "active", "linked"),
    );
    await expect(retention.open(lease)).rejects.toThrow();
    await rm(join(parent, "active", "linked"));
    await rm(join(parent, "active", "checkpoints"), { recursive: true });
    await expect(retention.open(lease)).rejects.toThrow("incomplete");
    await rm(join(parent, "active"), { recursive: true });
    await expect(retention.open(lease)).rejects.toThrow("resume");
  });
  it("does not silently initialize a missing header during normal startup", async () => {
    const { retention, stores } = await fixture();
    await rm(join(stores.root, "approvals", "header.json"));
    await expect(retention.open(lease)).rejects.toThrow();
    expect(await readdir(join(stores.root, "approvals"))).toEqual([]);
    await expect(retention.resume(lease, proof)).rejects.toThrow();
  });
  it("freshly authenticates approval evidence and blocks live unused grants", async () => {
    const { retention, stores } = await fixture();
    const now = Date.now();
    const snapshot: Phase3ProposalSnapshot = {
      proposalId: record().proposalId,
      proposalStorageSha256: sha256("storage"),
      state: "pending",
      path: "automations.yaml",
      expectedSha256: sha256("old"),
      candidateSha256: sha256("new"),
      diffSha256: sha256("diff"),
      risk: "high",
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      expiresAt: new Date(now + 600000).toISOString(),
    };
    const approvals = new DurablePhase3ApprovalGrants(
      join(stores.root, "approvals"),
      key,
      { durability, now: () => now },
    );
    await approvals.initialize();
    const grant = await approvals.issueApplyGrant(snapshot, {
      now,
      signal: new AbortController().signal,
    });
    expect(await approvals.retentionSummary()).toEqual({
      consumed: 0,
      expired: 0,
      liveUnused: 1,
    });
    await expect(retention.rotate(lease, proof)).rejects.toThrow("live unused");
    await approvals.consumeApplyGrant(grant.grantId, snapshot, {
      now,
      signal: new AbortController().signal,
    });
    expect(await approvals.retentionSummary()).toEqual({
      consumed: 1,
      expired: 0,
      liveUnused: 0,
    });
    await approvals.close();
    await retention.rotate(lease, proof);
    const fresh = await retention.open(lease);
    await expect(
      fresh.approvals.consumeApplyGrant(grant.grantId, snapshot, {
        now,
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow();
    await fresh.approvals.close();
  });
  it("counts expired authenticated grants at the exact trusted expiry boundary", async () => {
    const { stores } = await fixture();
    let now = Date.now();
    const approvals = new DurablePhase3ApprovalGrants(
      join(stores.root, "approvals"),
      key,
      { durability, now: () => now },
    );
    await approvals.initialize();
    const proposal: Phase3ProposalSnapshot = {
      proposalId: record().proposalId,
      proposalStorageSha256: sha256("storage"),
      state: "pending",
      path: "automations.yaml",
      expectedSha256: sha256("old"),
      candidateSha256: sha256("new"),
      diffSha256: sha256("diff"),
      risk: "high",
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      expiresAt: new Date(now + 600000).toISOString(),
    };
    const grant = await approvals.issueApplyGrant(proposal, {
      now,
      signal: new AbortController().signal,
    });
    now = Date.parse(grant.expiresAt);
    expect(await approvals.retentionSummary()).toEqual({
      consumed: 0,
      expired: 1,
      liveUnused: 0,
    });
    await approvals.close();
  });
  it("rotates an expired unused grant and rejects tampered authenticated evidence", async () => {
    const { retention, stores } = await fixture();
    const now = Date.now() - 600_000;
    const proposal: Phase3ProposalSnapshot = {
      proposalId: record().proposalId,
      proposalStorageSha256: sha256("storage"),
      state: "pending",
      path: "automations.yaml",
      expectedSha256: sha256("old"),
      candidateSha256: sha256("new"),
      diffSha256: sha256("diff"),
      risk: "high",
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      expiresAt: new Date(now + 600_000).toISOString(),
    };
    const approvals = new DurablePhase3ApprovalGrants(
      join(stores.root, "approvals"),
      key,
      { durability, now: () => now },
    );
    await approvals.initialize();
    await approvals.issueApplyGrant(proposal, {
      now,
      signal: new AbortController().signal,
    });
    await approvals.close();
    await retention.rotate(lease, proof);
    const fresh = await retention.open(lease);
    await fresh.approvals.close();
    await writeFile(join(fresh.root, "approvals", "header.json"), "{}");
    await expect(retention.rotate(lease, proof)).rejects.toThrow();
  });
  it("refuses concurrent retention operations and checks a lost lease before mutation", async () => {
    let release: (() => void) | undefined;
    let entered: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const { parent, retention } = await fixture({
      afterStage: async (stage) => {
        if (stage === "marker_synced") {
          entered!();
          await gate;
        }
      },
    });
    const rotating = retention.rotate(lease, proof);
    await started;
    await expect(retention.open(lease)).rejects.toThrow("already active");
    release!();
    await rotating;
    let checks = 0;
    await expect(
      retention.rotate(
        {
          assertHeld: async () => {
            if (++checks === 2) throw new Error("lease lost");
          },
        },
        proof,
      ),
    ).rejects.toThrow("lease lost");
    expect(await readdir(parent)).not.toContain("rotation.json");
  });
  it("refuses a recognized marker whose archived directory identity was replaced", async () => {
    const { parent, retention, stores } = await fixture({
      afterStage: async (stage) => {
        if (stage === "archive_renamed") throw new Error("crash");
      },
    });
    await terminal(stores);
    await expect(retention.rotate(lease, proof)).rejects.toThrow("crash");
    const marker = JSON.parse(
      await readFile(join(parent, "rotation.json"), "utf8"),
    ) as { inode: string };
    await writeFile(
      join(parent, "rotation.json"),
      JSON.stringify({ ...marker, inode: "0" }),
    );
    await expect(
      new Phase3OfflineRetention(parent, key, { durability }).resume(
        lease,
        proof,
      ),
    ).rejects.toThrow("identity");
  });
});
