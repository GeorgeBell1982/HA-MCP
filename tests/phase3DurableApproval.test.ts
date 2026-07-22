import { createHmac } from "node:crypto";
import { constants, readdirSync } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import { Phase3ApprovalError } from "../src/phase3/approval.js";
import {
  canonicalJson,
  sha256,
  type Phase3ProposalSnapshot,
} from "../src/phase3/contracts.js";
import {
  DurablePhase3ApprovalGrants,
  PHASE3_APPROVAL_DOMAINS,
  PHASE3_APPROVAL_LIMITS,
  Phase3ApprovalSimulatedCrash,
  type DurablePhase3ApprovalOptions,
  type Phase3ApprovalFileHandle,
  type Phase3ApprovalFilesystem,
  type Phase3ApprovalHookStage,
  type Phase3ApprovalOpenLease,
} from "../src/phase3/durableApproval.js";

const roots: string[] = [];
const key = Buffer.alloc(32, 0x31);
const otherKey = Buffer.alloc(32, 0x32);
const issuedAt = Date.parse("2026-07-22T10:00:00.000Z");
const signal = new AbortController().signal;
const proposal: Phase3ProposalSnapshot = {
  proposalId: "11111111-1111-4111-8111-111111111111",
  proposalStorageSha256: sha256("proposal"),
  state: "pending",
  path: "automations/lights.yaml",
  expectedSha256: sha256("old"),
  candidateSha256: sha256("new"),
  diffSha256: sha256("diff"),
  risk: "high",
  impact: "domain_reload",
  reloadTarget: "automation.reload",
  expiresAt: "2026-07-22T10:05:00.000Z",
};

const logicalDurability: Phase2DurabilityPort = Object.freeze({
  privateMode: () => true,
  syncDirectory: async () => {},
});

const nativeFilesystem: Phase3ApprovalFilesystem = Object.freeze({
  lstat,
  mkdir,
  open: async (
    path: string,
    flags: number,
    mode: number | undefined,
    lease: Phase3ApprovalOpenLease,
  ) => await leasedHandle(await open(path, flags, mode), lease),
  readdir,
  link,
  rename,
  rm,
});

afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

describe("Phase 3L durable approval grants", () => {
  it("exports frozen exact limits and distinct trailing-NUL domains", () => {
    expect(PHASE3_APPROVAL_LIMITS).toEqual({
      slots: 256,
      headerStages: 4,
      grantStages: 32,
      usedStages: 4,
      rootScanEntries: 293,
      slotScanEntries: 6,
      headerBytes: 1024,
      grantBytes: 4096,
      receiptBytes: 1024,
      grantTtlMs: 120_000,
      uuidAttempts: 4,
    });
    expect(Object.isFrozen(PHASE3_APPROVAL_LIMITS)).toBe(true);
    expect(new Set(Object.values(PHASE3_APPROVAL_DOMAINS)).size).toBe(4);
    for (const domain of Object.values(PHASE3_APPROVAL_DOMAINS))
      expect(domain.endsWith("\0")).toBe(true);
  });

  it("issues the exact canonical authenticated wire and fixed TTL", async () => {
    const root = await approvalRoot();
    const uuids = uuidSource([
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    ]);
    const store = durable(root, key, issuedAt, uuids);
    await store.initialize();
    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });

    expect(grant).toEqual({
      grantId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      proposalId: proposal.proposalId,
      proposalStorageSha256: proposal.proposalStorageSha256,
      candidateSha256: proposal.candidateSha256,
      diffSha256: proposal.diffSha256,
      operation: "apply",
      risk: proposal.risk,
      impact: proposal.impact,
      reloadTarget: proposal.reloadTarget,
      issuedAt: "2026-07-22T10:00:00.000Z",
      expiresAt: "2026-07-22T10:02:00.000Z",
    });
    expect(await readdir(root)).toEqual(["header.json", "slot-000"]);

    const headerText = await readFile(join(root, "header.json"), "utf8");
    const header = JSON.parse(headerText) as Record<string, unknown>;
    expect(headerText).toBe(canonicalJson(header));
    const headerCore = {
      schemaVersion: header.schemaVersion,
      storeId: header.storeId,
      keyId: header.keyId,
    };
    expect(header.headerHmac).toBe(
      hmac(key, PHASE3_APPROVAL_DOMAINS.header, headerCore),
    );
    expect(header.keyId).toBe(
      hmac(key, PHASE3_APPROVAL_DOMAINS.keyId, {
        schemaVersion: 1,
        purpose: "phase3_approval_key_identity",
      }),
    );

    const grantText = await readFile(
      join(root, "slot-000", "grant.json"),
      "utf8",
    );
    const envelope = JSON.parse(grantText) as Record<string, unknown>;
    expect(grantText).toBe(canonicalJson(envelope));
    expect(envelope.grantHmac).toBe(
      hmac(key, PHASE3_APPROVAL_DOMAINS.grant, {
        schemaVersion: 1,
        grant,
      }),
    );
  });

  it("persists single-use consumption across restart with replay precedence", async () => {
    const root = await approvalRoot();
    const store = durable(
      root,
      key,
      issuedAt,
      uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    );
    await store.initialize();
    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).resolves.toEqual(grant);
    expect(await readdir(join(root, "slot-000"))).toEqual([
      "grant.json",
      "used.json",
    ]);

    const restarted = durable(root, key, issuedAt + 2, uuidSource([]));
    await restarted.initialize();
    await expect(
      restarted.consumeApplyGrant(
        grant.grantId,
        { ...proposal, state: "discarded" },
        { now: Number.NaN, signal },
      ),
    ).rejects.toMatchObject({ code: "approval_replayed" });
  });

  it("fails wrong bindings, exact boundaries, malformed time, and cancellation closed", async () => {
    const root = await approvalRoot();
    let clock = issuedAt;
    const store = durable(
      root,
      key,
      () => clock,
      uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    );
    await store.initialize();
    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      store.consumeApplyGrant(
        grant.grantId,
        { ...proposal, diffSha256: sha256("drift") },
        { now: issuedAt + 1, signal },
      ),
    ).rejects.toMatchObject({ code: "approval_wrong_binding" });
    clock = Date.parse(grant.expiresAt);
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: clock,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_expired" });
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(
      store.consumeApplyGrant(
        "00000000-0000-4000-8000-000000000000",
        proposal,
        {
          now: Number.NaN,
          signal: cancelled.signal,
        },
      ),
    ).rejects.toMatchObject({ code: "approval_cancelled" });
  });

  it("accepts concurrent same-key initialization and rejects a different key", async () => {
    const root = await approvalRoot();
    const left = durable(
      root,
      key,
      issuedAt,
      uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    );
    const right = durable(
      root,
      key,
      issuedAt,
      uuidSource(["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]),
    );
    await expect(
      Promise.all([left.initialize(), right.initialize()]),
    ).resolves.toEqual([undefined, undefined]);
    const wrong = durable(root, otherKey, issuedAt, uuidSource([]));
    await expect(wrong.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });
  });

  it("serializes two-instance issue and consume races without duplicate success", async () => {
    const root = await approvalRoot();
    const first = durable(
      root,
      key,
      issuedAt,
      uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    );
    await first.initialize();
    const second = durable(
      root,
      key,
      issuedAt,
      uuidSource(["cccccccc-cccc-4ccc-8ccc-cccccccccccc"]),
    );
    await second.initialize();
    const grants = await Promise.all([
      first.issueApplyGrant(proposal, { now: issuedAt, signal }),
      second.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ]);
    expect(new Set(grants.map((grant) => grant.grantId)).size).toBe(2);

    const consumerA = durable(root, key, issuedAt + 1, uuidSource([]));
    const consumerB = durable(root, key, issuedAt + 1, uuidSource([]));
    await Promise.all([consumerA.initialize(), consumerB.initialize()]);
    const settled = await Promise.allSettled([
      consumerA.consumeApplyGrant(grants[0].grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
      consumerB.consumeApplyGrant(grants[0].grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ]);
    expect(
      settled.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejected = settled.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { code: "approval_replayed" },
    });
  });

  it("fails closed for tamper, noncanonical bytes, wrong topology, and stage range", async () => {
    const tamperRoot = await approvalRoot();
    const store = durable(
      tamperRoot,
      key,
      issuedAt,
      uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    );
    await store.initialize();
    await store.issueApplyGrant(proposal, { now: issuedAt, signal });
    const grantPath = join(tamperRoot, "slot-000", "grant.json");
    const parsed = JSON.parse(await readFile(grantPath, "utf8")) as object;
    await writeFile(grantPath, JSON.stringify(parsed, null, 2), {
      mode: 0o600,
    });
    await expect(
      durable(tamperRoot, key, issuedAt, uuidSource([])).initialize(),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });

    const topologyRoot = await approvalRoot();
    await writeFile(join(topologyRoot, "unknown"), "", { mode: 0o600 });
    await expect(
      durable(
        topologyRoot,
        key,
        issuedAt,
        uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      ).initialize(),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });

    const rangeRoot = await approvalRoot();
    await mkdir(join(rangeRoot, ".grant-stage-32"), { mode: 0o700 });
    await expect(
      durable(
        rangeRoot,
        key,
        issuedAt,
        uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      ).initialize(),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
  });

  it("keeps fixed-stage exhaustion non-latching and accepts the exact maximum", async () => {
    const root = await approvalRoot();
    for (let index = 0; index < PHASE3_APPROVAL_LIMITS.headerStages; index += 1)
      await writeFile(join(root, `.header-stage-${index}`), "", {
        mode: 0o600,
      });
    const store = durable(
      root,
      key,
      issuedAt,
      uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      ]),
    );
    await expect(store.initialize()).rejects.toMatchObject({
      code: "approval_capacity_exhausted",
    });
    await rm(join(root, ".header-stage-0"));
    await expect(store.initialize()).resolves.toBeUndefined();

    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    const slot = join(root, "slot-000");
    for (let index = 0; index < PHASE3_APPROVAL_LIMITS.usedStages; index += 1)
      await writeFile(join(slot, `.used-stage-${index}`), "", { mode: 0o600 });
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_capacity_exhausted" });
    await rm(join(slot, ".used-stage-0"));
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).resolves.toEqual(grant);
  });

  it("zeros grant envelopes across exact stage exhaustion, retry, and claim failure", async () => {
    const exhaustedRoot = await approvalRoot();
    const exhaustedStore = configured(exhaustedRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      ]),
    });
    await exhaustedStore.initialize();
    for (let index = 0; index < PHASE3_APPROVAL_LIMITS.grantStages; index += 1)
      await mkdir(
        join(exhaustedRoot, `.grant-stage-${String(index).padStart(2, "0")}`),
        { mode: 0o700 },
      );

    const exhaustedTracking = trackBufferZeroing();
    try {
      await expect(
        exhaustedStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
      ).rejects.toMatchObject({ code: "approval_capacity_exhausted" });
      const grantEvents = exhaustedTracking.events.filter((event) =>
        event.before.includes(Buffer.from('"grant":')),
      );
      expect(grantEvents.length).toBeGreaterThan(0);
      expect(grantEvents.every((event) => isZeroed(event.buffer))).toBe(true);
    } finally {
      exhaustedTracking.restore();
    }

    await rm(join(exhaustedRoot, ".grant-stage-00"), {
      recursive: true,
      force: true,
    });
    await expect(
      exhaustedStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).resolves.toMatchObject({
      grantId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    });

    const failedRoot = await approvalRoot();
    const failedSeed = configured(failedRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await failedSeed.initialize();
    const failedStore = configured(failedRoot, {
      filesystem: {
        ...nativeFilesystem,
        mkdir: async () => {
          throw ioFailure("grant claim canary");
        },
      },
      randomUUID: uuidSource(["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]),
    });
    await failedStore.initialize();
    const failedTracking = trackBufferZeroing();
    try {
      await expect(
        failedStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
      ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
      const grantEvents = failedTracking.events.filter((event) =>
        event.before.includes(Buffer.from('"grant":')),
      );
      expect(grantEvents.length).toBeGreaterThan(0);
      expect(grantEvents.every((event) => isZeroed(event.buffer))).toBe(true);
      await expect(
        failedStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
      ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
    } finally {
      failedTracking.restore();
    }
  });

  it("returns durable success after post-parent hooks and closes idempotently", async () => {
    const root = await approvalRoot();
    const postParent = new Set<Phase3ApprovalHookStage>([
      "header_parent_synced",
      "grant_parent_synced",
      "receipt_parent_synced",
    ]);
    const sourceKey = Buffer.alloc(32, 0x44);
    const store = new DurablePhase3ApprovalGrants(root, sourceKey, {
      durability: logicalDurability,
      now: () => issuedAt,
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
      hooks: {
        afterStage: async ({ stage }) => {
          if (postParent.has(stage)) throw new Error("post-durable canary");
        },
      },
    });
    await store.initialize();
    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).resolves.toEqual(grant);
    const firstClose = store.close();
    expect(store.close()).toBe(firstClose);
    await firstClose;
    expect(sourceKey.every((byte) => byte === 0x44)).toBe(true);
    await expect(store.initialize()).rejects.toBeInstanceOf(
      Phase3ApprovalError,
    );
  });

  it("reconciles committed-but-threw syscalls and post-commit hooks", async () => {
    const root = await approvalRoot();
    const postCommit = new Set<Phase3ApprovalHookStage>([
      "header_post_commit",
      "grant_post_commit",
      "receipt_post_commit",
    ]);
    const filesystem: Phase3ApprovalFilesystem = {
      ...nativeFilesystem,
      link: async (source, target) => {
        await link(source, target);
        throw ioFailure("link committed canary");
      },
      rename: async (source, target) => {
        await rename(source, target);
        throw ioFailure("rename committed canary");
      },
    };
    const store = configured(root, {
      filesystem,
      hooks: {
        afterStage: async ({ stage }) => {
          if (postCommit.has(stage)) throw new Error("post-commit canary");
        },
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await store.initialize();
    const grant = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      store.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).resolves.toEqual(grant);
  });

  it("latches commit unknown when post-syscall reconciliation cannot observe header, grant, or receipt", async () => {
    const headerRoot = await approvalRoot();
    let failHeaderObservation = false;
    const headerStore = configured(headerRoot, {
      filesystem: {
        ...nativeFilesystem,
        link: async (source, target) => {
          await link(source, target);
          failHeaderObservation = true;
          throw ioFailure("header committed canary");
        },
        lstat: async (path, options) => {
          if (failHeaderObservation && path === join(headerRoot, "header.json"))
            throw ioFailure("header observation canary");
          return await lstat(path, options);
        },
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await expect(headerStore.initialize()).rejects.toMatchObject({
      code: "approval_commit_unknown",
    });
    await expect(headerStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });

    const grantRoot = await approvalRoot();
    const seed = configured(grantRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await seed.initialize();
    let failGrantObservation = false;
    const grantStore = configured(grantRoot, {
      filesystem: {
        ...nativeFilesystem,
        rename: async (source, target) => {
          await rename(source, target);
          failGrantObservation = true;
          throw ioFailure("grant committed canary");
        },
        lstat: async (path, options) => {
          if (failGrantObservation && path === join(grantRoot, "slot-000"))
            throw ioFailure("grant observation canary");
          return await lstat(path, options);
        },
      },
      randomUUID: uuidSource(["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]),
    });
    await grantStore.initialize();
    await expect(
      grantStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "approval_commit_unknown" });

    const receiptRoot = await approvalRoot();
    const receiptSeed = configured(receiptRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await receiptSeed.initialize();
    const grant = await receiptSeed.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    let failReceiptObservation = false;
    const receiptStore = configured(receiptRoot, {
      filesystem: {
        ...nativeFilesystem,
        link: async (source, target) => {
          await link(source, target);
          if (target.endsWith("used.json")) {
            failReceiptObservation = true;
            throw ioFailure("receipt committed canary");
          }
        },
        lstat: async (path, options) => {
          if (
            failReceiptObservation &&
            path === join(receiptRoot, "slot-000", "used.json")
          )
            throw ioFailure("receipt observation canary");
          return await lstat(path, options);
        },
      },
      randomUUID: uuidSource([]),
    });
    await receiptStore.initialize();
    await expect(
      receiptStore.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_commit_unknown" });
  });

  it("revalidates cancellation and expiry after issue and consume precommit hooks", async () => {
    const issueRoot = await approvalRoot();
    const issueClock = issuedAt;
    const issueAbort = new AbortController();
    const issueStore = configured(issueRoot, {
      now: () => issueClock,
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "grant_pre_commit") issueAbort.abort();
        },
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await issueStore.initialize();
    await expect(
      issueStore.issueApplyGrant(proposal, {
        now: issuedAt,
        signal: issueAbort.signal,
      }),
    ).rejects.toMatchObject({ code: "approval_cancelled" });

    const expiryRoot = await approvalRoot();
    let expiryClock = issuedAt;
    const expiryStore = configured(expiryRoot, {
      now: () => expiryClock,
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "grant_pre_commit")
            expiryClock = Date.parse(proposal.expiresAt);
        },
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await expiryStore.initialize();
    await expect(
      expiryStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "proposal_expired" });

    const consumeRoot = await approvalRoot();
    const consumeClock = issuedAt;
    const consumeAbort = new AbortController();
    const consumeStore = configured(consumeRoot, {
      now: () => consumeClock,
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "receipt_pre_commit") consumeAbort.abort();
        },
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await consumeStore.initialize();
    const abortGrant = await consumeStore.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      consumeStore.consumeApplyGrant(abortGrant.grantId, proposal, {
        now: issuedAt + 1,
        signal: consumeAbort.signal,
      }),
    ).rejects.toMatchObject({ code: "approval_cancelled" });

    const consumeExpiryRoot = await approvalRoot();
    let consumeExpiryClock = issuedAt;
    const consumeExpiryStore = configured(consumeExpiryRoot, {
      now: () => consumeExpiryClock,
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "receipt_pre_commit")
            consumeExpiryClock = issuedAt + PHASE3_APPROVAL_LIMITS.grantTtlMs;
        },
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await consumeExpiryStore.initialize();
    const expiryGrant = await consumeExpiryStore.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await expect(
      consumeExpiryStore.consumeApplyGrant(expiryGrant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_expired" });
  });

  it("sanitizes and latches representative filesystem, durability, and hook failures before commit", async () => {
    const cases: ReadonlyArray<{
      name: string;
      options: (root: string) => DurablePhase3ApprovalOptions;
    }> = [
      {
        name: "open",
        options: () => ({
          filesystem: {
            ...nativeFilesystem,
            open: async () => {
              throw ioFailure("open path canary");
            },
          },
        }),
      },
      {
        name: "write",
        options: () => ({
          filesystem: {
            ...nativeFilesystem,
            open: async (path, flags, mode, lease) => {
              const handle = await open(path, flags, mode);
              return await leasedHandle(
                handle,
                lease,
                failingHandle(handle, "write"),
              );
            },
          },
        }),
      },
      {
        name: "file sync",
        options: () => ({
          filesystem: {
            ...nativeFilesystem,
            open: async (path, flags, mode, lease) => {
              const handle = await open(path, flags, mode);
              return await leasedHandle(
                handle,
                lease,
                failingHandle(handle, "sync"),
              );
            },
          },
        }),
      },
      {
        name: "hook",
        options: () => ({
          hooks: {
            afterStage: async ({ stage }) => {
              if (stage === "header_file_synced")
                throw new Error("hook path canary");
            },
          },
        }),
      },
    ];
    for (const failure of cases) {
      const root = await approvalRoot();
      const store = configured(root, {
        ...failure.options(root),
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });
      const error = await store.initialize().catch((caught: unknown) => caught);
      expect(error, failure.name).toMatchObject({
        code: "approval_store_unhealthy",
      });
      expect(String(error)).not.toContain("canary");
      expect(String(error)).not.toContain(root);
      await expect(store.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
      });
    }

    const root = await approvalRoot();
    const seed = configured(root, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await seed.initialize();
    const issueStore = configured(root, {
      filesystem: {
        ...nativeFilesystem,
        mkdir: async () => {
          throw ioFailure("mkdir path canary");
        },
      },
      randomUUID: uuidSource(["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]),
    });
    await issueStore.initialize();
    await expect(
      issueStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
    await expect(
      issueStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
  });

  it("retries benign header cleanup, stage creation, and rename scan windows", async () => {
    const headerRoot = await approvalRoot();
    const headerSeed = configured(headerRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await headerSeed.initialize();
    const headerStage = join(headerRoot, ".header-stage-0");
    await link(join(headerRoot, "header.json"), headerStage);
    let headerWindow = true;
    const headerReader = configured(headerRoot, {
      filesystem: {
        ...nativeFilesystem,
        readdir: async (path) => {
          const names = await readdir(path);
          if (headerWindow && path === headerRoot) {
            headerWindow = false;
            await rm(headerStage);
          }
          return names;
        },
      },
      randomUUID: uuidSource([]),
    });
    await expect(headerReader.initialize()).resolves.toBeUndefined();

    const stageRoot = await approvalRoot();
    const stageSeed = configured(stageRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await stageSeed.initialize();
    let stageWindow = true;
    const stageReader = configured(stageRoot, {
      filesystem: {
        ...nativeFilesystem,
        readdir: async (path) => {
          const names = await readdir(path);
          if (stageWindow && path === stageRoot) {
            stageWindow = false;
            await mkdir(join(stageRoot, ".grant-stage-00"), { mode: 0o700 });
          }
          return names;
        },
      },
      randomUUID: uuidSource([]),
    });
    await expect(stageReader.initialize()).resolves.toBeUndefined();

    const renameRoot = await approvalRoot();
    const renameSeed = configured(renameRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await renameSeed.initialize();
    await renameSeed.issueApplyGrant(proposal, { now: issuedAt, signal });
    await rename(
      join(renameRoot, "slot-000"),
      join(renameRoot, ".grant-stage-00"),
    );
    let renameWindow = true;
    const renameReader = configured(renameRoot, {
      filesystem: {
        ...nativeFilesystem,
        readdir: async (path) => {
          const names = await readdir(path);
          if (renameWindow && path === renameRoot) {
            renameWindow = false;
            await rename(
              join(renameRoot, ".grant-stage-00"),
              join(renameRoot, "slot-000"),
            );
          }
          return names;
        },
      },
      randomUUID: uuidSource([]),
    });
    await expect(renameReader.initialize()).resolves.toBeUndefined();
  });

  it("regenerates an existing durable grant ID without committing a collision slot", async () => {
    const root = await approvalRoot();
    const values = [
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    ];
    let slotCountBeforeRegeneration = -1;
    let stagesBeforeRegeneration: string[] = [];
    const store = configured(root, {
      randomUUID: () => {
        const value = values.shift();
        if (!value) throw new Error("UUID source exhausted");
        if (value.startsWith("cccccccc")) {
          const names = readdirSync(root);
          slotCountBeforeRegeneration = names.filter((name) =>
            name.startsWith("slot-"),
          ).length;
          stagesBeforeRegeneration = names.filter((name) =>
            name.startsWith(".grant-stage-"),
          );
        }
        return value;
      },
    });
    await store.initialize();
    const first = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    const second = await store.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    expect(first.grantId).toBe("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    expect(second.grantId).toBe("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    expect(slotCountBeforeRegeneration).toBe(1);
    expect(stagesBeforeRegeneration).toEqual([]);
    expect(
      (await readdir(root)).filter((name) => name.startsWith("slot-")),
    ).toEqual(["slot-000", "slot-001"]);
  });

  it("sanitizes Phase3ApprovalError values thrown by filesystem, durability, and hook boundaries", async () => {
    const filesystemRoot = await approvalRoot();
    const filesystemStore = configured(filesystemRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async () => {
          throw new Phase3ApprovalError(
            "approval_cancelled",
            `${filesystemRoot} filesystem canary`,
          );
        },
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await expectSanitizedFailure(
      filesystemStore.initialize(),
      "approval_store_unhealthy",
      filesystemRoot,
    );
    await expect(filesystemStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });

    const durabilityRoot = await approvalRoot();
    const durabilityStore = new DurablePhase3ApprovalGrants(
      durabilityRoot,
      key,
      {
        durability: {
          privateMode: () => true,
          syncDirectory: async () => {
            throw new Phase3ApprovalError(
              "approval_replayed",
              `${durabilityRoot} durability canary`,
            );
          },
        },
        now: () => issuedAt,
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      },
    );
    await expectSanitizedFailure(
      durabilityStore.initialize(),
      "approval_commit_unknown",
      durabilityRoot,
    );
    await expect(durabilityStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });

    const hookRoot = await approvalRoot();
    const hookStore = configured(hookRoot, {
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "header_file_synced")
            throw new Phase3ApprovalError(
              "approval_not_found",
              `${hookRoot} hook canary`,
            );
        },
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await expectSanitizedFailure(
      hookStore.initialize(),
      "approval_store_unhealthy",
      hookRoot,
    );
  });

  it("copies hostile successful filesystem results inside boundary sanitization", async () => {
    const cases: ReadonlyArray<{
      name: string;
      message?: string;
      filesystem: (foreign: Phase3ApprovalError) => Phase3ApprovalFilesystem;
    }> = [
      {
        name: "lstat metadata getter",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          lstat: async (path, options) => {
            const metadata = await lstat(path, options);
            return new Proxy(metadata, {
              get: (target, property) => {
                if (property === "mode") throw foreign;
                return Reflect.get(target, property, target) as unknown;
              },
            });
          },
        }),
      },
      {
        name: "lstat metadata method",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          lstat: async (path, options) => {
            const metadata = await lstat(path, options);
            return new Proxy(metadata, {
              get: (target, property) => {
                if (property === "isDirectory")
                  return () => {
                    throw foreign;
                  };
                return Reflect.get(target, property, target) as unknown;
              },
            });
          },
        }),
      },
      {
        name: "readdir array",
        message: "Approval store scan did not stabilize",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          readdir: async (path) => {
            const entries = await readdir(path);
            return new Proxy(entries, {
              get: (target, property) => {
                if (property === "length") throw foreign;
                return Reflect.get(target, property, target) as unknown;
              },
            });
          },
        }),
      },
      {
        name: "readdir entry",
        message: "Approval store scan did not stabilize",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          readdir: async () =>
            new Proxy(["header.json"], {
              get: (target, property) => {
                if (property === "0") throw foreign;
                return Reflect.get(target, property, target) as unknown;
              },
            }),
        }),
      },
      {
        name: "open handle method",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          open: async (_path, _flags, _mode, lease) => {
            lease.register(async () => {});
            return new Proxy({} as Phase3ApprovalFileHandle, {
              get: (_target, property) => {
                if (property === "then") return undefined;
                if (property === "write") throw foreign;
                return async () => undefined;
              },
            });
          },
        }),
      },
      {
        name: "write result",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          open: async (path, flags, mode, lease) => {
            const handle = await open(path, flags, mode);
            const exposed: Phase3ApprovalFileHandle = {
              write: async (buffer, offset, length, position) =>
                new Proxy(
                  await handle.write(buffer, offset, length, position),
                  {
                    get: (target, property) => {
                      if (property === "bytesWritten") throw foreign;
                      return Reflect.get(target, property, target) as unknown;
                    },
                  },
                ),
              sync: async () => await handle.sync(),
              stat: async (options) => await handle.stat(options),
              readFile: async () => await handle.readFile(),
            };
            return await leasedHandle(handle, lease, exposed);
          },
        }),
      },
      {
        name: "handle stat result",
        filesystem: (foreign) => ({
          ...nativeFilesystem,
          open: async (path, flags, mode, lease) => {
            const handle = await open(path, flags, mode);
            const exposed: Phase3ApprovalFileHandle = {
              write: async (buffer, offset, length, position) =>
                await handle.write(buffer, offset, length, position),
              sync: async () => await handle.sync(),
              stat: async (options) =>
                new Proxy(await handle.stat(options), {
                  get: (target, property) => {
                    if (property === "size") throw foreign;
                    return Reflect.get(target, property, target) as unknown;
                  },
                }),
              readFile: async () => await handle.readFile(),
            };
            return await leasedHandle(handle, lease, exposed);
          },
        }),
      },
    ];

    for (const testCase of cases) {
      const root = await approvalRoot();
      const foreign = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} ${testCase.name} canary`,
      );
      const store = configured(root, {
        filesystem: testCase.filesystem(foreign),
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });
      const first = await store.initialize().catch((error: unknown) => error);
      expect(first, testCase.name).not.toBe(foreign);
      expect(first, testCase.name).toMatchObject({
        code: "approval_store_unhealthy",
        message: testCase.message ?? "Approval initialization failed",
      });
      expect(String(first), testCase.name).not.toContain(root);
      expect(String(first), testCase.name).not.toContain("canary");
      await expect(store.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval store is unhealthy",
      });
    }
  });

  it("closes a real opened handle exactly once when wrapper validation fails", async () => {
    for (const failureProperty of ["stat", "readFile"] as const) {
      const root = await approvalRoot();
      const validationFailure = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} ${failureProperty} validation canary`,
      );
      const closeFailure = new Phase3ApprovalError(
        "approval_cancelled",
        `${root} close canary`,
      );
      const closeMemberFailure = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} close getter canary`,
      );
      let closes = 0;
      let closeGetterReads = 0;
      const store = configured(root, {
        filesystem: {
          ...nativeFilesystem,
          open: async (path, flags, mode, lease) => {
            const handle = await open(path, flags, mode);
            const close = handle.close.bind(handle);
            lease.register(async () => {
              closes += 1;
              await close();
              if (failureProperty === "readFile") throw closeFailure;
            });
            return new Proxy(handle, {
              get: (target, property) => {
                if (property === "then") return undefined;
                if (property === "close") {
                  closeGetterReads += 1;
                  throw closeMemberFailure;
                }
                if (property === failureProperty) throw validationFailure;
                const result = Reflect.get(target, property, target) as unknown;
                return bindUnknownMethod(result, target);
              },
            });
          },
        },
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });

      const first = await store.initialize().catch((error: unknown) => error);
      expect(first, failureProperty).not.toBe(validationFailure);
      expect(first, failureProperty).not.toBe(closeFailure);
      expect(first, failureProperty).not.toBe(closeMemberFailure);
      expect(first, failureProperty).toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval initialization failed",
      });
      expect(String(first), failureProperty).not.toContain(root);
      expect(String(first), failureProperty).not.toContain("canary");
      expect(closes, failureProperty).toBe(1);
      expect(closeGetterReads, failureProperty).toBe(0);
      await expect(store.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval store is unhealthy",
      });
      expect(closes, failureProperty).toBe(1);
      expect(closeGetterReads, failureProperty).toBe(0);

      const stage = join(root, ".header-stage-0");
      await rm(stage, { force: true });
      await writeFile(stage, "closed", { mode: 0o600 });
      await rm(stage, { force: true });
    }
  });

  it("atomically copies and zeroes successful and failed Proxy Buffer handoffs", async () => {
    const successfulRoot = await approvalRoot();
    const successfulSeed = configured(successfulRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await successfulSeed.initialize();
    const successfulSources: Buffer[] = [];
    const successfulSnapshots: Buffer[] = [];
    const successfulTracking = trackBufferZeroing();
    try {
      const successfulStore = configured(successfulRoot, {
        filesystem: {
          ...nativeFilesystem,
          open: async (path, flags, mode, lease) => {
            const handle = await open(path, flags, mode);
            const exposed: Phase3ApprovalFileHandle = {
              write: async (buffer, offset, length, position) =>
                await handle.write(buffer, offset, length, position),
              sync: async () => await handle.sync(),
              stat: async (options) => await handle.stat(options),
              readFile: async () => {
                const source = await handle.readFile();
                successfulSources.push(source);
                successfulSnapshots.push(Buffer.from(source));
                return proxyBuffer(source);
              },
            };
            return await leasedHandle(handle, lease, exposed);
          },
        },
        randomUUID: uuidSource([]),
      });
      await successfulStore.initialize();
      expect(successfulSources.length).toBeGreaterThan(0);
      expect(successfulSources.every(isZeroed)).toBe(true);
      for (const snapshot of successfulSnapshots)
        expect(
          successfulTracking.events.some(
            (event) =>
              !successfulSources.includes(event.buffer) &&
              Buffer.compare(event.before, snapshot) === 0 &&
              isZeroed(event.buffer),
          ),
        ).toBe(true);
      await successfulStore.close();
    } finally {
      successfulTracking.restore();
    }

    const failedRoot = await approvalRoot();
    const failedSeed = configured(failedRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await failedSeed.initialize();
    const failedSources: Buffer[] = [];
    const failedSnapshots: Buffer[] = [];
    const failedForeign = new Phase3ApprovalError(
      "approval_commit_unknown",
      `${failedRoot} buffer cleanup canary`,
    );
    const failedTracking = trackBufferZeroing();
    try {
      const failedStore = configured(failedRoot, {
        filesystem: {
          ...nativeFilesystem,
          open: async (path, flags, mode, lease) => {
            const handle = await open(path, flags, mode);
            const exposed: Phase3ApprovalFileHandle = {
              write: async (buffer, offset, length, position) =>
                await handle.write(buffer, offset, length, position),
              sync: async () => await handle.sync(),
              stat: async (options) => await handle.stat(options),
              readFile: async () => {
                const source = await handle.readFile();
                failedSources.push(source);
                failedSnapshots.push(Buffer.from(source));
                return proxyBuffer(source, failedForeign);
              },
            };
            return await leasedHandle(handle, lease, exposed);
          },
        },
        randomUUID: uuidSource([]),
      });
      const first = await failedStore
        .initialize()
        .catch((error: unknown) => error);
      expect(first).not.toBe(failedForeign);
      expect(first).toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval store scan did not stabilize",
      });
      expect(String(first)).not.toContain(failedRoot);
      expect(String(first)).not.toContain("canary");
      expect(failedSources.some((source) => !isZeroed(source))).toBe(true);
      for (const snapshot of failedSnapshots)
        expect(
          failedTracking.events.some(
            (event) =>
              !failedSources.includes(event.buffer) &&
              Buffer.compare(event.before, snapshot) === 0 &&
              isZeroed(event.buffer),
          ),
        ).toBe(true);
      await expect(failedStore.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval store is unhealthy",
      });
    } finally {
      failedTracking.restore();
    }
  });

  it("ignores shadowed buffer clear returns without unhandled rejection", async () => {
    for (const returnKind of ["rejectedPromise", "throwingThen"] as const) {
      const root = await approvalRoot();
      const seed = configured(root, {
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });
      await seed.initialize();
      await seed.close();
      const foreign = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} ${returnKind} clear canary`,
      );
      const sources: Buffer[] = [];
      const sourceLengths: number[] = [];
      const cleanups: Array<{ count: number }> = [];
      const unhandled: unknown[] = [];
      let fillCalls = 0;
      let thenGetterReads = 0;
      const onUnhandled = (reason: unknown): void => {
        unhandled.push(reason);
      };
      const allocations = trackBufferAllocations();
      process.on("unhandledRejection", onUnhandled);
      try {
        const store = configured(root, {
          filesystem: {
            ...nativeFilesystem,
            open: async (path, flags, mode, lease) => {
              const handle = await open(path, flags, mode);
              const close = handle.close.bind(handle);
              const cleanup = { count: 0 };
              cleanups.push(cleanup);
              try {
                lease.register(async () => {
                  cleanup.count += 1;
                  await close();
                });
                const exposed: Phase3ApprovalFileHandle = {
                  write: async (buffer, offset, length, position) =>
                    await handle.write(buffer, offset, length, position),
                  sync: async () => await handle.sync(),
                  stat: async (options) => await handle.stat(options),
                  readFile: async () => {
                    const source = await handle.readFile();
                    sources.push(source);
                    sourceLengths.push(source.byteLength);
                    Object.defineProperty(source, "fill", {
                      configurable: true,
                      value: (): unknown => {
                        fillCalls += 1;
                        for (
                          let index = 0;
                          index < source.byteLength;
                          index += 1
                        )
                          source[index] = 0;
                        if (returnKind === "rejectedPromise")
                          return Promise.reject(foreign);
                        return Object.create(null, {
                          then: {
                            get: () => {
                              thenGetterReads += 1;
                              throw foreign;
                            },
                          },
                        });
                      },
                    });
                    return source;
                  },
                };
                return exposed;
              } catch (error) {
                await close().catch(() => undefined);
                throw error;
              }
            },
          },
          randomUUID: uuidSource([]),
        });

        await expect(store.initialize()).resolves.toBeUndefined();
        await expect(store.initialize()).resolves.toBeUndefined();
        expect(fillCalls, returnKind).toBe(0);
        expect(thenGetterReads, returnKind).toBe(0);
        expect(sources.length, returnKind).toBeGreaterThan(0);
        expect(sources.every(isZeroed), returnKind).toBe(true);
        await store.close();
        await new Promise<void>((resolve) => setImmediate(resolve));
        expect(cleanups.length, returnKind).toBeGreaterThan(0);
        expect(
          cleanups.every((cleanup) => cleanup.count === 1),
          returnKind,
        ).toBe(true);
        for (const length of sourceLengths) {
          const destinations = allocations.buffers.filter(
            (buffer) => buffer.byteLength === length,
          );
          expect(destinations.length, returnKind).toBeGreaterThan(0);
          expect(destinations.every(isZeroed), returnKind).toBe(true);
        }
        expect(unhandled.map(String).join(" "), returnKind).not.toContain(root);
        expect(unhandled.map(String).join(" "), returnKind).not.toContain(
          "canary",
        );
        expect(unhandled, returnKind).toEqual([]);
      } finally {
        process.off("unhandledRejection", onUnhandled);
        allocations.restore();
      }
    }
  });

  it("zeros preallocated destinations on nth-byte and valueOf-bearing copy failures", async () => {
    for (const failureKind of ["getter", "valueOf"] as const) {
      const root = await approvalRoot();
      const seed = configured(root, {
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });
      await seed.initialize();
      const foreign = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} ${failureKind} copy canary`,
      );
      let sourceLength = 0;
      let valueOfCalls = 0;
      const allocations = trackBufferAllocations();
      try {
        const store = configured(root, {
          filesystem: {
            ...nativeFilesystem,
            open: async (path, flags, mode, lease) => {
              const handle = await open(path, flags, mode);
              const exposed: Phase3ApprovalFileHandle = {
                write: async (buffer, offset, length, position) =>
                  await handle.write(buffer, offset, length, position),
                sync: async () => await handle.sync(),
                stat: async (options) => await handle.stat(options),
                readFile: async () => {
                  const source = await handle.readFile();
                  sourceLength = source.byteLength;
                  return new Proxy(source, {
                    get: (target, property) => {
                      if (property === "then") return undefined;
                      if (property === "7") {
                        if (failureKind === "getter") throw foreign;
                        return {
                          valueOf: () => {
                            valueOfCalls += 1;
                            throw foreign;
                          },
                        };
                      }
                      const result = Reflect.get(
                        target,
                        property,
                        target,
                      ) as unknown;
                      return bindUnknownMethod(result, target);
                    },
                  });
                },
              };
              return await leasedHandle(handle, lease, exposed);
            },
          },
          randomUUID: uuidSource([]),
        });
        const first = await store.initialize().catch((error: unknown) => error);
        expect(first, failureKind).not.toBe(foreign);
        expect(first, failureKind).toMatchObject({
          code: "approval_store_unhealthy",
          message: "Approval store scan did not stabilize",
        });
        expect(String(first), failureKind).not.toContain(root);
        expect(String(first), failureKind).not.toContain("canary");
        const destinations = allocations.buffers.filter(
          (buffer) => buffer.byteLength === sourceLength,
        );
        expect(destinations.length, failureKind).toBeGreaterThan(0);
        expect(destinations.every(isZeroed), failureKind).toBe(true);
        if (failureKind === "valueOf") expect(valueOfCalls).toBe(0);
        await expect(store.initialize()).rejects.toMatchObject({
          code: "approval_store_unhealthy",
          message: "Approval store is unhealthy",
        });
      } finally {
        allocations.restore();
      }
    }
  });

  it("sanitizes hostile read buffers, UUIDs, clocks, hooks, and durability results", async () => {
    const readRoot = await approvalRoot();
    const readSeed = configured(readRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await readSeed.initialize();
    const readForeign = new Phase3ApprovalError(
      "approval_cancelled",
      `${readRoot} read canary`,
    );
    const readStore = configured(readRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          const exposed: Phase3ApprovalFileHandle = {
            write: async (buffer, offset, length, position) =>
              await handle.write(buffer, offset, length, position),
            sync: async () => await handle.sync(),
            stat: async (options) => await handle.stat(options),
            readFile: async () =>
              new Proxy(await handle.readFile(), {
                get: (target, property) => {
                  if (property === "length") throw readForeign;
                  return Reflect.get(target, property, target) as unknown;
                },
                set: (_target, property) => {
                  if (property === "0") throw readForeign;
                  return false;
                },
              }),
          };
          return await leasedHandle(handle, lease, exposed);
        },
      },
      randomUUID: uuidSource([]),
    });
    await expectSanitizedFailure(
      readStore.initialize(),
      "approval_store_unhealthy",
      readRoot,
    );
    await expect(readStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });

    const uuidRoot = await approvalRoot();
    const uuidForeign = new Phase3ApprovalError(
      "approval_commit_unknown",
      `${uuidRoot} UUID canary`,
    );
    const uuidStore = configured(uuidRoot, {
      randomUUID: () =>
        new Proxy(
          {},
          {
            get: () => {
              throw uuidForeign;
            },
          },
        ) as unknown as string,
    });
    const uuidFailure = await uuidStore
      .initialize()
      .catch((error: unknown) => error);
    expect(uuidFailure).not.toBe(uuidForeign);
    expect(uuidFailure).toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval UUID source failed",
    });
    expect(String(uuidFailure)).not.toContain(uuidRoot);
    expect(String(uuidFailure)).not.toContain("canary");
    await expect(uuidStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval store is unhealthy",
    });

    const clockRoot = await approvalRoot();
    const clockSeed = configured(clockRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await clockSeed.initialize();
    const clockForeign = new Phase3ApprovalError(
      "approval_commit_unknown",
      `${clockRoot} clock canary`,
    );
    const clockStore = configured(clockRoot, {
      now: () =>
        new Proxy(
          {},
          {
            get: () => {
              throw clockForeign;
            },
          },
        ) as unknown as number,
      randomUUID: uuidSource([]),
    });
    await clockStore.initialize();
    const clockFailure = await clockStore
      .issueApplyGrant(proposal, { now: issuedAt, signal })
      .catch((error: unknown) => error);
    expect(clockFailure).not.toBe(clockForeign);
    expect(clockFailure).toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval trusted clock failed",
    });
    expect(String(clockFailure)).not.toContain(clockRoot);
    expect(String(clockFailure)).not.toContain("canary");
    await expect(
      clockStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });

    const hookRoot = await approvalRoot();
    const hookStore = configured(hookRoot, {
      hooks: {
        afterStage: async ({ stage }) =>
          (stage === "header_file_synced" ? {} : undefined) as undefined,
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await expect(hookStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval lifecycle hook failed",
    });
    await expect(hookStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval store is unhealthy",
    });

    const durabilityRoot = await approvalRoot();
    const durabilityStore = new DurablePhase3ApprovalGrants(
      durabilityRoot,
      key,
      {
        durability: {
          privateMode: () => true,
          syncDirectory: async () => ({}) as unknown as undefined,
        },
        now: () => issuedAt,
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      },
    );
    await expect(durabilityStore.initialize()).rejects.toMatchObject({
      code: "approval_commit_unknown",
      message: "Approval header commit is unknown",
    });
    await expect(durabilityStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval store is unhealthy",
    });
  });

  it("trap-safely sanitizes hook Proxy retention metadata and latches unhealthy", async () => {
    const cases: ReadonlyArray<{
      name: string;
      thrown: (foreign: Phase3ApprovalError) => object;
    }> = [
      {
        name: "get trap",
        thrown: (foreign) =>
          new Proxy<object>(
            Object.create({ retainPhase3ApprovalStage: true }) as object,
            {
              get: () => {
                throw foreign;
              },
            },
          ),
      },
      {
        name: "getOwnPropertyDescriptor trap",
        thrown: (foreign) =>
          new Proxy(
            {},
            {
              getOwnPropertyDescriptor: () => {
                throw foreign;
              },
            },
          ),
      },
    ];

    for (const testCase of cases) {
      const root = await approvalRoot();
      const foreign = new Phase3ApprovalError(
        "approval_commit_unknown",
        `${root} ${testCase.name} canary`,
      );
      const thrown = testCase.thrown(foreign);
      const store = configured(root, {
        hooks: {
          afterStage: async ({ stage }) => {
            if (stage === "header_file_synced") throw thrown;
          },
        },
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });

      const first = await store.initialize().catch((error: unknown) => error);
      expect(first, testCase.name).toBeInstanceOf(Phase3ApprovalError);
      expect(first, testCase.name).not.toBe(foreign);
      expect(Object.is(first, thrown), testCase.name).toBe(false);
      expect(first, testCase.name).toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval lifecycle hook failed",
      });
      expect(String(first), testCase.name).not.toContain(root);
      expect(String(first), testCase.name).not.toContain("canary");
      await expect(store.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
        message: "Approval store is unhealthy",
      });
    }
  });

  it("retains a precommit stage only for the internally minted crash marker", async () => {
    const root = await approvalRoot();
    const store = configured(root, {
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "header_file_synced")
            throw new Phase3ApprovalSimulatedCrash(stage);
        },
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });

    await expect(store.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval lifecycle hook failed",
    });
    expect(await readdir(root)).toEqual([".header-stage-0"]);
    await expect(store.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
      message: "Approval store is unhealthy",
    });
  });

  it("zeros read and write buffers when handle close or slot parsing fails", async () => {
    const writeRoot = await approvalRoot();
    const written: Uint8Array[] = [];
    const writeStore = configured(writeRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          const closeFailure = new Phase3ApprovalError(
            "approval_expired",
            `${writeRoot} write-close canary`,
          );
          return await leasedHandle(
            handle,
            lease,
            trackedHandle(handle, { writes: written }),
            closeFailure,
          );
        },
      },
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await expect(writeStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });
    expect(written.length).toBeGreaterThan(0);
    expect(written.every(isZeroed)).toBe(true);

    const readRoot = await approvalRoot();
    const readSeed = configured(readRoot, {
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await readSeed.initialize();
    const closeReads: Buffer[] = [];
    const readStore = configured(readRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          const closeFailure =
            flags & constants.O_WRONLY
              ? undefined
              : new Phase3ApprovalError(
                  "approval_wrong_binding",
                  `${readRoot} read-close canary`,
                );
          return await leasedHandle(
            handle,
            lease,
            trackedHandle(handle, { reads: closeReads }),
            closeFailure,
          );
        },
      },
      randomUUID: uuidSource([]),
    });
    await expectSanitizedFailure(
      readStore.initialize(),
      "approval_store_unhealthy",
      readRoot,
    );
    expect(closeReads.length).toBeGreaterThan(0);
    expect(closeReads.every(isZeroed)).toBe(true);

    const parseRoot = await approvalRoot();
    const parseSeed = configured(parseRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await parseSeed.initialize();
    await parseSeed.issueApplyGrant(proposal, { now: issuedAt, signal });
    await writeFile(join(parseRoot, "slot-000", "used.json"), "{}", {
      mode: 0o600,
    });
    const parseReads: Buffer[] = [];
    const parseStore = configured(parseRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          return await leasedHandle(
            handle,
            lease,
            trackedHandle(handle, { reads: parseReads }),
          );
        },
      },
      randomUUID: uuidSource([]),
    });
    await expect(parseStore.initialize()).rejects.toMatchObject({
      code: "approval_store_unhealthy",
    });
    expect(parseReads.length).toBeGreaterThan(0);
    expect(parseReads.every(isZeroed)).toBe(true);
  });

  it("rejects malformed trusted clocks without cancellation or replay masking", async () => {
    const issueRoot = await approvalRoot();
    const issueStore = configured(issueRoot, {
      now: () => Number.NaN,
      randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
    });
    await issueStore.initialize();
    await expect(
      issueStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });

    const consumeRoot = await approvalRoot();
    let trustedClock = issuedAt;
    const consumeStore = configured(consumeRoot, {
      now: () => trustedClock,
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await consumeStore.initialize();
    const grant = await consumeStore.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    trustedClock = Number.POSITIVE_INFINITY;
    await expect(
      consumeStore.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_store_unhealthy" });
  });

  it("sanitizes foreign proposal access and uses an immutable copied snapshot downstream", async () => {
    const issueRoot = await approvalRoot();
    const issueBoundaryError = new Phase3ApprovalError(
      "approval_cancelled",
      `${issueRoot} issue proposal canary`,
    );
    const issueStore = configured(issueRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      ]),
    });
    await issueStore.initialize();
    const issueProxy = new Proxy(proposal, {
      get: (target, property, receiver): unknown => {
        if (property === "state") throw issueBoundaryError;
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const issueFailure = await issueStore
      .issueApplyGrant(issueProxy, { now: issuedAt, signal })
      .catch((error: unknown) => error);
    expect(issueFailure).toBeInstanceOf(Phase3ApprovalError);
    expect(issueFailure).not.toBe(issueBoundaryError);
    expect(issueFailure).toMatchObject({
      code: "proposal_not_pending",
      message: "Approval requires an exact pending proposal",
    });
    expect(String(issueFailure)).not.toContain(issueRoot);
    expect(String(issueFailure)).not.toContain("canary");
    await expect(
      issueStore.issueApplyGrant(proposal, { now: issuedAt, signal }),
    ).resolves.toMatchObject({
      grantId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    });

    const consumeRoot = await approvalRoot();
    let revokeProposal = false;
    let revokeOnClock = false;
    const consumeStore = configured(consumeRoot, {
      now: () => {
        if (revokeOnClock) revokeProposal = true;
        return issuedAt + (revokeOnClock ? 1 : 0);
      },
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await consumeStore.initialize();
    const grant = await consumeStore.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    const consumeBoundaryError = new Phase3ApprovalError(
      "approval_commit_unknown",
      `${consumeRoot} consume proposal canary`,
    );
    const throwingProposal = Object.defineProperty(
      { ...proposal },
      "proposalId",
      {
        enumerable: true,
        get: () => {
          throw consumeBoundaryError;
        },
      },
    ) as Phase3ProposalSnapshot;
    const consumeFailure = await consumeStore
      .consumeApplyGrant(grant.grantId, throwingProposal, {
        now: issuedAt + 1,
        signal,
      })
      .catch((error: unknown) => error);
    expect(consumeFailure).toBeInstanceOf(Phase3ApprovalError);
    expect(consumeFailure).not.toBe(consumeBoundaryError);
    expect(consumeFailure).toMatchObject({
      code: "proposal_not_pending",
      message: "Approval requires an exact pending proposal",
    });
    expect(String(consumeFailure)).not.toContain(consumeRoot);
    expect(String(consumeFailure)).not.toContain("canary");

    const revocableProposal = new Proxy(proposal, {
      get: (target, property, receiver): unknown => {
        if (revokeProposal)
          throw new Phase3ApprovalError(
            "approval_commit_unknown",
            `${consumeRoot} late proposal canary`,
          );
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    revokeOnClock = true;
    await expect(
      consumeStore.consumeApplyGrant(grant.grantId, revocableProposal, {
        now: issuedAt + 1,
        signal,
      }),
    ).resolves.toEqual(grant);
  });

  it("zeros superseded sequential and concurrent initialize buffers and retained buffers on close", async () => {
    const sequentialRoot = await approvalRoot();
    const sequentialSeed = configured(sequentialRoot, {
      randomUUID: uuidSource([
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      ]),
    });
    await sequentialSeed.initialize();
    await sequentialSeed.issueApplyGrant(proposal, {
      now: issuedAt,
      signal,
    });
    await sequentialSeed.close();

    const generations: [Buffer[], Buffer[]] = [[], []];
    let generation: 0 | 1 = 0;
    const sequential = configured(sequentialRoot, {
      filesystem: {
        ...nativeFilesystem,
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          return await leasedHandle(
            handle,
            lease,
            trackedHandle(handle, {
              onRead: (bytes) => {
                if (path.endsWith("grant.json"))
                  generations[generation].push(bytes);
              },
            }),
          );
        },
      },
      randomUUID: uuidSource([]),
    });
    const sequentialTracking = trackBufferZeroing();
    try {
      await sequential.initialize();
      expect(generations[0]).toHaveLength(1);
      expect(generations[0].every(isZeroed)).toBe(true);
      generation = 1;
      await sequential.initialize();
      expect(generations[0].every(isZeroed)).toBe(true);
      expect(generations[1]).toHaveLength(1);
      expect(generations[1].every(isZeroed)).toBe(true);
      const beforeClose = sequentialTracking.events.filter((event) =>
        event.before.includes(Buffer.from('"grant":')),
      ).length;
      await sequential.close();
      const afterClose = sequentialTracking.events.filter((event) =>
        event.before.includes(Buffer.from('"grant":')),
      ).length;
      expect(afterClose).toBeGreaterThan(beforeClose);
      expect(generations[1].every(isZeroed)).toBe(true);
    } finally {
      sequentialTracking.restore();
    }

    const concurrentBuffers: Buffer[] = [];
    let arrivals = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolveGate) => {
      release = resolveGate;
    });
    const concurrent = configured(sequentialRoot, {
      filesystem: {
        ...nativeFilesystem,
        readdir: async (path) => {
          if (path === sequentialRoot && arrivals < 2) {
            arrivals += 1;
            if (arrivals === 2) release();
            await gate;
          }
          return await readdir(path);
        },
        open: async (path, flags, mode, lease) => {
          const handle = await open(path, flags, mode);
          return await leasedHandle(
            handle,
            lease,
            trackedHandle(handle, {
              onRead: (bytes) => {
                if (path.endsWith("grant.json")) concurrentBuffers.push(bytes);
              },
            }),
          );
        },
      },
      randomUUID: uuidSource([]),
    });
    await Promise.all([concurrent.initialize(), concurrent.initialize()]);
    expect(concurrentBuffers).toHaveLength(2);
    expect(concurrentBuffers.every(isZeroed)).toBe(true);
    await concurrent.close();
    expect(concurrentBuffers.every(isZeroed)).toBe(true);
  });

  it.runIf(process.platform === "win32")(
    "requires injected logical durability on Windows",
    async () => {
      const root = await approvalRoot();
      const store = new DurablePhase3ApprovalGrants(root, key, {
        randomUUID: uuidSource(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
      });
      await expect(store.initialize()).rejects.toMatchObject({
        code: "approval_store_unhealthy",
      });
    },
  );
});

async function approvalRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "phase3-approval-"));
  await chmod(root, 0o700);
  roots.push(root);
  return root;
}

function durable(
  root: string,
  secret: Uint8Array,
  now: number | (() => number),
  uuid: () => string,
): DurablePhase3ApprovalGrants {
  return new DurablePhase3ApprovalGrants(root, secret, {
    durability: logicalDurability,
    now: typeof now === "number" ? () => now : now,
    randomUUID: uuid,
  });
}

function configured(
  root: string,
  options: DurablePhase3ApprovalOptions,
): DurablePhase3ApprovalGrants {
  return new DurablePhase3ApprovalGrants(root, key, {
    durability: logicalDurability,
    now: () => issuedAt,
    ...options,
  });
}

function ioFailure(message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code: "EIO" });
}

async function leasedHandle(
  handle: Awaited<ReturnType<typeof open>>,
  lease: Phase3ApprovalOpenLease,
  exposed: Phase3ApprovalFileHandle = handle,
  closeFailure?: unknown,
): Promise<Phase3ApprovalFileHandle> {
  const close = handle.close.bind(handle);
  try {
    lease.register(async () => {
      await close();
      if (closeFailure !== undefined) throw closeFailure;
    });
    return exposed;
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
}

function failingHandle(
  handle: Awaited<ReturnType<typeof open>>,
  failure: "write" | "sync",
): Phase3ApprovalFileHandle {
  return {
    write: async (buffer, offset, length, position) => {
      if (failure === "write") throw ioFailure("write path canary");
      return await handle.write(buffer, offset, length, position);
    },
    sync: async () => {
      if (failure === "sync") throw ioFailure("sync path canary");
      await handle.sync();
    },
    stat: async (options) => await handle.stat(options),
    readFile: async () => await handle.readFile(),
  };
}

function trackedHandle(
  handle: Awaited<ReturnType<typeof open>>,
  options: Readonly<{
    reads?: Buffer[];
    writes?: Uint8Array[];
    onRead?: (bytes: Buffer) => void;
  }>,
): Phase3ApprovalFileHandle {
  return {
    write: async (buffer, offset, length, position) => {
      options.writes?.push(buffer);
      return await handle.write(buffer, offset, length, position);
    },
    sync: async () => await handle.sync(),
    stat: async (statOptions) => await handle.stat(statOptions),
    readFile: async () => {
      const bytes = await handle.readFile();
      options.reads?.push(bytes);
      options.onRead?.(bytes);
      return bytes;
    },
  };
}

function proxyBuffer(source: Buffer, clearFailure?: unknown): Buffer {
  return new Proxy(source, {
    get: (target, property) => {
      if (property === "then") return undefined;
      const result = Reflect.get(target, property, target) as unknown;
      return bindUnknownMethod(result, target);
    },
    set: (target, property, value, receiver) => {
      if (clearFailure !== undefined && property === "0") throw clearFailure;
      return Reflect.set(target, property, value, receiver);
    },
  });
}

function bindUnknownMethod(value: unknown, receiver: object): unknown {
  if (typeof value !== "function") return value;
  const method = value as (...args: unknown[]) => unknown;
  return (...args: unknown[]) => Reflect.apply(method, receiver, args);
}

interface BufferZeroEvent {
  readonly buffer: Buffer;
  readonly before: Buffer;
}

function trackBufferAllocations(): {
  readonly buffers: Buffer[];
  readonly restore: () => void;
} {
  const descriptor = Object.getOwnPropertyDescriptor(Buffer, "alloc");
  if (!descriptor || typeof descriptor.value !== "function")
    throw new Error("Buffer.alloc descriptor is unavailable");
  const original = descriptor.value as (...args: unknown[]) => Buffer;
  const buffers: Buffer[] = [];
  const trackingAlloc = (...args: unknown[]): Buffer => {
    const buffer = Reflect.apply(original, Buffer, args);
    buffers.push(buffer);
    return buffer;
  };
  Object.defineProperty(Buffer, "alloc", {
    ...descriptor,
    value: trackingAlloc,
  });
  return {
    buffers,
    restore: () => {
      Object.defineProperty(Buffer, "alloc", descriptor);
    },
  };
}

function trackBufferZeroing(): {
  readonly events: BufferZeroEvent[];
  readonly restore: () => void;
} {
  const descriptor = Object.getOwnPropertyDescriptor(Buffer.prototype, "fill");
  if (!descriptor || typeof descriptor.value !== "function")
    throw new Error("Buffer.fill descriptor is unavailable");
  const original = descriptor.value as (...args: unknown[]) => Buffer;
  const events: BufferZeroEvent[] = [];
  const trackingFill = function (this: Buffer, ...args: unknown[]): Buffer {
    const before = args[0] === 0 ? Buffer.from(this) : undefined;
    const result = Reflect.apply(original, this, args);
    if (before) events.push({ buffer: this, before });
    return result;
  };
  Object.defineProperty(Buffer.prototype, "fill", {
    ...descriptor,
    value: trackingFill,
  });
  return {
    events,
    restore: () => {
      Object.defineProperty(Buffer.prototype, "fill", descriptor);
    },
  };
}

function isZeroed(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

async function expectSanitizedFailure(
  operation: Promise<unknown>,
  code: string,
  root: string,
): Promise<void> {
  const error = await operation.catch((caught: unknown) => caught);
  expect(error).toMatchObject({ code });
  expect(String(error)).not.toContain(root);
  expect(String(error)).not.toContain("canary");
}

function uuidSource(values: readonly string[]): () => string {
  const pending = [...values];
  return () => {
    const value = pending.shift();
    if (!value) throw new Error("UUID source exhausted");
    return value;
  };
}

function hmac(keyBytes: Uint8Array, domain: string, core: unknown): string {
  return createHmac("sha256", keyBytes)
    .update(Buffer.from(domain, "ascii"))
    .update(Buffer.from(canonicalJson(core), "utf8"))
    .digest("hex");
}
