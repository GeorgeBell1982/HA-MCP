import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import {
  ProtectedProposalStore,
  storageEnvelope,
  type StoredProposal,
} from "../src/proposals/storage.js";
import { ProtectedPhase3ProposalAdapter } from "../src/phase3/proposalAdapter.js";

const roots: string[] = [];
const proposalId = "11111111-1111-4111-8111-111111111111";
const otherProposalId = "22222222-2222-4222-8222-222222222222";
const idempotencyKey = "33333333-3333-4333-8333-333333333333";
const candidate = Buffer.from("value: new\n");
const diff = Buffer.from(
  "--- a/configuration.yaml\n+++ b/configuration.yaml\n",
);
const expectedSha256 = digest("value: old\n");

const logicalDurability = Object.freeze({
  privateMode: (_mode: bigint) => true,
  syncDirectory: async (_path: string) => undefined,
}) satisfies Phase2DurabilityPort;

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true })),
  );
});

describe("Phase 3B protected proposal adapter", () => {
  it.each(["pending", "discarded", "expired"] as const)(
    "maps an exact %s Phase 2 proposal without changing state",
    async (state) => {
      const { adapter, value } = await fixture(stored({ state }));
      await expect(adapter.load(proposalId)).resolves.toEqual({
        proposalId,
        proposalStorageSha256: value.storageSha256,
        state,
        path: "configuration.yaml",
        expectedSha256,
        candidateSha256: digest(candidate),
        diffSha256: digest(diff),
        risk: "high",
        impact: "domain_reload",
        expiresAt: "2026-07-21T00:00:00.000Z",
      });
    },
  );

  it.each(["none", "domain_reload", "restart_required"] as const)(
    "maps the exact %s impact",
    async (reloadImpact) => {
      const { adapter } = await fixture(stored({ reloadImpact }));
      await expect(adapter.load(proposalId)).resolves.toMatchObject({
        impact: reloadImpact,
      });
    },
  );

  it("returns independent candidate buffers and validates the protected diff", async () => {
    const { adapter } = await fixture(stored());
    const first = await adapter.loadCandidate(proposalId);
    const second = await adapter.loadCandidate(proposalId);
    expect(Array.from(first)).toEqual(Array.from(candidate));
    expect(Array.from(second)).toEqual(Array.from(candidate));
    expect(first).not.toBe(second);
    first.fill(0);
    expect(Array.from(second)).toEqual(Array.from(candidate));
  });

  it.each([
    ["protected proposal id", stored({ protectedProposalId: otherProposalId })],
    ["idempotency key", stored({ protectedIdempotencyKey: randomUUID() })],
    ["candidate digest", stored({ publicCandidateSha256: digest("other") })],
    ["diff digest", stored({ publicDiffSha256: digest("other") })],
  ])("rejects cross-boundary %s drift", async (_case, value) => {
    const { adapter } = await fixture(value);
    await expect(adapter.loadCandidate(proposalId)).rejects.toMatchObject({
      code: "proposal_identity_mismatch",
    });
  });

  it.each([
    [
      "noncanonical candidate base64",
      stored({ candidateBase64: "dmFsdWU6IG5ldwo" }),
    ],
    [
      "invalid candidate UTF-8",
      stored({
        candidateBase64: Buffer.from([0xff]).toString("base64"),
        protectedCandidateSha256: digest(Buffer.from([0xff])),
        publicCandidateSha256: digest(Buffer.from([0xff])),
      }),
    ],
    ["noncanonical diff base64", stored({ diffBase64: "ZGlmZgo" })],
    [
      "invalid diff UTF-8",
      stored({
        diffBase64: Buffer.from([0xff]).toString("base64"),
        protectedDiffSha256: digest(Buffer.from([0xff])),
        publicDiffSha256: digest(Buffer.from([0xff])),
      }),
    ],
  ])("fails closed for %s", async (_case, value) => {
    const { adapter } = await fixture(value);
    await expect(adapter.loadCandidate(proposalId)).rejects.toMatchObject({
      code: "proposal_unavailable",
    });
  });

  it("fails closed for storage-envelope tampering and missing proposals", async () => {
    const invalid = { ...stored(), storageSha256: "f".repeat(64) };
    const { adapter } = await fixture(invalid);
    await expect(adapter.load(proposalId)).rejects.toMatchObject({
      code: "proposal_unavailable",
    });
    await expect(adapter.load(otherProposalId)).rejects.toMatchObject({
      code: "proposal_unavailable",
    });
  });

  it("reads exact files without scanning or mutating protected storage", async () => {
    const { store } = await fixture(stored());
    const path = join(store.proposalsPath, proposalId + ".json");
    await writeFile(path, "{invalid", { mode: 0o600 });
    const beforeNames = await readdir(store.proposalsPath);
    const beforeBytes = await readFile(path);
    await expect(store.readExact(proposalId)).rejects.toThrow();
    expect(await readdir(store.proposalsPath)).toEqual(beforeNames);
    expect(await readFile(path)).toEqual(beforeBytes);
    expect(await readdir(store.quarantinePath)).toEqual([]);
  });

  it("rejects noncanonical identifiers before constructing a path", async () => {
    const { store } = await fixture(stored());
    await expect(store.readExact("../configuration")).rejects.toThrow(
      "identifier is invalid",
    );
    await expect(
      store.readExact("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ).rejects.toThrow("identifier is invalid");
  });
});

async function fixture(value: StoredProposal) {
  const root = await mkdtemp(join(tmpdir(), "phase3-proposal-"));
  roots.push(root);
  const store = new ProtectedProposalStore(root, logicalDurability);
  await store.initialize();
  await store.create(value, context());
  return {
    store,
    adapter: new ProtectedPhase3ProposalAdapter(store),
    value,
  };
}

function stored(
  options: Readonly<{
    state?: "pending" | "discarded" | "expired";
    reloadImpact?: "none" | "domain_reload" | "restart_required";
    protectedProposalId?: string;
    protectedIdempotencyKey?: string;
    candidateBase64?: string;
    diffBase64?: string;
    publicCandidateSha256?: string;
    protectedCandidateSha256?: string;
    publicDiffSha256?: string;
    protectedDiffSha256?: string;
  }> = {},
): StoredProposal {
  const candidateBase64 =
    options.candidateBase64 ?? candidate.toString("base64");
  const candidateBytes = Buffer.from(candidateBase64, "base64");
  const protectedCandidateSha256 =
    options.protectedCandidateSha256 ?? digest(candidateBytes);
  const diffBase64 = options.diffBase64 ?? diff.toString("base64");
  const protectedDiffSha256 =
    options.protectedDiffSha256 ?? digest(Buffer.from(diffBase64, "base64"));
  return storageEnvelope(
    {
      proposalId,
      idempotencyKey,
      state: options.state ?? "pending",
      path: "configuration.yaml",
      expectedSha256,
      candidateSha256:
        options.publicCandidateSha256 ?? protectedCandidateSha256,
      diffSha256: options.publicDiffSha256 ?? protectedDiffSha256,
      redactedDiff: "safe",
      createdAt: "2026-07-20T00:00:00.000Z",
      expiresAt: "2026-07-21T00:00:00.000Z",
      risk: "high",
      validationPlan: ["validate"],
      reloadImpact: options.reloadImpact ?? "domain_reload",
      sourceEvidence:
        "Protected /data proposal store and /homeassistant repository snapshot",
    },
    {
      schemaVersion: 1,
      proposalId: options.protectedProposalId ?? proposalId,
      idempotencyKey: options.protectedIdempotencyKey ?? idempotencyKey,
      candidateSha256: protectedCandidateSha256,
      diffSha256: protectedDiffSha256,
      encoding: "utf-8",
      exactCandidateBytesBase64: candidateBase64,
      exactDiffBytesBase64: diffBase64,
    },
  );
}

function context(): Phase2OperationContext {
  return {
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt: Date.now() + 60_000,
    signal: new AbortController().signal,
  };
}

function digest(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}
