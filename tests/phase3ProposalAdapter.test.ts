import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import {
  ProtectedProposalStore,
  storageEnvelope,
  type StoredProposal,
} from "../src/proposals/storage.js";
import { ProtectedPhase3ProposalAdapter } from "../src/phase3/proposalAdapter.js";
import { ProposalService } from "../src/proposals/proposalService.js";
import { Phase2AuditAdapter } from "../src/proposals/phase2Audit.js";
import { ProposalCursorCodec } from "../src/proposals/cursor.js";
import type { ProtectedIdentityRegistry } from "../src/security/repositoryBoundary.js";
import {
  GuardedPhase3PolicyPort,
  InMemoryPhase3Journal,
  Phase3ApplyCoordinator,
} from "../src/phase3/applyCoordinator.js";
import { InjectedApprovalGrantPort } from "../src/phase3/approval.js";
import { Phase3ResourceLocks } from "../src/phase3/resourceLocks.js";
import { StrictYamlPhase3Validation } from "../src/phase3/validationAdapter.js";
import { NarrowPhase3ReloadAdapter } from "../src/phase3/reloadAdapter.js";

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
      const { adapter, value } = await fixture(
        stored({ state, reloadImpact: "none" }),
      );
      await expect(adapter.load(proposalId)).resolves.toEqual({
        proposalId,
        proposalStorageSha256: value.storageSha256,
        state,
        path: "configuration.yaml",
        expectedSha256,
        candidateSha256: digest(candidate),
        diffSha256: digest(diff),
        risk: "high",
        impact: "none",
        reloadTarget: null,
        expiresAt: "2026-07-21T00:00:00.000Z",
      });
    },
  );

  it.each(["none", "restart_required"] as const)(
    "maps the exact %s impact to a null reload target",
    async (reloadImpact) => {
      const { adapter } = await fixture(stored({ reloadImpact }));
      await expect(adapter.load(proposalId)).resolves.toMatchObject({
        impact: reloadImpact,
        reloadTarget: null,
      });
    },
  );

  it("rejects current domain_reload proposals without an explicit stored target", async () => {
    const { adapter } = await fixture(
      stored({ reloadImpact: "domain_reload" }),
    );
    await expect(adapter.load(proposalId)).rejects.toMatchObject({
      code: "proposal_identity_mismatch",
    });
  });

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
    ["empty automation list", "[]\n"],
    [
      "ordinary automation list",
      "- id: example\n  triggers: []\n  actions: []\n",
    ],
  ])("classifies a %s candidate", async (_name, proposedContent) => {
    const fixture = await producerFixture();
    const created = await fixture.service.propose(
      { ...fixture.input, proposedContent },
      context(),
    );
    expect(created).toMatchObject({
      reloadImpact: "domain_reload",
      reloadTarget: "automation.reload",
    });
  });

  it("requires catalog revalidation before reload when another include transitively shares the automation file", async () => {
    const fixture = await producerFixture(
      "automation: !include automations.yaml\nscene: !include scenes.yaml\n",
      { "scenes.yaml": "!include automations.yaml\n" },
    );
    const created = await fixture.service.propose(fixture.input, context());
    const snapshot = await new ProtectedPhase3ProposalAdapter(
      fixture.store,
    ).load(created.proposalId);
    expect(snapshot.reloadTarget).toBe("automation.reload");
    const reload = vi.fn(async () =>
      Object.freeze({ status: "completed" as const }),
    );
    const resolve = vi.fn(async () =>
      Object.freeze({ status: "unavailable" as const }),
    );
    const adapter = new NarrowPhase3ReloadAdapter({ resolve }, { reload });
    await expect(
      adapter.reloadDomain(
        { path: snapshot.path, target: "automation.reload" },
        context(),
      ),
    ).rejects.toMatchObject({ code: "reload_unavailable" });
    expect(resolve).toHaveBeenCalledWith("automations.yaml", expect.anything());
    expect(reload).not.toHaveBeenCalled();
    // Catalog is a test double: actual include-graph rejection is still a live adapter gate.
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

describe("real automation proposal producer to Phase 3", () => {
  it("persists a repository-derived target and applies through the actual adapter and policy", async () => {
    const fixture = await producerFixture(
      "automation: !include automations.yaml\nscript: !include scripts.yaml\nscene: !include scenes.yaml\n",
    );
    const created = await fixture.service.propose(fixture.input, context());
    expect(created).toMatchObject({
      reloadImpact: "domain_reload",
      reloadTarget: "automation.reload",
    });
    const adapter = new ProtectedPhase3ProposalAdapter(fixture.store);
    const snapshot = await adapter.load(created.proposalId);
    expect(snapshot).toMatchObject({
      impact: "domain_reload",
      reloadTarget: "automation.reload",
    });
    await expect(
      new GuardedPhase3PolicyPort().evaluate(snapshot),
    ).resolves.toMatchObject({ allowed: false, code: "writes_disabled" });
    let live = Buffer.from(fixture.source);
    const calls: string[] = [];
    const now = Date.now();
    const grantId = randomUUID();
    const coordinator = new Phase3ApplyCoordinator({
      proposals: adapter,
      policy: new GuardedPhase3PolicyPort({
        writesEnabled: true,
        applyCapability: true,
        domainReloadCapability: true,
      }),
      locks: new Phase3ResourceLocks(),
      approvals: new InjectedApprovalGrantPort([
        {
          grantId,
          proposalId: snapshot.proposalId,
          proposalStorageSha256: snapshot.proposalStorageSha256,
          candidateSha256: snapshot.candidateSha256,
          diffSha256: snapshot.diffSha256,
          operation: "apply",
          risk: snapshot.risk,
          impact: snapshot.impact,
          reloadTarget: snapshot.reloadTarget,
          issuedAt: new Date(now).toISOString(),
          expiresAt: new Date(now + 60_000).toISOString(),
        },
      ]),
      source: {
        async read() {
          return { bytes: Uint8Array.from(live), sha256: digest(live) };
        },
        async readDigest() {
          return digest(live);
        },
      },
      validation: new StrictYamlPhase3Validation(),
      checkpoints: {
        async create() {
          return {
            checkpointId: randomUUID(),
            checkpointSha256: digest(fixture.source),
          };
        },
        async load() {
          return Uint8Array.from(fixture.source);
        },
      },
      atomicApply: {
        async replace(input) {
          live = Buffer.from(input.content);
          return { status: "committed" };
        },
      },
      reload: new NarrowPhase3ReloadAdapter(
        {
          async resolve(path) {
            calls.push(`resolve:${path}`);
            return Object.freeze({
              status: "resolved",
              target: "automation.reload",
            });
          },
        },
        {
          async reload(target) {
            calls.push(target);
            return Object.freeze({ status: "completed" });
          },
        },
      ),
      verification: {
        async verify() {
          calls.push("verify");
        },
      },
      journal: new InMemoryPhase3Journal(),
    });
    const result = await coordinator.apply(
      { proposalId: snapshot.proposalId, grantId },
      context(),
    );
    expect(result.state).toBe("verification_succeeded");
    expect(result.reloadTarget).toBe("automation.reload");
    expect(live.toString("utf8")).toBe(fixture.input.proposedContent);
    expect(calls).toEqual([
      "resolve:automations.yaml",
      "automation.reload",
      "verify",
    ]);
    expect(fixture.source.toString("utf8")).toContain("Old");
    expect(await fixture.service.propose(fixture.input, context())).toEqual(
      created,
    );
  });

  it.each([
    ["unreferenced file", "default_config:\n"],
    ["different included file", "automation: !include other.yaml\n"],
    ["directory include", "automation: !include_dir_merge_list automations\n"],
    [
      "named automation",
      "automation: !include automations.yaml\nautomation extra: []\n",
    ],
    [
      "packages",
      "automation: !include automations.yaml\nhomeassistant:\n  packages: {}\n",
    ],
    [
      "shared include",
      "automation: !include automations.yaml\nscene: !include automations.yaml\n",
    ],
    [
      "normalized shared include",
      "automation: !include automations.yaml\nscene: !include ./automations.yaml\n",
    ],
    [
      "root directory shared include",
      "automation: !include automations.yaml\nscene: !include_dir_merge_list .\n",
    ],
  ])("retains restart_required for %s", async (_name, configuration) => {
    const fixture = await producerFixture(configuration);
    const created = await fixture.service.propose(fixture.input, context());
    expect(created.reloadImpact).toBe("restart_required");
    expect(created).not.toHaveProperty("reloadTarget");
  });

  it.each([
    "value: mapping\n",
    "- scalar\n",
    "- action: !include actions.yaml\n",
    "- action: !input actions\n",
    "- action: !secret action\n",
    "- &item {id: example}\n",
    "- id: example\n  action: &action []\n  trigger: *action\n",
  ])(
    "retains restart_required for unsupported automation structure %s",
    async (proposedContent) => {
      const fixture = await producerFixture();
      const created = await fixture.service.propose(
        { ...fixture.input, proposedContent },
        context(),
      );
      expect(created.reloadImpact).toBe("restart_required");
    },
  );

  it.each(["bytes", "identity", "root", "size"] as const)(
    "rejects %s drift on the second configuration read without storing a proposal",
    async (drift) => {
      const fixture = await producerFixture();
      let configurationReads = 0;
      const original = fixture.readContent.getMockImplementation()!;
      fixture.readContent.mockImplementation(async (path, operation) => {
        const result = await original(path, operation);
        if (path !== "configuration.yaml" || ++configurationReads !== 2)
          return result;
        return {
          ...result,
          ...(drift === "bytes"
            ? { bytes: Buffer.from("automation: !include automations.yml\n") }
            : {}),
          ...(drift === "size"
            ? { bytes: Buffer.from("automation: []\n") }
            : {}),
          ...(drift === "identity"
            ? { identity: { ...result.identity, inode: "999" } }
            : {}),
          ...(drift === "root"
            ? { rootIdentity: { ...result.rootIdentity, inode: "999" } }
            : {}),
        };
      });
      await expect(
        fixture.service.propose(fixture.input, context()),
      ).rejects.toMatchObject({ code: "stale_source" });
      expect(await fixture.store.readAll()).toEqual([]);
    },
  );
});

async function producerFixture(
  configuration = "automation: !include automations.yaml\n",
  extraFiles: Readonly<Record<string, string>> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "phase3-producer-"));
  roots.push(root);
  const source = Buffer.from(
    "- id: example\n  alias: Old\n  triggers: []\n  actions: []\n",
  );
  const files = new Map([
    ["configuration.yaml", Buffer.from(configuration)],
    ["automations.yaml", source],
  ]);
  for (const [path, content] of Object.entries(extraFiles))
    files.set(path, Buffer.from(content));
  const rootIdentity = { device: "1", inode: "1" };
  const catalog = {
    rootIdentity,
    directories: [],
    files: [...files.entries()].map(([path, bytes], index) => ({
      path,
      identity: { device: "1", inode: String(index + 2) },
      size: bytes.byteLength,
      mtimeNanoseconds: "1",
      ctimeNanoseconds: "1",
    })),
  };
  const readContent = vi.fn<ProtectedIdentityRegistry["readContent"]>(
    async (path) => ({
      path,
      rootIdentity,
      identity: catalog.files.find((file) => file.path === path)!.identity,
      bytes: Uint8Array.from(files.get(path)!),
    }),
  );
  const registry = {
    async assertFresh() {},
    readContent,
    redactWholeText(text: string) {
      return text;
    },
  } as unknown as ProtectedIdentityRegistry;
  const store = new ProtectedProposalStore(
    join(root, "store"),
    logicalDurability,
  );
  const service = new ProposalService(
    store,
    new Phase2AuditAdapter(
      join(root, "audit", "phase2.jsonl"),
      {},
      logicalDurability,
    ),
    registry,
    {
      async catalog() {
        return catalog;
      },
    },
    new ProposalCursorCodec(Buffer.alloc(32, 7), Buffer.alloc(32, 8)),
  );
  await service.initialize();
  return {
    service,
    store,
    source,
    readContent,
    input: {
      idempotencyKey: randomUUID(),
      path: "automations.yaml",
      expectedSha256: digest(source),
      proposedContent: source.toString("utf8").replace("Old", "New"),
    },
  };
}

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
      reloadImpact: options.reloadImpact ?? "none",
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
