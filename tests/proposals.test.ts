import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  link,
  mkdir,
  open,
  readFile,
  readdir,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import type { RepositoryCatalogProvider } from "../src/repository/repositoryReads.js";
import {
  RepositoryBoundaryError,
  assertOperationActive,
  type ProtectedIdentityRegistry,
} from "../src/security/repositoryBoundary.js";
import {
  ProposalCursorCodec,
  ProposalCursorError,
  proposalSnapshot,
} from "../src/proposals/cursor.js";
import {
  PHASE2_AUDIT_LIMITS,
  Phase2AuditAdapter,
  type Phase2AuditHooks,
} from "../src/proposals/phase2Audit.js";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import {
  ProposalService,
  ProposalServiceError,
  type ProposalServiceHooks,
} from "../src/proposals/proposalService.js";
import {
  PROPOSAL_STORE_LIMITS,
  ProtectedProposalStore,
  ProtectedWriteError,
  atomicProtectedWrite,
  canonicalJson,
  journalEnvelope,
  storageEnvelope,
  type ProposalJournal,
  type StoredProposal,
} from "../src/proposals/storage.js";
import { mkdtemp } from "node:fs/promises";

const SOURCE = Buffer.from("value: old\n");
const CANDIDATE = "value: new\n";
const PATH = "configuration.yaml";
const IDENTITY = Object.freeze({ device: "1", inode: "2" });
const ROOT_IDENTITY = Object.freeze({ device: "1", inode: "1" });

function context(
  overrides: Partial<Phase2OperationContext> = {},
): Phase2OperationContext {
  return {
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt: Date.now() + 60_000,
    signal: new AbortController().signal,
    ...overrides,
  };
}

function attempt(operationId: string = randomUUID()) {
  return {
    schemaVersion: 2,
    timestamp: new Date(0).toISOString(),
    requestId: randomUUID(),
    operationId,
    phase: "attempt",
    tool: "ha_list_proposals",
    risk: "read-only",
    target: { kind: "proposal-store" },
  } as const;
}

function outcome(base: ReturnType<typeof attempt>) {
  return {
    schemaVersion: 2,
    timestamp: new Date(1).toISOString(),
    requestId: base.requestId,
    operationId: base.operationId,
    phase: "outcome",
    tool: "ha_list_proposals",
    result: "success",
  } as const;
}
function jsonRecord(line: string): Record<string, unknown> {
  const value: unknown = JSON.parse(line);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("Expected an audit object");
  return value as Record<string, unknown>;
}

async function auditFixture() {
  const root = await mkdtemp(join(tmpdir(), "phase2-audit-"));
  const path = join(root, "private", "phase2.jsonl");
  const audit = new Phase2AuditAdapter(path, {}, logicalDurability);
  await audit.recover();
  return { audit, path, root };
}

function auditOperationId(index: number): string {
  return "00000000-0000-4000-8000-" + index.toString(16).padStart(12, "0");
}

function proposalAuditAttempt(operationId = randomUUID()) {
  return {
    schemaVersion: 2,
    timestamp: new Date(0).toISOString(),
    requestId: randomUUID(),
    operationId,
    phase: "attempt",
    tool: "ha_propose_config_change",
    risk: "proposal-metadata",
    target: {
      kind: "proposal-create",
      idempotencyKey: randomUUID(),
      path: PATH,
      expectedSha256: "a".repeat(64),
      candidateSha256: "b".repeat(64),
    },
  } as const;
}

function fullAuditFile(): string {
  const lines: string[] = [];
  let bytes = 0;
  for (let index = 0; ; index += 1) {
    const line =
      canonicalJson(attempt(auditOperationId(index))) + String.fromCharCode(10);
    const nextBytes = Buffer.byteLength(line, "utf8");
    if (bytes + nextBytes > PHASE2_AUDIT_LIMITS.fileBytes) break;
    lines.push(line);
    bytes += nextBytes;
  }
  return lines.join("");
}

function stored(id: string = randomUUID(), key: string = randomUUID()) {
  const candidate = Buffer.from(CANDIDATE);
  const diff = Buffer.from(
    "--- a/configuration.yaml\n+++ b/configuration.yaml\n",
  );
  const candidateSha256 = createHash("sha256").update(candidate).digest("hex");
  const diffSha256 = createHash("sha256").update(diff).digest("hex");
  return storageEnvelope(
    {
      proposalId: id,
      idempotencyKey: key,
      state: "pending",
      path: PATH,
      expectedSha256: createHash("sha256").update(SOURCE).digest("hex"),
      candidateSha256,
      diffSha256,
      redactedDiff: "safe",
      createdAt: new Date(0).toISOString(),
      expiresAt: new Date(86_400_000).toISOString(),
      risk: "high",
      validationPlan: ["validate"],
      reloadImpact: "restart_required",
      sourceEvidence:
        "Protected /data proposal store and /homeassistant repository snapshot",
    },
    {
      schemaVersion: 1,
      proposalId: id,
      idempotencyKey: key,
      candidateSha256,
      diffSha256,
      encoding: "utf-8",
      exactCandidateBytesBase64: candidate.toString("base64"),
      exactDiffBytesBase64: diff.toString("base64"),
    },
  );
}

type FileHandleWrite = (
  this: unknown,
  buffer: Uint8Array,
  offset?: number,
  length?: number,
  position?: number | null,
) => Promise<{ bytesWritten: number; buffer: Uint8Array }>;

async function withFileHandleWriteSpy<T>(
  directory: string,
  implementation: (originalWrite: FileHandleWrite) => FileHandleWrite,
  action: (callCount: () => number) => Promise<T>,
): Promise<T> {
  const probe = await open(join(directory, "probe"), "w");
  const writePrototype = Object.getPrototypeOf(probe) as {
    write: FileHandleWrite;
  };
  await probe.close();
  const originalWrite = writePrototype.write;
  const spy = vi
    .spyOn(writePrototype, "write")
    .mockImplementation(implementation(originalWrite));
  try {
    return await action(() => spy.mock.calls.length);
  } finally {
    spy.mockRestore();
  }
}
const logicalDurability = Object.freeze({
  privateMode: (_mode: bigint) => true,
  syncDirectory: async (_path: string) => undefined,
}) satisfies Phase2DurabilityPort;

async function expectStoreLatched(
  store: ProtectedProposalStore,
): Promise<void> {
  expect(() => store.assertHealthy()).toThrow("unhealthy");
  await expect(store.readAll()).rejects.toThrow("unhealthy");
}

interface MemoryStoreState {
  proposals: StoredProposal[];
  journals: ProposalJournal[];
  unhealthy: boolean;
  chain: Promise<void>;
}

const memoryStoreStates = new Map<string, MemoryStoreState>();

class MemoryProposalStore {
  private readonly state: MemoryStoreState;

  constructor(key: string) {
    const existing = memoryStoreStates.get(key);
    this.state = existing ?? {
      proposals: [],
      journals: [],
      unhealthy: false,
      chain: Promise.resolve(),
    };
    memoryStoreStates.set(key, this.state);
  }

  async initialize(): Promise<void> {
    this.assertHealthy();
  }

  serialized<T>(task: () => Promise<T>): Promise<T> {
    this.assertHealthy();
    const result = this.state.chain.then(task, task);
    this.state.chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async readAll(): Promise<StoredProposal[]> {
    this.assertHealthy();
    return [...this.state.proposals];
  }

  async create(
    value: StoredProposal,
    operation?: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    if (operation) assertOperationActive(operation);
    if (
      this.state.proposals.some(
        (item) => item.public.proposalId === value.public.proposalId,
      )
    )
      throw new Error("duplicate proposal");
    this.state.proposals.push(value);
  }

  async replace(
    value: StoredProposal,
    previous: StoredProposal,
    operation?: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    if (operation) assertOperationActive(operation);
    const index = this.state.proposals.findIndex(
      (item) => item.storageSha256 === previous.storageSha256,
    );
    if (index < 0) throw new Error("proposal replacement mismatch");
    this.state.proposals[index] = value;
  }

  async readJournals(): Promise<ProposalJournal[]> {
    this.assertHealthy();
    return [...this.state.journals];
  }

  async createJournal(
    value: ProposalJournal,
    operation?: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    this.state.journals.push(value);
    if (operation) assertOperationActive(operation);
  }

  async replaceJournal(
    value: ProposalJournal,
    previous: ProposalJournal,
  ): Promise<void> {
    this.assertHealthy();
    const index = this.state.journals.findIndex(
      (item) => item.journalSha256 === previous.journalSha256,
    );
    if (index < 0) throw new Error("journal replacement mismatch");
    this.state.journals[index] = value;
  }

  async removeJournal(value: ProposalJournal): Promise<void> {
    this.assertHealthy();
    const index = this.state.journals.findIndex(
      (item) => item.journalSha256 === value.journalSha256,
    );
    if (index < 0) throw new Error("journal removal mismatch");
    this.state.journals.splice(index, 1);
  }

  markUnhealthy(): void {
    this.state.unhealthy = true;
  }

  assertHealthy(): void {
    if (this.state.unhealthy) throw new Error("memory store unhealthy");
  }
}

async function serviceFixture(
  root: string,
  auditPath: string,
  hooks: ProposalServiceHooks = {},
  auditHooks: Phase2AuditHooks = {},
  cursorKey: Uint8Array = randomBytes(32),
  cursorSessionNonce: Uint8Array = Buffer.alloc(32, 7),
) {
  const store = new MemoryProposalStore(root);
  const audit = new Phase2AuditAdapter(
    auditPath,
    auditHooks,
    logicalDurability,
  );
  const registryReadContent = vi.fn<ProtectedIdentityRegistry["readContent"]>(
    async () =>
      Object.freeze({
        path: PATH,
        rootIdentity: ROOT_IDENTITY,
        identity: IDENTITY,
        bytes: Uint8Array.from(SOURCE),
      }),
  );
  const registry = {
    assertFresh: vi.fn(async () => undefined),
    readContent: registryReadContent,
    redactWholeText: vi.fn((text: string) =>
      text.replace(/secret-value/gu, "[REDACTED]"),
    ),
  } as unknown as ProtectedIdentityRegistry;
  const catalog = {
    catalog: vi.fn<RepositoryCatalogProvider["catalog"]>(async () =>
      Object.freeze({
        rootIdentity: ROOT_IDENTITY,
        directories: Object.freeze([]),
        files: Object.freeze([
          Object.freeze({
            path: PATH,
            identity: IDENTITY,
            size: SOURCE.byteLength,
            mtimeNanoseconds: "1",
            ctimeNanoseconds: "1",
          }),
        ]),
      }),
    ),
  } satisfies RepositoryCatalogProvider;
  const cursors = new ProposalCursorCodec(cursorKey, cursorSessionNonce);
  const service = new ProposalService(
    store as unknown as ProtectedProposalStore,
    audit,
    registry,
    catalog,
    cursors,
    hooks,
  );
  await service.initialize();
  return {
    service,
    store,
    audit,
    registry,
    registryReadContent,
    catalog,
    cursors,
  };
}

function proposalInput(idempotencyKey = randomUUID()) {
  return {
    idempotencyKey,
    path: PATH,
    expectedSha256: createHash("sha256").update(SOURCE).digest("hex"),
    proposedContent: CANDIDATE,
  };
}

describe("G1 authenticated proposal cursors", () => {
  it("binds operation/key/session and fails after close", () => {
    const snapshot = Buffer.alloc(32, 3);
    const key = Buffer.alloc(32, 1);
    const codec = new ProposalCursorCodec(key, Buffer.alloc(32, 2));
    const value = codec.encode(1, 4, 5, snapshot);
    expect(codec.decode(value, 1)).toMatchObject({ generation: 4, offset: 5 });
    expect(() => codec.decode(value, 2)).toThrow(ProposalCursorError);
    expect(() =>
      new ProposalCursorCodec(key, Buffer.alloc(32, 9)).decode(value, 1),
    ).toThrow(ProposalCursorError);
    codec.close();
    expect(() => codec.decode(value, 1)).toThrow("session is closed");
    expect(() => codec.encode(1, 0, 0, snapshot)).toThrow("session is closed");
  });
});

describe("G1 Phase 2 durable audit", () => {
  it("persists canonical attempt then outcome and recovers them", async () => {
    const { audit, path } = await auditFixture();
    const first = attempt();
    await audit.append(first);
    await audit.append(outcome(first));
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    expect(lines.map((line) => jsonRecord(line).phase)).toEqual([
      "attempt",
      "outcome",
    ]);
    expect(lines[0]).toBe(canonicalJson(first));
    const recovered = new Phase2AuditAdapter(path, {}, logicalDurability);
    await recovered.recover();
    expect(recovered.hasOutcome(first.operationId)).toBe(true);
  });

  it("recovers more than 1,280 retained canonical attempt/outcome records without an artificial cap", async () => {
    const fixture = await auditFixture();
    const rotated: string[] = [];
    const active: string[] = [];
    for (let index = 0; index < 1_281; index += 1) {
      const first = attempt(auditOperationId(index));
      const pair =
        canonicalJson(first) +
        String.fromCharCode(10) +
        canonicalJson(outcome(first)) +
        String.fromCharCode(10);
      (index < 641 ? rotated : active).push(pair);
    }
    await writeFile(fixture.path + ".1", rotated.join(""));
    await writeFile(fixture.path, active.join(""));

    const recovered = new Phase2AuditAdapter(
      fixture.path,
      {},
      logicalDurability,
    );
    await recovered.recover();
    expect(recovered.isHealthy()).toBe(true);
    expect(recovered.pendingAuditAttempts()).toEqual([]);
  });

  it("latches on active attempt-outcome-attempt reuse", async () => {
    const fixture = await auditFixture();
    const first = attempt();
    await writeFile(
      fixture.path,
      [
        canonicalJson(first),
        canonicalJson(outcome(first)),
        canonicalJson(first),
        "",
      ].join(String.fromCharCode(10)),
    );
    const recovered = new Phase2AuditAdapter(
      fixture.path,
      {},
      logicalDurability,
    );

    await expect(recovered.recover()).rejects.toThrow(
      "attempt operation is duplicated",
    );
    expect(recovered.isHealthy()).toBe(false);
  });

  it("latches on cross-rotation duplicate attempts", async () => {
    const fixture = await auditFixture();
    const first = attempt();
    await writeFile(
      fixture.path + ".1",
      canonicalJson(first) + String.fromCharCode(10),
    );
    await writeFile(
      fixture.path,
      canonicalJson(first) + String.fromCharCode(10),
    );
    const recovered = new Phase2AuditAdapter(
      fixture.path,
      {},
      logicalDurability,
    );

    await expect(recovered.recover()).rejects.toThrow(
      "attempt operation is duplicated",
    );
    expect(recovered.isHealthy()).toBe(false);
  });

  it("latches when a live attempt reuses a terminal operation ID", async () => {
    const fixture = await auditFixture();
    const first = attempt();
    await fixture.audit.append(first);
    await fixture.audit.append(outcome(first));

    await expect(fixture.audit.append(first)).rejects.toThrow(
      "attempt operation is duplicated",
    );
    expect(fixture.audit.isHealthy()).toBe(false);
  });

  it.each(["live", "active", "rotated"] as const)(
    "latches on %s outcome-before-attempt ordering",
    async (mode) => {
      const fixture = await auditFixture();
      const first = attempt();
      if (mode === "live") {
        await expect(fixture.audit.append(outcome(first))).rejects.toThrow(
          "outcome has no prior attempt",
        );
        expect(fixture.audit.isHealthy()).toBe(false);
        return;
      }
      if (mode === "active")
        await writeFile(
          fixture.path,
          [canonicalJson(outcome(first)), canonicalJson(first), ""].join(
            String.fromCharCode(10),
          ),
        );
      else {
        await writeFile(
          fixture.path + ".1",
          canonicalJson(outcome(first)) + String.fromCharCode(10),
        );
        await writeFile(
          fixture.path,
          canonicalJson(first) + String.fromCharCode(10),
        );
      }
      const recovered = new Phase2AuditAdapter(
        fixture.path,
        {},
        logicalDurability,
      );
      await expect(recovered.recover()).rejects.toThrow(
        "outcome has no prior attempt",
      );
      expect(recovered.isHealthy()).toBe(false);
    },
  );
  it("serializes concurrent terminal outcomes and latches on the duplicate", async () => {
    const { audit } = await auditFixture();
    const first = attempt();
    await audit.append(first);
    const terminal = outcome(first);
    const settled = await Promise.allSettled([
      audit.append(terminal),
      audit.append(terminal),
    ]);
    expect(settled.filter((item) => item.status === "fulfilled")).toHaveLength(
      1,
    );
    expect(audit.isHealthy()).toBe(false);
    await expect(audit.append(attempt())).rejects.toThrow("unhealthy");
  });

  it.each(["after_write", "after_sync"] as const)(
    "latches at %s, then recovers one attempt and accepts exactly one terminal outcome",
    async (stage) => {
      const root = await mkdtemp(join(tmpdir(), "phase2-audit-stage-"));
      const path = join(root, "private", "phase2.jsonl");
      const failing = new Phase2AuditAdapter(
        path,
        {
          checkpoint: async (current) => {
            if (current === stage) throw new Error(stage + " failure");
          },
        },
        logicalDurability,
      );
      await failing.recover();
      const first = attempt();
      await expect(failing.append(first)).rejects.toThrow(
        "Phase 2 audit append failed",
      );
      expect(failing.isHealthy()).toBe(false);

      const recovered = new Phase2AuditAdapter(path, {}, logicalDurability);
      await recovered.recover();
      expect(recovered.pendingAuditAttempts()).toMatchObject([
        {
          requestId: first.requestId,
          operationId: first.operationId,
          tool: first.tool,
        },
      ]);
      const terminal = {
        ...outcome(first),
        result: "failure",
        errorCode: "service_unhealthy",
      } as const;
      await recovered.append(terminal);
      expect(recovered.pendingAuditAttempts()).toEqual([]);
      const records = (await readFile(path, "utf8"))
        .trim()
        .split(String.fromCharCode(10))
        .map(jsonRecord);
      expect(
        records.filter((record) => record.operationId === first.operationId),
      ).toMatchObject([
        { phase: "attempt" },
        { phase: "outcome", result: "failure" },
      ]);
      await expect(recovered.append(terminal)).rejects.toThrow(
        "terminal outcome is duplicated",
      );
      expect(recovered.isHealthy()).toBe(false);
    },
  );

  it("latches when active audit creation cannot sync its directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase2-audit-dirsync-"));
    const path = join(root, "private", "phase2.jsonl");
    const failingDurability: Phase2DurabilityPort = {
      privateMode: logicalDurability.privateMode,
      syncDirectory: async () => {
        throw new Error("audit directory sync failure");
      },
    };
    const audit = new Phase2AuditAdapter(path, {}, failingDurability);

    await expect(audit.recover()).rejects.toThrow(
      "Phase 2 audit recovery failed",
    );
    expect(audit.isHealthy()).toBe(false);
    await expect(audit.append(attempt())).rejects.toThrow("unhealthy");
  });

  it("rejects an ambiguous rotation gap and remains unhealthy", async () => {
    const fixture = await auditFixture();
    const record = canonicalJson(attempt()) + String.fromCharCode(10);
    await writeFile(fixture.path + ".1", record);
    await writeFile(fixture.path + ".3", record);
    const audit = new Phase2AuditAdapter(fixture.path, {}, logicalDurability);

    await expect(audit.recover()).rejects.toThrow(
      "rotation sequence is ambiguous",
    );
    expect(audit.isHealthy()).toBe(false);
    await expect(audit.append(attempt())).rejects.toThrow("unhealthy");
  });
  it("latches unhealthy after a durable append checkpoint failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase2-audit-latch-"));
    const path = join(root, "private", "phase2.jsonl");
    const audit = new Phase2AuditAdapter(
      path,
      {
        checkpoint: async (stage) => {
          if (stage === "before_write")
            throw new Error("injected append failure");
        },
      },
      logicalDurability,
    );
    await audit.recover();

    const failure: unknown = await audit.append(attempt()).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe("Phase 2 audit append failed");
    expect((failure as Error).message).not.toContain("injected append failure");
    expect(audit.isHealthy()).toBe(false);
    await expect(audit.append(attempt())).rejects.toThrow("unhealthy");
  });

  it("retries short audit appends until the full record is durable", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase2-audit-short-write-"));
    const path = join(root, "private", "phase2.jsonl");
    const audit = new Phase2AuditAdapter(path, {}, logicalDurability);
    await audit.recover();
    const first = attempt();
    let calls = 0;
    await withFileHandleWriteSpy(
      dirname(path),
      (originalWrite) =>
        function (this: unknown, buffer, offset = 0, length, position = null) {
          return originalWrite.call(
            this,
            buffer,
            offset,
            Math.min(length ?? buffer.byteLength - offset, 5),
            position,
          );
        },
      async (callCount) => {
        await audit.append(first);
        calls = callCount();
      },
    );
    expect((await readFile(path, "utf8")).trim()).toBe(canonicalJson(first));
    expect(calls).toBeGreaterThan(1);
    const recovered = new Phase2AuditAdapter(path, {}, logicalDurability);
    await recovered.recover();
    expect(recovered.pendingAuditAttempts()).toMatchObject([
      { operationId: first.operationId },
    ]);
  });

  it("retries interrupted audit appends without losing bytes", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase2-audit-eintr-write-"));
    const path = join(root, "private", "phase2.jsonl");
    const audit = new Phase2AuditAdapter(path, {}, logicalDurability);
    await audit.recover();
    const first = attempt();
    let interrupted = false;
    await withFileHandleWriteSpy(
      dirname(path),
      (originalWrite) =>
        function (this: unknown, buffer, offset = 0, length, position = null) {
          if (!interrupted) {
            interrupted = true;
            return Promise.reject(
              Object.assign(new Error("interrupted"), { code: "EINTR" }),
            );
          }
          return originalWrite.call(this, buffer, offset, length, position);
        },
      async () => {
        await audit.append(first);
      },
    );
    expect(interrupted).toBe(true);
    expect((await readFile(path, "utf8")).trim()).toBe(canonicalJson(first));
  });

  it("latches unhealthy after an audit append makes no write progress", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase2-audit-zero-write-"));
    const path = join(root, "private", "phase2.jsonl");
    const audit = new Phase2AuditAdapter(path, {}, logicalDurability);
    await audit.recover();
    await withFileHandleWriteSpy(
      dirname(path),
      () =>
        async function (_buffer, _offset, _length, _position) {
          return { bytesWritten: 0, buffer: _buffer };
        },
      async () => {
        await expect(audit.append(attempt())).rejects.toThrow(
          "Phase 2 audit write did not make progress",
        );
      },
    );
    expect(audit.isHealthy()).toBe(false);
    await expect(audit.append(attempt())).rejects.toThrow("unhealthy");
    expect(await readFile(path, "utf8")).toBe("");
  });
  it("rotates only past the active-file boundary and latches at rotation N+1", async () => {
    const first = await auditFixture();
    await writeFile(first.path, fullAuditFile());
    const rotating = new Phase2AuditAdapter(first.path, {}, logicalDurability);
    await rotating.recover();
    await rotating.append(attempt());
    expect((await readFile(first.path + ".1")).byteLength).toBeGreaterThan(0);
    expect((await readFile(first.path, "utf8")).trim()).not.toBe("");

    const exhausted = await auditFixture();
    await writeFile(exhausted.path, fullAuditFile());
    for (let index = 1; index <= PHASE2_AUDIT_LIMITS.rotations; index += 1)
      await writeFile(
        exhausted.path + "." + String(index),
        canonicalJson(attempt()) + String.fromCharCode(10),
      );
    const bounded = new Phase2AuditAdapter(
      exhausted.path,
      {},
      logicalDurability,
    );
    await bounded.recover();
    await expect(bounded.append(attempt())).rejects.toThrow(
      "rotation boundary is exhausted",
    );
    expect(bounded.isHealthy()).toBe(false);
  });

  it.each([
    "after_rotate_rename",
    "after_rotate_create",
    "after_rotate_dirsync",
  ] as const)(
    "recovers safely after the %s crash checkpoint",
    async (stage) => {
      const fixture = await auditFixture();
      await writeFile(fixture.path, fullAuditFile());
      const crashing = new Phase2AuditAdapter(
        fixture.path,
        {
          checkpoint: async (current) => {
            if (current === stage) throw new Error("rotation crash");
          },
        },
        logicalDurability,
      );
      await crashing.recover();
      await expect(crashing.append(attempt())).rejects.toThrow(
        "Phase 2 audit append failed",
      );
      expect(crashing.isHealthy()).toBe(false);

      const recovered = new Phase2AuditAdapter(
        fixture.path,
        {},
        logicalDurability,
      );
      await recovered.recover();
      expect(recovered.isHealthy()).toBe(true);
      await recovered.append(attempt());
    },
  );
  it("repairs only an incomplete active tail and rejects invalid complete data", async () => {
    const { path } = await auditFixture();
    const first = attempt();
    await writeFile(path, canonicalJson(first) + '\n{"schemaVersion":2');
    await new Phase2AuditAdapter(path, {}, logicalDurability).recover();
    expect(await readFile(path, "utf8")).toBe(canonicalJson(first) + "\n");
    await writeFile(path, canonicalJson(first) + "\n{}\n");
    await expect(
      new Phase2AuditAdapter(path, {}, logicalDurability).recover(),
    ).rejects.toThrow("invalid or non-canonical");
  });
});

describe("G1 protected proposal store", () => {
  it("round-trips frozen canonical content through the logical durability port", async () => {
    const root = join(await mkdtemp(join(tmpdir(), "proposal-store-")), "data");
    const store = new ProtectedProposalStore(root, logicalDurability);
    await store.initialize();
    const value = stored();
    await store.create(value, context());
    const values = await store.readAll();
    expect(values).toHaveLength(1);
    expect(Object.isFrozen(values[0])).toBe(true);
    expect(values[0]?.storageSha256).toBe(value.storageSha256);
  });

  it.runIf(process.platform !== "win32")(
    "rejects hard-linked protected artifacts",
    async () => {
      const root = join(
        await mkdtemp(join(tmpdir(), "proposal-hardlink-")),
        "data",
      );
      const store = new ProtectedProposalStore(root, logicalDurability);
      await store.initialize();
      const value = stored();
      await store.create(value, context());
      const source = join(root, "proposals", `${value.public.proposalId}.json`);
      const alias = join(root, "proposals", `${randomUUID()}.json`);
      await link(source, alias);
      await expect(store.readAll()).rejects.toThrow("unsafe");
      await expectStoreLatched(store);
    },
  );

  it("fails before reading proposal content at the N+1 count boundary", async () => {
    const root = join(await mkdtemp(join(tmpdir(), "proposal-count-")), "data");
    const store = new ProtectedProposalStore(root, logicalDurability);
    await store.initialize();
    for (let index = 0; index <= PROPOSAL_STORE_LIMITS.proposals; index += 1)
      await writeFile(join(root, "proposals", `${randomUUID()}.json`), "", {
        mode: 0o600,
      });
    await expect(store.readAll()).rejects.toThrow("count limit");
    await expectStoreLatched(store);

    const journalRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-journal-count-")),
      "data",
    );
    const journalStore = new ProtectedProposalStore(
      journalRoot,
      logicalDurability,
    );
    await journalStore.initialize();
    for (let index = 0; index <= PROPOSAL_STORE_LIMITS.journals; index += 1)
      await writeFile(
        join(journalRoot, "journals", `${randomUUID()}.json`),
        "",
        {
          mode: 0o600,
        },
      );
    await expect(journalStore.readJournals()).rejects.toThrow("count limit");
    await expectStoreLatched(journalStore);
  });

  it("cleans precommit failures and reports committed durability failures", async () => {
    const directory = join(
      await mkdtemp(join(tmpdir(), "proposal-atomic-")),
      "private",
    );
    await mkdir(directory);
    const bytes = Buffer.from("protected-value");

    for (const stage of ["written", "synced"] as const) {
      const target = join(directory, stage + ".json");
      await expect(
        atomicProtectedWrite(
          target,
          bytes,
          undefined,
          async (current) => {
            if (current === stage) throw new Error(stage + " failure");
          },
          undefined,
          logicalDurability,
        ),
      ).rejects.toThrow(stage + " failure");
      expect(await readdir(directory)).not.toContain(stage + ".json");
      expect(
        (await readdir(directory)).some((name) => name.startsWith(".tmp-")),
      ).toBe(false);
    }

    const renamed = join(directory, "renamed.json");
    await expect(
      atomicProtectedWrite(
        renamed,
        bytes,
        undefined,
        async (stage) => {
          if (stage === "renamed") throw new Error("renamed failure");
        },
        undefined,
        logicalDurability,
      ),
    ).rejects.toMatchObject({ committed: true });
    expect(await readFile(renamed, "utf8")).toBe("protected-value");

    const dirsync = join(directory, "dirsync.json");
    const failingDurability: Phase2DurabilityPort = {
      privateMode: logicalDurability.privateMode,
      syncDirectory: async () => {
        throw new Error("dirsync failure");
      },
    };
    const failure: unknown = await atomicProtectedWrite(
      dirsync,
      bytes,
      undefined,
      undefined,
      undefined,
      failingDurability,
    ).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ProtectedWriteError);
    expect((failure as ProtectedWriteError).committed).toBe(true);
    expect(await readFile(dirsync, "utf8")).toBe("protected-value");
    bytes.fill(0);
  });

  it("retries short atomic writes until every byte in the view is durable", async () => {
    const directory = join(
      await mkdtemp(join(tmpdir(), "proposal-short-write-")),
      "private",
    );
    await mkdir(directory);
    const target = join(directory, "short.json");
    const backing = Buffer.from("xxprotected-valueyy");
    const bytes = backing.subarray(2, backing.byteLength - 2);
    let calls = 0;
    await withFileHandleWriteSpy(
      directory,
      (originalWrite) =>
        function (this: unknown, buffer, offset = 0, length, position = null) {
          return originalWrite.call(
            this,
            buffer,
            offset,
            Math.min(length ?? buffer.byteLength - offset, 4),
            position,
          );
        },
      async (callCount) => {
        try {
          await atomicProtectedWrite(
            target,
            bytes,
            undefined,
            undefined,
            undefined,
            logicalDurability,
          );
        } finally {
          backing.fill(0);
        }
        calls = callCount();
      },
    );
    expect(await readFile(target, "utf8")).toBe("protected-value");
    expect(calls).toBeGreaterThan(1);
  });
  it("rejects directory artifacts and oversized protected items", async () => {
    const directoryRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-directory-artifact-")),
      "data",
    );
    const directoryStore = new ProtectedProposalStore(
      directoryRoot,
      logicalDurability,
    );
    await directoryStore.initialize();
    await mkdir(join(directoryRoot, "proposals", randomUUID() + ".json"));
    await expect(directoryStore.readAll()).rejects.toThrow("unsafe");
    await expectStoreLatched(directoryStore);

    const oversizeRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-oversize-artifact-")),
      "data",
    );
    const oversizeStore = new ProtectedProposalStore(
      oversizeRoot,
      logicalDurability,
    );
    await oversizeStore.initialize();
    const oversized = Buffer.alloc(PROPOSAL_STORE_LIMITS.itemBytes + 1, 1);
    try {
      await writeFile(
        join(oversizeRoot, "proposals", randomUUID() + ".json"),
        oversized,
      );
    } finally {
      oversized.fill(0);
    }
    await expect(oversizeStore.readAll()).rejects.toThrow(
      "exceeds its safe boundary",
    );
    await expectStoreLatched(oversizeStore);
  });

  it.runIf(process.platform !== "win32")(
    "rejects symlinked protected artifacts",
    async () => {
      const root = join(
        await mkdtemp(join(tmpdir(), "proposal-symlink-")),
        "data",
      );
      const store = new ProtectedProposalStore(root, logicalDurability);
      await store.initialize();
      const target = join(root, "target.json");
      await writeFile(target, canonicalJson(stored()));
      await symlink(target, join(root, "proposals", randomUUID() + ".json"));
      await expect(store.readAll()).rejects.toThrow("unsafe");
      await expectStoreLatched(store);
    },
  );

  it("latches proposal and journal aggregate overflow", async () => {
    const candidate = Buffer.alloc(480 * 1024, 0x61);
    const diff = Buffer.alloc(480 * 1024, 0x62);
    const base = stored();
    const candidateSha256 = createHash("sha256")
      .update(candidate)
      .digest("hex");
    const diffSha256 = createHash("sha256").update(diff).digest("hex");
    const largeProposal = storageEnvelope(
      { ...base.public, candidateSha256, diffSha256 },
      {
        ...base.protected,
        candidateSha256,
        diffSha256,
        exactCandidateBytesBase64: candidate.toString("base64"),
        exactDiffBytesBase64: diff.toString("base64"),
      },
    );
    candidate.fill(0);
    diff.fill(0);
    const proposalBytes = Buffer.from(canonicalJson(largeProposal));
    expect(proposalBytes.byteLength).toBeLessThanOrEqual(
      PROPOSAL_STORE_LIMITS.itemBytes,
    );

    const proposalRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-aggregate-")),
      "data",
    );
    const proposalStore = new ProtectedProposalStore(
      proposalRoot,
      logicalDurability,
    );
    await proposalStore.initialize();
    const proposalCount =
      Math.floor(
        PROPOSAL_STORE_LIMITS.aggregateBytes / proposalBytes.byteLength,
      ) + 1;
    for (let index = 0; index < proposalCount; index += 1)
      await writeFile(
        join(proposalRoot, "proposals", `${randomUUID()}.json`),
        proposalBytes,
      );
    proposalBytes.fill(0);
    await expect(proposalStore.readAll()).rejects.toThrow("byte limit");
    await expectStoreLatched(proposalStore);

    const journalRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-journal-aggregate-")),
      "data",
    );
    const journalStore = new ProtectedProposalStore(
      journalRoot,
      logicalDurability,
    );
    await journalStore.initialize();
    const journalBytes = Buffer.from(
      canonicalJson(
        journalEnvelope({
          schemaVersion: 1,
          operationId: randomUUID(),
          requestId: randomUUID(),
          tool: "ha_propose_config_change",
          phase: "prepared",
          beforeSha256: null,
          proposal: largeProposal,
        }),
      ),
    );
    expect(journalBytes.byteLength).toBeLessThanOrEqual(
      PROPOSAL_STORE_LIMITS.itemBytes,
    );
    const journalCount =
      Math.floor(
        PROPOSAL_STORE_LIMITS.aggregateBytes / journalBytes.byteLength,
      ) + 1;
    expect(journalCount).toBeLessThanOrEqual(PROPOSAL_STORE_LIMITS.journals);
    for (let index = 0; index < journalCount; index += 1)
      await writeFile(
        join(journalRoot, "journals", `${randomUUID()}.json`),
        journalBytes,
      );
    journalBytes.fill(0);
    await expect(journalStore.readJournals()).rejects.toThrow("byte limit");
    await expectStoreLatched(journalStore);
  });

  it("latches malformed proposal and journal scan artifacts", async () => {
    for (const directory of ["proposals", "journals"] as const) {
      const root = join(
        await mkdtemp(join(tmpdir(), `proposal-malformed-${directory}-`)),
        "data",
      );
      const store = new ProtectedProposalStore(root, logicalDurability);
      await store.initialize();
      await writeFile(join(root, directory, `${randomUUID()}.json`), "{}");
      const scan =
        directory === "proposals" ? store.readAll() : store.readJournals();
      await expect(scan).rejects.toThrow("quarantined");
      await expectStoreLatched(store);
    }
  });
  it("rejects duplicate creates without changing the original or leaving temporary files", async () => {
    const root = join(
      await mkdtemp(join(tmpdir(), "proposal-duplicate-create-")),
      "data",
    );
    const store = new ProtectedProposalStore(root, logicalDurability);
    await store.initialize();
    const value = stored();
    await store.create(value, context());
    const path = join(root, "proposals", value.public.proposalId + ".json");
    const original = await readFile(path);

    await expect(store.create(value, context())).rejects.toBeInstanceOf(Error);
    expect(await readFile(path)).toEqual(original);
    expect(
      (await readdir(join(root, "proposals"))).some((name) =>
        name.startsWith(".tmp-"),
      ),
    ).toBe(false);
    expect(() => store.assertHealthy()).not.toThrow();
    expect(await store.readAll()).toHaveLength(1);

    const changedOnDisk = stored(value.public.proposalId, randomUUID());
    await writeFile(path, canonicalJson(changedOnDisk));
    const replacement = stored(value.public.proposalId, randomUUID());
    await expect(store.replace(replacement, value, context())).rejects.toThrow(
      "replacement identity changed",
    );
    expect(() => store.assertHealthy()).not.toThrow();
    expect(await store.readAll()).toEqual([changedOnDisk]);
  });

  it("latches on ambiguous and oversized quarantine sources", async () => {
    const directoryRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-quarantine-directory-")),
      "data",
    );
    const directoryStore = new ProtectedProposalStore(
      directoryRoot,
      logicalDurability,
    );
    await directoryStore.initialize();
    await mkdir(join(directoryRoot, "proposals", "unsafe-directory"));
    await expect(directoryStore.readAll()).rejects.toThrow("unsafe");
    await expectStoreLatched(directoryStore);
    await expectStoreLatched(directoryStore);

    const oversizeRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-quarantine-oversize-")),
      "data",
    );
    const oversizeStore = new ProtectedProposalStore(
      oversizeRoot,
      logicalDurability,
    );
    await oversizeStore.initialize();
    const oversized = Buffer.alloc(PROPOSAL_STORE_LIMITS.itemBytes + 1, 2);
    try {
      await writeFile(
        join(oversizeRoot, "proposals", "unsafe-oversize"),
        oversized,
      );
    } finally {
      oversized.fill(0);
    }
    await expect(oversizeStore.readAll()).rejects.toThrow(
      "exceeds its safe boundary",
    );
    await expectStoreLatched(oversizeStore);
    await expectStoreLatched(oversizeStore);
  });

  it("latches when quarantine aggregate bytes cross N+1", async () => {
    const root = join(
      await mkdtemp(join(tmpdir(), "proposal-quarantine-bytes-")),
      "data",
    );
    const store = new ProtectedProposalStore(root, logicalDurability);
    await store.initialize();
    const item = Buffer.alloc(PROPOSAL_STORE_LIMITS.itemBytes, 3);
    try {
      const itemCount =
        PROPOSAL_STORE_LIMITS.aggregateBytes / PROPOSAL_STORE_LIMITS.itemBytes;
      for (let index = 0; index < itemCount; index += 1)
        await writeFile(
          join(root, "quarantine", String(index) + ".quarantine"),
          item,
        );
    } finally {
      item.fill(0);
    }
    await writeFile(join(root, "proposals", "unsafe"), "x");

    await expect(store.readAll()).rejects.toThrow(
      "Quarantine byte limit exceeded",
    );
    await expectStoreLatched(store);
  });
  it("quarantines one unsafe source and fails closed at quarantine N+1", async () => {
    const successRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-quarantine-")),
      "data",
    );
    const success = new ProtectedProposalStore(successRoot, logicalDurability);
    await success.initialize();
    await writeFile(join(successRoot, "proposals", "unsafe"), "bad");
    await expect(success.readAll()).rejects.toThrow("quarantined");
    expect(await readdir(join(successRoot, "quarantine"))).toHaveLength(1);
    await expectStoreLatched(success);

    const fullRoot = join(
      await mkdtemp(join(tmpdir(), "proposal-quarantine-full-")),
      "data",
    );
    const full = new ProtectedProposalStore(fullRoot, logicalDurability);
    await full.initialize();
    for (let index = 0; index < PROPOSAL_STORE_LIMITS.quarantine; index += 1)
      await writeFile(
        join(fullRoot, "quarantine", String(index) + ".quarantine"),
        "",
      );
    await writeFile(join(fullRoot, "proposals", "unsafe"), "bad");
    await expect(full.readAll()).rejects.toThrow("Quarantine is full");
    await expectStoreLatched(full);
  });
});

describe("G1 proposal service lifecycle", () => {
  it("paginates exact N and N+1 deterministically", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-page-boundary-"));
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
    );
    await fixture.service.propose(proposalInput(), context());
    await fixture.service.propose(proposalInput(), context());

    const exact = await fixture.service.list({ limit: 2 }, context());
    expect(exact.items).toHaveLength(2);
    expect(exact.nextCursor).toBeNull();

    await fixture.service.propose(proposalInput(), context());
    const first = await fixture.service.list({ limit: 2 }, context());
    expect(first.items).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();
    const last = await fixture.service.list(
      { limit: 2, cursor: first.nextCursor },
      context(),
    );
    expect(last.items).toHaveLength(1);
    expect(last.nextCursor).toBeNull();
    const ids = [...first.items, ...last.items].map((item) => item.proposalId);
    expect(new Set(ids)).toHaveLength(3);
    expect(await fixture.service.list({ limit: 2 }, context())).toEqual(first);
  });

  it("classifies malformed, tampered, rotated-key, and authenticated out-of-range cursors", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-cursor-classify-"));
    const root = join(base, "store");
    const auditPath = join(base, "audit", "phase2.jsonl");
    const cursorKey = Buffer.alloc(32, 1);
    const session = Buffer.alloc(32, 2);
    const fixture = await serviceFixture(
      root,
      auditPath,
      {},
      {},
      cursorKey,
      session,
    );
    await fixture.service.propose(proposalInput(), context());
    await fixture.service.propose(proposalInput(), context());
    const page = await fixture.service.list({ limit: 1 }, context());
    expect(page.nextCursor).not.toBeNull();
    const valid = page.nextCursor as string;

    await expect(
      fixture.service.list({ limit: 1, cursor: "x" }, context()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    const tampered = valid.slice(0, -1) + (valid.endsWith("A") ? "B" : "A");
    await expect(
      fixture.service.list({ limit: 1, cursor: tampered }, context()),
    ).rejects.toMatchObject({ code: "invalid_input" });

    const decoded = fixture.cursors.decode(valid, 1);
    const values = await fixture.store.readAll();
    const snapshot = proposalSnapshot(values, context());
    try {
      const beyond = fixture.cursors.encode(
        1,
        decoded.generation,
        values.length,
        snapshot,
      );
      await expect(
        fixture.service.list({ limit: 1, cursor: beyond }, context()),
      ).rejects.toMatchObject({ code: "stale_source" });
    } finally {
      decoded.snapshot.fill(0);
      snapshot.fill(0);
    }

    const rotated = await serviceFixture(
      root,
      auditPath,
      {},
      {},
      Buffer.alloc(32, 9),
      session,
    );
    await expect(
      rotated.service.list({ limit: 1, cursor: valid }, context()),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("expires exactly at the boundary and never reverts across clock rewind or restart", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-expiry-boundary-"));
    const root = join(base, "store");
    const auditPath = join(base, "audit", "phase2.jsonl");
    let now = 1_000;
    const fixture = await serviceFixture(root, auditPath, {
      now: () => now,
    });
    const created = await fixture.service.propose(proposalInput(), context());
    const expiry = Date.parse(created.expiresAt);

    now = expiry - 1;
    expect(
      await fixture.service.get({ proposalId: created.proposalId }, context()),
    ).toMatchObject({ state: "pending" });

    now = expiry;
    await expect(
      fixture.service.get({ proposalId: created.proposalId }, context()),
    ).rejects.toMatchObject({ code: "proposal_expired" });
    expect(
      (await fixture.service.list({ limit: 10 }, context())).items[0],
    ).toMatchObject({ state: "expired" });

    now = expiry + 1;
    expect(
      (await fixture.service.list({ limit: 10 }, context())).items[0],
    ).toMatchObject({ state: "expired" });
    now = expiry - 1;
    expect(
      (await fixture.service.list({ limit: 10 }, context())).items[0],
    ).toMatchObject({ state: "expired" });

    const restarted = await serviceFixture(root, auditPath, {
      now: () => now,
    });
    expect(
      (await restarted.service.list({ limit: 10 }, context())).items[0],
    ).toMatchObject({ state: "expired" });
    await expect(
      restarted.service.discard({ proposalId: created.proposalId }, context()),
    ).rejects.toMatchObject({ code: "proposal_expired" });
  });

  it("returns original discarded and expired proposals for terminal idempotent retries", async () => {
    const discardedBase = await mkdtemp(
      join(tmpdir(), "proposal-retry-discarded-"),
    );
    const discardedFixture = await serviceFixture(
      join(discardedBase, "store"),
      join(discardedBase, "audit", "phase2.jsonl"),
    );
    const discardedInput = proposalInput();
    const created = await discardedFixture.service.propose(
      discardedInput,
      context(),
    );
    const discarded = await discardedFixture.service.discard(
      { proposalId: created.proposalId },
      context(),
    );
    expect(
      await discardedFixture.service.propose(discardedInput, context()),
    ).toEqual(discarded);

    const expiredBase = await mkdtemp(
      join(tmpdir(), "proposal-retry-expired-"),
    );
    let now = 1_000;
    const expiredFixture = await serviceFixture(
      join(expiredBase, "store"),
      join(expiredBase, "audit", "phase2.jsonl"),
      { now: () => now },
    );
    const expiredInput = proposalInput();
    const pending = await expiredFixture.service.propose(
      expiredInput,
      context(),
    );
    now = Date.parse(pending.expiresAt);
    await expiredFixture.service.list({ limit: 10 }, context());
    expect(
      await expiredFixture.service.propose(expiredInput, context()),
    ).toMatchObject({
      proposalId: pending.proposalId,
      state: "expired",
    });
  });

  it("invalidates paging when proposals expire between pages", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-page-expiry-"));
    let now = 1_000;
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
      { now: () => now },
    );
    const first = await fixture.service.propose(proposalInput(), context());
    await fixture.service.propose(proposalInput(), context());
    const page = await fixture.service.list({ limit: 1 }, context());
    expect(page.nextCursor).not.toBeNull();

    now = Date.parse(first.expiresAt);
    await expect(
      fixture.service.list({ limit: 1, cursor: page.nextCursor }, context()),
    ).rejects.toMatchObject({ code: "stale_source" });
  });

  it("blocks subsequent service operations after the Phase 2 audit latches", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-service-latch-"));
    let beforeWrites = 0;
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
      {},
      {
        checkpoint: async (stage) => {
          if (stage === "before_write" && (beforeWrites += 1) === 3)
            throw new Error("audit latch");
        },
      },
    );
    const proposal = await fixture.service.propose(proposalInput(), context());
    await expect(
      fixture.service.list({ limit: 10 }, context()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
    expect(fixture.audit.isHealthy()).toBe(false);

    for (const operation of [
      () => fixture.service.list({ limit: 10 }, context()),
      () => fixture.service.get({ proposalId: proposal.proposalId }, context()),
      () => fixture.service.propose(proposalInput(), context()),
      () =>
        fixture.service.discard({ proposalId: proposal.proposalId }, context()),
    ])
      await expect(operation()).rejects.toMatchObject({
        code: "service_unhealthy",
      });
    expect(await fixture.store.readAll()).toHaveLength(1);
  });
  it("wipes owned authoritative source buffers on success and stale failure", async () => {
    const successBase = await mkdtemp(join(tmpdir(), "proposal-wipe-success-"));
    const success = await serviceFixture(
      join(successBase, "store"),
      join(successBase, "audit", "phase2.jsonl"),
    );
    const successCanary = Uint8Array.from(SOURCE);
    success.registryReadContent.mockResolvedValue(
      Object.freeze({
        path: PATH,
        rootIdentity: ROOT_IDENTITY,
        identity: IDENTITY,
        bytes: successCanary,
      }),
    );
    await success.service.propose(proposalInput(), context());
    expect([...successCanary].every((byte) => byte === 0)).toBe(true);

    const staleBase = await mkdtemp(join(tmpdir(), "proposal-wipe-stale-"));
    const stale = await serviceFixture(
      join(staleBase, "store"),
      join(staleBase, "audit", "phase2.jsonl"),
    );
    const staleCanary = Uint8Array.from(SOURCE);
    stale.registryReadContent.mockResolvedValue(
      Object.freeze({
        path: PATH,
        rootIdentity: ROOT_IDENTITY,
        identity: IDENTITY,
        bytes: staleCanary,
      }),
    );
    await expect(
      stale.service.propose(
        { ...proposalInput(), expectedSha256: "0".repeat(64) },
        context(),
      ),
    ).rejects.toMatchObject({ code: "stale_source" });
    expect([...staleCanary].every((byte) => byte === 0)).toBe(true);
  });
  it("keeps secret candidate and diff bytes protected while public diff and audit are redacted", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-protected-canary-"));
    const auditPath = join(base, "audit", "phase2.jsonl");
    const fixture = await serviceFixture(join(base, "store"), auditPath);
    const proposedContent = "password: secret-value" + String.fromCharCode(10);
    const created = await fixture.service.propose(
      { ...proposalInput(), proposedContent },
      context(),
    );
    const persisted = (await fixture.store.readAll()).find(
      (value) => value.public.proposalId === created.proposalId,
    );
    expect(persisted).toBeDefined();
    const candidateBytes = Buffer.from(
      persisted!.protected.exactCandidateBytesBase64,
      "base64",
    );
    const diffBytes = Buffer.from(
      persisted!.protected.exactDiffBytesBase64,
      "base64",
    );
    try {
      expect(candidateBytes.toString("utf8")).toBe(proposedContent);
      expect(candidateBytes.toString("utf8")).toContain("secret-value");
      expect(created.redactedDiff).toContain("[REDACTED]");
      expect(created.redactedDiff).not.toContain("secret-value");
      expect("exactCandidateBytesBase64" in created).toBe(false);
      expect("exactDiffBytesBase64" in created).toBe(false);
      expect(createHash("sha256").update(candidateBytes).digest("hex")).toBe(
        created.candidateSha256,
      );
      expect(persisted!.protected.candidateSha256).toBe(
        created.candidateSha256,
      );
      expect(createHash("sha256").update(diffBytes).digest("hex")).toBe(
        created.diffSha256,
      );
      expect(persisted!.protected.diffSha256).toBe(created.diffSha256);
      expect(await readFile(auditPath, "utf8")).not.toContain("secret-value");
    } finally {
      candidateBytes.fill(0);
      diffBytes.fill(0);
    }
  });

  it("produces identical deterministic exact and redacted diffs for identical source and candidate", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-deterministic-diff-"));
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
    );
    const proposedContent = "password: secret-value" + String.fromCharCode(10);
    const first = await fixture.service.propose(
      { ...proposalInput(), proposedContent },
      context(),
    );
    const second = await fixture.service.propose(
      { ...proposalInput(), proposedContent },
      context(),
    );
    expect(second.proposalId).not.toBe(first.proposalId);
    expect(second.diffSha256).toBe(first.diffSha256);
    expect(second.redactedDiff).toBe(first.redactedDiff);
    const persisted = await fixture.store.readAll();
    const firstStored = persisted.find(
      (value) => value.public.proposalId === first.proposalId,
    );
    const secondStored = persisted.find(
      (value) => value.public.proposalId === second.proposalId,
    );
    expect(firstStored?.protected.exactDiffBytesBase64).toBe(
      secondStored?.protected.exactDiffBytesBase64,
    );
    expect(firstStored?.protected.exactCandidateBytesBase64).toBe(
      secondStored?.protected.exactCandidateBytesBase64,
    );
  });

  it("fails stale on source identity drift and after-read catalog drift", async () => {
    async function expectSingleFailure(
      auditPath: string,
      operationId: string,
    ): Promise<void> {
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split(String.fromCharCode(10))
        .map(jsonRecord)
        .filter((record) => record.operationId === operationId);
      expect(records).toMatchObject([
        { phase: "attempt" },
        { phase: "outcome", result: "failure" },
      ]);
      expect(
        records.filter((record) => record.phase === "outcome"),
      ).toHaveLength(1);
    }

    const identityBase = await mkdtemp(
      join(tmpdir(), "proposal-identity-drift-"),
    );
    const identityAudit = join(identityBase, "audit", "phase2.jsonl");
    const identityFixture = await serviceFixture(
      join(identityBase, "store"),
      identityAudit,
    );
    identityFixture.registryReadContent.mockResolvedValue(
      Object.freeze({
        path: PATH,
        rootIdentity: ROOT_IDENTITY,
        identity: Object.freeze({ device: "9", inode: "9" }),
        bytes: Uint8Array.from(SOURCE),
      }),
    );
    const identityContext = context();
    await expect(
      identityFixture.service.propose(proposalInput(), identityContext),
    ).rejects.toMatchObject({ code: "stale_source" });
    expect(await identityFixture.store.readAll()).toEqual([]);
    await expectSingleFailure(identityAudit, identityContext.operationId);

    const catalogBase = await mkdtemp(
      join(tmpdir(), "proposal-catalog-drift-"),
    );
    const catalogAudit = join(catalogBase, "audit", "phase2.jsonl");
    const catalogFixture = await serviceFixture(
      join(catalogBase, "store"),
      catalogAudit,
    );
    const beforeCatalog = Object.freeze({
      rootIdentity: ROOT_IDENTITY,
      directories: Object.freeze([]),
      files: Object.freeze([
        Object.freeze({
          path: PATH,
          identity: IDENTITY,
          size: SOURCE.byteLength,
          mtimeNanoseconds: "1",
          ctimeNanoseconds: "1",
        }),
      ]),
    });
    const afterCatalog = Object.freeze({
      rootIdentity: ROOT_IDENTITY,
      directories: Object.freeze([]),
      files: Object.freeze([
        Object.freeze({
          path: PATH,
          identity: IDENTITY,
          size: SOURCE.byteLength,
          mtimeNanoseconds: "2",
          ctimeNanoseconds: "1",
        }),
      ]),
    });
    vi.mocked(catalogFixture.catalog.catalog)
      .mockResolvedValueOnce(beforeCatalog)
      .mockResolvedValueOnce(afterCatalog);
    const catalogContext = context();
    await expect(
      catalogFixture.service.propose(proposalInput(), catalogContext),
    ).rejects.toMatchObject({ code: "stale_source" });
    expect(await catalogFixture.store.readAll()).toEqual([]);
    await expectSingleFailure(catalogAudit, catalogContext.operationId);
  });
  it("serializes concurrent identical proposals into one durable effect", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-concurrent-"));
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
    );
    const input = proposalInput();

    const [first, second] = await Promise.all([
      fixture.service.propose(input, context()),
      fixture.service.propose(input, context()),
    ]);

    expect(second).toEqual(first);
    expect(await fixture.store.readAll()).toHaveLength(1);
  });

  it("rejects a cursor after a concurrent proposal changes its snapshot", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-cursor-stale-"));
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
    );
    await fixture.service.propose(proposalInput(), context());
    await fixture.service.propose(proposalInput(), context());
    const firstPage = await fixture.service.list({ limit: 1 }, context());
    expect(firstPage.nextCursor).not.toBeNull();

    await fixture.service.propose(proposalInput(), context());

    await expect(
      fixture.service.list(
        { limit: 1, cursor: firstPage.nextCursor },
        context(),
      ),
    ).rejects.toMatchObject({ code: "stale_source" });
  });
  it("classifies a service cursor after the cursor session closes", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-cursor-closed-"));
    const fixture = await serviceFixture(
      join(base, "store"),
      join(base, "audit", "phase2.jsonl"),
    );
    await fixture.service.propose(proposalInput(), context());
    await fixture.service.propose(proposalInput(), context());
    const firstPage = await fixture.service.list({ limit: 1 }, context());
    expect(firstPage.nextCursor).not.toBeNull();
    fixture.service.close();

    await expect(
      fixture.service.list(
        { limit: 1, cursor: firstPage.nextCursor },
        context(),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("rejects invalid, aliased, non-canonical, and oversized candidates before repository reads", async () => {
    for (const [proposedContent, code] of [
      ["value: *missing" + String.fromCharCode(10), "invalid_input"],
      [String.fromCharCode(0xd800), "unsupported_encoding"],
      ["x".repeat(512 * 1024 + 1), "invalid_input"],
    ] as const) {
      const base = await mkdtemp(join(tmpdir(), "proposal-candidate-invalid-"));
      const fixture = await serviceFixture(
        join(base, "store"),
        join(base, "audit", "phase2.jsonl"),
      );

      await expect(
        fixture.service.propose(
          { ...proposalInput(), proposedContent },
          context(),
        ),
      ).rejects.toMatchObject({ code });
      expect(fixture.registryReadContent).not.toHaveBeenCalled();
    }
  });

  it("records exactly one correlated failure outcome for normal post-attempt source failures", async () => {
    async function expectCorrelatedFailure(
      auditPath: string,
      operationId: string,
    ): Promise<void> {
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split(String.fromCharCode(10))
        .filter(Boolean)
        .map(jsonRecord)
        .filter((record) => record.operationId === operationId);
      expect(records).toMatchObject([
        { phase: "attempt" },
        { phase: "outcome", result: "failure" },
      ]);
      expect(
        records.filter((record) => record.phase === "outcome"),
      ).toHaveLength(1);
    }

    const missingBase = await mkdtemp(
      join(tmpdir(), "proposal-audit-missing-"),
    );
    const missingAudit = join(missingBase, "audit", "phase2.jsonl");
    const missing = await serviceFixture(
      join(missingBase, "store"),
      missingAudit,
    );
    vi.mocked(missing.catalog.catalog).mockResolvedValue(
      Object.freeze({
        rootIdentity: ROOT_IDENTITY,
        directories: Object.freeze([]),
        files: Object.freeze([]),
      }),
    );
    const missingContext = context();
    await expect(
      missing.service.propose(proposalInput(), missingContext),
    ).rejects.toMatchObject({ code: "resource_not_found" });
    await expectCorrelatedFailure(missingAudit, missingContext.operationId);

    const staleBase = await mkdtemp(join(tmpdir(), "proposal-audit-stale-"));
    const staleAudit = join(staleBase, "audit", "phase2.jsonl");
    const stale = await serviceFixture(join(staleBase, "store"), staleAudit);
    const staleContext = context();
    await expect(
      stale.service.propose(
        { ...proposalInput(), expectedSha256: "0".repeat(64) },
        staleContext,
      ),
    ).rejects.toMatchObject({ code: "stale_source" });
    await expectCorrelatedFailure(staleAudit, staleContext.operationId);

    const protectedBase = await mkdtemp(
      join(tmpdir(), "proposal-audit-protected-"),
    );
    const protectedAudit = join(protectedBase, "audit", "phase2.jsonl");
    const protectedFixture = await serviceFixture(
      join(protectedBase, "store"),
      protectedAudit,
    );
    protectedFixture.registryReadContent.mockRejectedValue(
      new RepositoryBoundaryError(
        "protected_resource",
        "protected source denied",
      ),
    );
    const protectedContext = context();
    await expect(
      protectedFixture.service.propose(proposalInput(), protectedContext),
    ).rejects.toMatchObject({ code: "protected_resource" });
    await expectCorrelatedFailure(protectedAudit, protectedContext.operationId);

    const invalidBase = await mkdtemp(
      join(tmpdir(), "proposal-audit-invalid-"),
    );
    const invalidAudit = join(invalidBase, "audit", "phase2.jsonl");
    const invalid = await serviceFixture(
      join(invalidBase, "store"),
      invalidAudit,
    );
    const invalidContext = context();
    await expect(
      invalid.service.propose(
        {
          ...proposalInput(),
          proposedContent: "value: *missing" + String.fromCharCode(10),
        },
        invalidContext,
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect((await readFile(invalidAudit, "utf8")).trim()).toBe("");
  });
  it("classifies missing, stale, and protected repository sources", async () => {
    const missingBase = await mkdtemp(join(tmpdir(), "proposal-missing-"));
    const missing = await serviceFixture(
      join(missingBase, "store"),
      join(missingBase, "audit", "phase2.jsonl"),
    );
    vi.mocked(missing.catalog.catalog).mockResolvedValue(
      Object.freeze({
        rootIdentity: ROOT_IDENTITY,
        directories: Object.freeze([]),
        files: Object.freeze([]),
      }),
    );
    await expect(
      missing.service.propose(proposalInput(), context()),
    ).rejects.toMatchObject({ code: "resource_not_found" });

    const staleBase = await mkdtemp(join(tmpdir(), "proposal-stale-"));
    const stale = await serviceFixture(
      join(staleBase, "store"),
      join(staleBase, "audit", "phase2.jsonl"),
    );
    await expect(
      stale.service.propose(
        { ...proposalInput(), expectedSha256: "0".repeat(64) },
        context(),
      ),
    ).rejects.toMatchObject({ code: "stale_source" });

    const protectedBase = await mkdtemp(join(tmpdir(), "proposal-protected-"));
    const protectedFixture = await serviceFixture(
      join(protectedBase, "store"),
      join(protectedBase, "audit", "phase2.jsonl"),
    );
    protectedFixture.registryReadContent.mockRejectedValue(
      new RepositoryBoundaryError(
        "protected_resource",
        "protected source denied",
      ),
    );
    await expect(
      protectedFixture.service.propose(proposalInput(), context()),
    ).rejects.toMatchObject({ code: "protected_resource" });
  });

  it("rejects invalid YAML and invalid UTF-8 in the authoritative source", async () => {
    for (const [sourceBytes, code] of [
      [
        Uint8Array.from(Buffer.from("value: [" + String.fromCharCode(10))),
        "invalid_input",
      ],
      [Uint8Array.from([0xff]), "unsupported_encoding"],
    ] as const) {
      const base = await mkdtemp(join(tmpdir(), "proposal-source-invalid-"));
      const fixture = await serviceFixture(
        join(base, "store"),
        join(base, "audit", "phase2.jsonl"),
      );
      fixture.registryReadContent.mockResolvedValue(
        Object.freeze({
          path: PATH,
          rootIdentity: ROOT_IDENTITY,
          identity: IDENTITY,
          bytes: sourceBytes,
        }),
      );
      const expectedSha256 = createHash("sha256")
        .update(sourceBytes)
        .digest("hex");

      await expect(
        fixture.service.propose(
          { ...proposalInput(), expectedSha256 },
          context(),
        ),
      ).rejects.toMatchObject({ code });
    }
  });
  it.each(["read", "pre-journal-propose"] as const)(
    "settles a dangling %s attempt exactly once across repeated restart",
    async (kind) => {
      const base = await mkdtemp(join(tmpdir(), "proposal-orphan-attempt-"));
      const root = join(base, "store");
      const auditPath = join(base, "audit", "phase2.jsonl");
      const seed = new Phase2AuditAdapter(auditPath, {}, logicalDurability);
      await seed.recover();
      const first = kind === "read" ? attempt() : proposalAuditAttempt();
      await seed.append(first);

      const recovered = await serviceFixture(root, auditPath);
      expect(recovered.audit.pendingAuditAttempts()).toEqual([]);
      const restarted = await serviceFixture(root, auditPath);
      expect(restarted.audit.pendingAuditAttempts()).toEqual([]);
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split(String.fromCharCode(10))
        .map(jsonRecord)
        .filter((record) => record.operationId === first.operationId);
      expect(records).toMatchObject([
        { phase: "attempt" },
        {
          phase: "outcome",
          result: "failure",
          errorCode: "service_unhealthy",
        },
      ]);
      expect(
        records.filter((record) => record.phase === "outcome"),
      ).toHaveLength(1);
    },
  );
  it("reconciles a committed effect after outcome audit persistence fails", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-outcome-recovery-"));
    const root = join(base, "store");
    const auditPath = join(base, "audit", "phase2.jsonl");
    let beforeWrites = 0;
    const fixture = await serviceFixture(
      root,
      auditPath,
      {},
      {
        checkpoint: async (stage) => {
          if (stage === "before_write" && (beforeWrites += 1) === 2)
            throw new Error("outcome persistence failure");
        },
      },
    );

    await expect(
      fixture.service.propose(proposalInput(), context()),
    ).rejects.toBeInstanceOf(Error);
    expect(await fixture.store.readAll()).toHaveLength(1);
    expect(await fixture.store.readJournals()).toHaveLength(1);

    const recovered = await serviceFixture(root, auditPath);
    expect(await recovered.store.readAll()).toHaveLength(1);
    expect(await recovered.store.readJournals()).toEqual([]);
    expect(recovered.audit.pendingAuditAttempts()).toEqual([]);
    const records = (await readFile(auditPath, "utf8"))
      .trim()
      .split(String.fromCharCode(10))
      .map(jsonRecord);
    expect(
      records.filter(
        (record) =>
          record.phase === "outcome" && record.result === "reconciled",
      ),
    ).toHaveLength(1);
  });
  it("supports durable idempotency, conflict, discard, restart, and derived expiry", async () => {
    const base = await mkdtemp(join(tmpdir(), "proposal-service-"));
    const root = join(base, "store");
    const auditPath = join(base, "audit", "phase2.jsonl");
    let now = 1_000;
    const fixture = await serviceFixture(root, auditPath, { now: () => now });
    const input = proposalInput();
    const created = await fixture.service.propose(input, context());
    expect(created.state).toBe("pending");
    expect(await fixture.service.propose(input, context())).toEqual(created);
    await expect(
      fixture.service.propose(
        { ...input, proposedContent: "value: different\n" },
        context(),
      ),
    ).rejects.toMatchObject({ code: "proposal_conflict" });
    const discarded = await fixture.service.discard(
      { proposalId: created.proposalId },
      context(),
    );
    expect(discarded.state).toBe("discarded");
    expect(
      await fixture.service.discard(
        { proposalId: created.proposalId },
        context(),
      ),
    ).toEqual(discarded);

    const restarted = await serviceFixture(root, auditPath, {
      now: () => now,
    });
    expect(
      await restarted.service.get(
        { proposalId: created.proposalId },
        context(),
      ),
    ).toEqual(discarded);

    const second = await restarted.service.propose(proposalInput(), context());
    now = Date.parse(second.expiresAt);
    const listed = await restarted.service.list({ limit: 100 }, context());
    expect(
      listed.items.find((item) => item.proposalId === second.proposalId)?.state,
    ).toBe("expired");
    await expect(
      restarted.service.get({ proposalId: second.proposalId }, context()),
    ).rejects.toMatchObject({ code: "proposal_expired" });
  });

  it.each([
    ["journal_prepared", false, "failure"],
    ["effect_committed", true, "committed_response_unconfirmed"],
    ["outcome_committed", true, "success"],
  ] as const)(
    "reconciles the %s crash window without duplicate effects",
    async (stage, committed, expectedResult) => {
      const base = await mkdtemp(join(tmpdir(), "proposal-crash-"));
      const root = join(base, "store");
      const auditPath = join(base, "audit", "phase2.jsonl");
      const fixture = await serviceFixture(root, auditPath, {
        checkpoint: async (current) => {
          if (current === stage) throw new Error("simulated crash");
        },
      });
      const crashContext = context();
      await expect(
        fixture.service.propose(proposalInput(), crashContext),
      ).rejects.toBeInstanceOf(ProposalServiceError);
      const recovered = await serviceFixture(root, auditPath);
      const list = await recovered.service.list({ limit: 100 }, context());
      expect(list.items.length > 0).toBe(committed);
      expect(await recovered.store.readJournals()).toEqual([]);

      const recoveredAgain = await serviceFixture(root, auditPath);
      expect((await recoveredAgain.store.readAll()).length > 0).toBe(committed);
      expect(await recoveredAgain.store.readJournals()).toEqual([]);
      const records = (await readFile(auditPath, "utf8"))
        .trim()
        .split(String.fromCharCode(10))
        .map(jsonRecord);
      const crashOutcomes = records.filter(
        (record) =>
          record.phase === "outcome" &&
          record.operationId === crashContext.operationId,
      );
      expect(crashOutcomes).toHaveLength(1);
      expect(crashOutcomes[0]).toMatchObject({
        result: expectedResult,
      });
    },
  );

  it("honors cancellation before commit and retains effects after commit", async () => {
    for (const [stage, committed] of [
      ["journal_prepared", false],
      ["effect_committed", true],
    ] as const) {
      const controller = new AbortController();
      const base = await mkdtemp(join(tmpdir(), "proposal-cancel-"));
      const fixture = await serviceFixture(
        join(base, "store"),
        join(base, "audit", "phase2.jsonl"),
        {
          checkpoint: async (current) => {
            if (current === stage) controller.abort();
          },
        },
      );
      await expect(
        fixture.service.propose(
          proposalInput(),
          context({ signal: controller.signal }),
        ),
      ).rejects.toMatchObject({ code: "operation_cancelled" });
      const list = await fixture.store.readAll();
      expect(list.length > 0).toBe(committed);
    }
  });
});
