import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
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
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import {
  DurablePhase3Journal,
  PHASE3_JOURNAL_LIMITS,
  Phase3JournalError,
  Phase3JournalSimulatedCrash,
  type Phase3JournalFilesystem,
  type Phase3JournalHooks,
} from "../src/phase3/journal.js";
import {
  canonicalJson,
  sha256,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "../src/phase3/contracts.js";

const roots: string[] = [];
const logicalDurability = Object.freeze({
  privateMode: (_mode: bigint) => true,
  syncDirectory: async (_path: string) => undefined,
}) satisfies Phase2DurabilityPort;

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("Phase 3C durable transaction journal", () => {
  it("requires initialization and survives restart with stable sorted evidence", async () => {
    const root = await journalRoot();
    const journal = new DurablePhase3Journal(root, {
      durability: logicalDurability,
    });
    await expect(journal.load(transactionId(1))).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    await journal.initialize();
    await journal.createIntent(record(2));
    await journal.createIntent(record(1));
    const restarted = new DurablePhase3Journal(root, {
      durability: logicalDurability,
    });
    await restarted.initialize();
    expect(
      (await restarted.listRecoverable()).map((item) => item.transactionId),
    ).toEqual([transactionId(1), transactionId(2)]);
    expect(await restarted.load(transactionId(1))).toMatchObject({
      state: "intent_prepared",
      version: 0,
    });
  });

  it("persists legal transitions and terminal evidence across fresh instances", async () => {
    const root = await journalRoot();
    const journal = await initialized(root);
    let current = await journal.createIntent(record(1));
    for (const state of [
      "apply_committed",
      "post_validation_succeeded",
      "reload_succeeded",
      "verification_succeeded",
    ] as const) {
      current = await journal.transition(
        current.transactionId,
        current.version,
        state,
      );
    }
    const restarted = await initialized(root);
    await expect(restarted.load(current.transactionId)).resolves.toMatchObject({
      state: "verification_succeeded",
      version: 4,
      priorState: "reload_succeeded",
    });
    expect((await restarted.listRecoverable())[0]?.state).toBe(
      "verification_succeeded",
    );
  });

  it("restarts with exact latest evidence for every transaction state", async () => {
    const root = await journalRoot();
    const journal = await initialized(root);
    const cases = [
      ["intent_prepared", []],
      ["apply_committed", ["apply_committed"]],
      [
        "post_validation_succeeded",
        ["apply_committed", "post_validation_succeeded"],
      ],
      [
        "reload_succeeded",
        ["apply_committed", "post_validation_succeeded", "reload_succeeded"],
      ],
      [
        "verification_succeeded",
        [
          "apply_committed",
          "post_validation_succeeded",
          "reload_succeeded",
          "verification_succeeded",
        ],
      ],
      ["rollback_intent", ["rollback_intent"]],
      ["rollback_committed", ["rollback_intent", "rollback_committed"]],
      [
        "rollback_validation_succeeded",
        [
          "rollback_intent",
          "rollback_committed",
          "rollback_validation_succeeded",
        ],
      ],
      [
        "rollback_verification_succeeded",
        [
          "rollback_intent",
          "rollback_committed",
          "rollback_validation_succeeded",
          "rollback_verification_succeeded",
        ],
      ],
      ["manual_recovery_required", ["manual_recovery_required"]],
    ] as const;
    for (let index = 0; index < cases.length; index += 1) {
      const [expected, path] = cases[index]!;
      let current = await journal.createIntent(record(index + 10));
      for (const state of path)
        current = await journal.transition(
          current.transactionId,
          current.version,
          state,
        );
      expect(current.state).toBe(expected);
    }
    const restarted = await initialized(root);
    expect(
      (await restarted.listRecoverable()).map((item) => item.state),
    ).toEqual(cases.map(([state]) => state));
  });
  it("rejects duplicate intents, stale versions, and illegal transitions", async () => {
    const journal = await initialized(await journalRoot());
    const initial = await journal.createIntent(record(1));
    await expect(journal.createIntent(initial)).rejects.toMatchObject({
      code: "journal_conflict",
    });
    await expect(
      journal.transition(initial.transactionId, 1, "apply_committed"),
    ).rejects.toMatchObject({ code: "journal_cas_conflict" });
    await expect(
      journal.transition(initial.transactionId, 0, "verification_succeeded"),
    ).rejects.toMatchObject({ code: "journal_illegal" });
  });

  it("gives exactly one winner to two independently initialized CAS writers", async () => {
    const root = await journalRoot();
    const first = await initialized(root);
    const initial = await first.createIntent(record(1));
    const second = await initialized(root);
    const results = await Promise.allSettled([
      first.transition(initial.transactionId, 0, "apply_committed"),
      second.transition(initial.transactionId, 0, "apply_committed"),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      reason: { code: "journal_cas_conflict" },
    });
    const restarted = await initialized(root);
    await expect(restarted.load(initial.transactionId)).resolves.toMatchObject({
      version: 1,
      state: "apply_committed",
    });
  });

  it("retains simulated precommit crash evidence without exposing a record", async () => {
    const root = await journalRoot();
    const journal = await initialized(root, {
      afterStage: async ({ stage }) => {
        if (stage === "pre_link") throw new Phase3JournalSimulatedCrash(stage);
      },
    });
    await expect(journal.createIntent(record(1))).rejects.toBeInstanceOf(
      Phase3JournalSimulatedCrash,
    );
    expect(
      (await readdir(root)).some((name) => name.startsWith(".pending-")),
    ).toBe(true);
    const restarted = await initialized(root);
    await expect(restarted.load(transactionId(1))).resolves.toBeNull();
  });

  it("removes its own pending directory after handled precommit failure", async () => {
    const root = await journalRoot();
    const journal = await initialized(root, {
      afterStage: async ({ stage }) => {
        if (stage === "pre_link") throw new Error("handled");
      },
    });
    await expect(journal.createIntent(record(1))).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    expect(await readdir(root)).toEqual([]);
  });

  it("reports commit unknown after link and reconciles exact state", async () => {
    const root = await journalRoot();
    const journal = await initialized(root, {
      afterStage: async ({ stage }) => {
        if (stage === "post_link") throw new Error("lost durability result");
      },
    });
    await expect(journal.createIntent(record(1))).rejects.toMatchObject({
      code: "journal_commit_unknown",
    });
    await expect(journal.load(transactionId(1))).resolves.toMatchObject({
      state: "intent_prepared",
      version: 0,
    });
    const restarted = await initialized(root);
    await expect(restarted.load(transactionId(1))).resolves.toMatchObject({
      state: "intent_prepared",
      version: 0,
    });
  });

  it("allows non-destructive initialize while another instance is paused pending", async () => {
    const root = await journalRoot();
    let release!: () => void;
    let reached!: () => void;
    const atPending = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const resume = new Promise<void>((resolve) => {
      release = resolve;
    });
    const writer = await initialized(root, {
      afterStage: async ({ stage }) => {
        if (stage === "pre_link") {
          reached();
          await resume;
        }
      },
    });
    const create = writer.createIntent(record(1));
    await atPending;
    const observer = await initialized(root);
    await expect(observer.load(transactionId(1))).resolves.toBeNull();
    release();
    await create;
    await expect(observer.load(transactionId(1))).resolves.toMatchObject({
      version: 0,
    });
  });

  it("latches unhealthy on committed tamper without mutating evidence", async () => {
    const root = await journalRoot();
    const journal = await initialized(root);
    await journal.createIntent(record(1));
    const entry = (await readdir(root)).find((name) => name.endsWith(".entry"));
    expect(entry).toBeDefined();
    const path = join(root, entry!);
    const value = JSON.parse(await readFile(path, "utf8")) as {
      record: { state: string };
    };
    value.record.state = "verification_succeeded";
    await writeFile(path, canonicalJson(value));
    const before = await readFile(path);
    const restarted = new DurablePhase3Journal(root, {
      durability: logicalDurability,
    });
    await expect(restarted.initialize()).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    expect(await readFile(path)).toEqual(before);
    expect(await readdir(root)).not.toContain("quarantine");
  });

  it("rejects a canonically re-signed immutable-history mutation", async () => {
    const root = await journalRoot();
    const journal = await initialized(root);
    const initial = await journal.createIntent(record(1));
    await journal.transition(initial.transactionId, 0, "apply_committed");
    const entry = (await readdir(root)).find((name) =>
      name.includes(".000000000001.entry"),
    )!;
    const path = join(root, entry);
    const value = JSON.parse(await readFile(path, "utf8")) as {
      schemaVersion: 1;
      record: Phase3TransactionRecord;
      recordSha256: string;
    };
    value.record.path = "scripts/tampered.yaml";
    value.recordSha256 = sha256(
      canonicalJson({ schemaVersion: 1, record: value.record }),
    );
    await writeFile(path, canonicalJson(value));
    await expect(initialized(root)).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
  });

  it("rejects hard-linked committed records without removing evidence", async () => {
    const root = await journalRoot();
    const outside = await journalRoot();
    const journal = await initialized(root);
    await journal.createIntent(record(1));
    const entry = (await readdir(root)).find((name) =>
      name.endsWith(".entry"),
    )!;
    const recordPath = join(root, entry);
    const alias = join(outside, "alias.json");
    await link(recordPath, alias);
    await expect(initialized(root)).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    await expect(readFile(recordPath)).resolves.toBeInstanceOf(Buffer);
    await expect(readFile(alias)).resolves.toBeInstanceOf(Buffer);
  });
  it("fails closed for unknown artifacts and version/name forks", async () => {
    const unknownRoot = await journalRoot();
    await writeFile(join(unknownRoot, "unknown"), "x");
    await expect(initialized(unknownRoot)).rejects.toMatchObject({
      code: "journal_unhealthy",
    });

    const forkRoot = await journalRoot();
    const journal = await initialized(forkRoot);
    await journal.createIntent(record(1));
    const entry = (await readdir(forkRoot)).find((name) =>
      name.endsWith(".entry"),
    )!;
    await rename(
      join(forkRoot, entry),
      join(forkRoot, transactionId(1) + ".000000000001.entry"),
    );
    await expect(initialized(forkRoot)).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
  });

  it("enforces the transaction boundary at N and N+1", async () => {
    const journal = await initialized(await journalRoot());
    for (let index = 0; index < PHASE3_JOURNAL_LIMITS.transactions; index += 1)
      await journal.createIntent(record(index + 100));
    await expect(journal.createIntent(record(9999))).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    expect((await journal.listRecoverable()).length).toBe(
      PHASE3_JOURNAL_LIMITS.transactions,
    );
  });
  it("enforces the pending-entry boundary at N and N+1", async () => {
    const root = await journalRoot();
    for (
      let index = 0;
      index < PHASE3_JOURNAL_LIMITS.pendingEntries;
      index += 1
    )
      await mkdir(join(root, ".pending-" + transactionId(index + 100)), {
        mode: 0o700,
      });
    await expect(initialized(root)).resolves.toBeInstanceOf(
      DurablePhase3Journal,
    );
    await mkdir(join(root, ".pending-" + transactionId(999)), { mode: 0o700 });
    await expect(initialized(root)).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
  });

  it("closes the record before ordered link and exposes no early final", async () => {
    const root = await journalRoot();
    const stages: string[] = [];
    const filesystem = closeTrackingFilesystem();
    const journal = new DurablePhase3Journal(root, {
      durability: logicalDurability,
      filesystem,
      hooks: {
        afterStage: async ({ stage, finalPath }) => {
          stages.push(stage);
          if (
            stage === "file_synced" ||
            stage === "file_closed" ||
            stage === "entry_synced" ||
            stage === "pre_link"
          )
            await expect(lstat(finalPath)).rejects.toMatchObject({
              code: "ENOENT",
            });
          if (stage === "post_link" || stage === "parent_synced")
            await expect(lstat(finalPath)).resolves.toMatchObject({});
        },
      },
    });
    await journal.initialize();
    await journal.createIntent(record(1));
    expect(stages).toEqual([
      "file_synced",
      "file_closed",
      "entry_synced",
      "pre_link",
      "post_link",
      "parent_synced",
    ]);
  });
  it("never overwrites an empty destination created at the link boundary", async () => {
    const root = await journalRoot();
    let destination = "";
    const journal = await initialized(root, {
      afterStage: async ({ stage, finalPath }) => {
        if (stage === "pre_link") {
          destination = finalPath;
          await mkdir(finalPath, { mode: 0o700 });
        }
      },
    });
    await expect(journal.createIntent(record(1))).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    expect(destination).not.toBe("");
    await expect(lstat(destination)).resolves.toMatchObject({});
    expect((await lstat(destination)).isDirectory()).toBe(true);
    expect(
      (await readdir(root)).filter((name) => name.startsWith(".pending-")),
    ).toEqual([]);
  });

  it.each([
    ["empty", Buffer.alloc(0)],
    ["malformed", Buffer.from("{", "utf8")],
  ])(
    "fails unhealthy when a %s regular file appears at the link boundary",
    async (_case, artifact) => {
      const root = await journalRoot();
      let destination = "";
      const journal = await initialized(root, {
        afterStage: async ({ stage, finalPath }) => {
          if (stage === "pre_link") {
            destination = finalPath;
            await writeFile(finalPath, artifact, { mode: 0o600 });
          }
        },
      });
      await expect(journal.createIntent(record(1))).rejects.toMatchObject({
        code: "journal_unhealthy",
      });
      expect(destination).not.toBe("");
      await expect(readFile(destination)).resolves.toEqual(artifact);
      await expect(journal.load(transactionId(1))).rejects.toMatchObject({
        code: "journal_unhealthy",
      });
      expect(
        (await readdir(root)).filter((name) => name.startsWith(".pending-")),
      ).toEqual([]);
    },
  );
  it("fails closed when the pending pathname changes during descriptor verification", async () => {
    const root = await journalRoot();
    const race = identitySwapFilesystem();
    const journal = new DurablePhase3Journal(root, {
      durability: logicalDurability,
      filesystem: race.filesystem,
    });
    await journal.initialize();
    await expect(journal.createIntent(record(1))).rejects.toMatchObject({
      code: "journal_unhealthy",
    });
    expect(race.wasSwapped()).toBe(true);
    expect(await readdir(root)).toEqual([]);
  });
  it("retries EINTR and completes short writes before commit", async () => {
    const root = await journalRoot();
    let writes = 0;
    const filesystem = instrumentedFilesystem(async (handle, ...args) => {
      writes += 1;
      if (writes === 1)
        throw Object.assign(new Error("interrupted"), { code: "EINTR" });
      const [buffer, offset, length, position] = args;
      const bounded = Math.min(length, 7);
      return await handle.write(buffer, offset, bounded, position);
    });
    const journal = new DurablePhase3Journal(root, {
      durability: logicalDurability,
      filesystem,
    });
    await journal.initialize();
    await journal.createIntent(record(1));
    expect(writes).toBeGreaterThan(2);
    await expect(journal.load(transactionId(1))).resolves.toMatchObject({
      version: 0,
    });
  });

  it.skipIf(process.platform !== "win32")(
    "fails closed when native durability is requested on Windows",
    async () => {
      const journal = new DurablePhase3Journal(await journalRoot());
      await expect(journal.initialize()).rejects.toMatchObject({
        code: "journal_unhealthy",
      });
    },
  );
  it.skipIf(process.platform === "win32")(
    "uses native private modes and directory fsync on Linux",
    async () => {
      const root = await journalRoot();
      const journal = new DurablePhase3Journal(root);
      await journal.initialize();
      await journal.createIntent(record(1));
      const restarted = new DurablePhase3Journal(root);
      await restarted.initialize();
      await expect(restarted.load(transactionId(1))).resolves.toMatchObject({
        version: 0,
      });
    },
  );

  it.skipIf(process.platform === "win32")(
    "rejects an unsafe native journal directory mode",
    async () => {
      const root = await journalRoot();
      await chmod(root, 0o755);
      const journal = new DurablePhase3Journal(root);
      await expect(journal.initialize()).rejects.toMatchObject({
        code: "journal_unhealthy",
      });
    },
  );

  it.skipIf(process.platform === "win32")(
    "rejects a symlinked committed record on native Linux",
    async () => {
      const root = await journalRoot();
      const outside = await journalRoot();
      const journal = new DurablePhase3Journal(root);
      await journal.initialize();
      await journal.createIntent(record(1));
      const entry = (await readdir(root)).find((name) =>
        name.endsWith(".entry"),
      )!;
      const recordPath = join(root, entry);
      const target = join(outside, "target.json");
      const bytes = await readFile(recordPath);
      await writeFile(target, bytes, { mode: 0o600 });
      bytes.fill(0);
      await rm(recordPath);
      await symlink(target, recordPath);
      const restarted = new DurablePhase3Journal(root);
      await expect(restarted.initialize()).rejects.toMatchObject({
        code: "journal_unhealthy",
      });
    },
  );
  it("rejects uppercase UUID identities before persistence", async () => {
    const journal = await initialized(await journalRoot());
    await expect(
      journal.createIntent({
        ...record(1),
        transactionId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      }),
    ).rejects.toMatchObject({ code: "journal_illegal" });
  });
});

async function journalRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "phase3-journal-"));
  roots.push(root);
  return root;
}

async function initialized(
  root: string,
  hooks: Phase3JournalHooks = {},
): Promise<DurablePhase3Journal> {
  const journal = new DurablePhase3Journal(root, {
    durability: logicalDurability,
    hooks,
  });
  await journal.initialize();
  return journal;
}

function record(index: number): Phase3TransactionRecord {
  const timestamp = "2026-07-21T00:00:00.000Z";
  return {
    schemaVersion: 1,
    transactionId: transactionId(index),
    proposalId: transactionId(index + 1000),
    proposalStorageSha256: sha256("storage-" + index),
    path: "automations/item-" + index + ".yaml",
    expectedSha256: sha256("old-" + index),
    candidateSha256: sha256("new-" + index),
    diffSha256: sha256("diff-" + index),
    checkpointId: transactionId(index + 2000),
    checkpointSha256: sha256("checkpoint-" + index),
    impact: "domain_reload",
    state: "intent_prepared",
    priorState: null,
    version: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    failure: null,
  };
}

function transactionId(index: number): string {
  return "00000000-0000-4000-8000-" + index.toString(16).padStart(12, "0");
}

function closeTrackingFilesystem(): Phase3JournalFilesystem {
  let writableHandles = 0;
  return {
    lstat,
    mkdir,
    open: async (path, flags, mode) => {
      const handle = await open(path, flags, mode);
      const writable = (flags & constants.O_WRONLY) !== 0;
      if (writable) writableHandles += 1;
      let closed = false;
      return {
        write: async (buffer, offset, length, position) =>
          await handle.write(buffer, offset, length, position),
        sync: async () => await handle.sync(),
        close: async () => {
          if (closed) return;
          closed = true;
          await handle.close();
          if (writable) writableHandles -= 1;
        },
        stat: async () => await handle.stat({ bigint: true }),
        readFile: async () => await handle.readFile(),
      };
    },
    readFile,
    readdir,
    link: async (source, destination) => {
      expect(writableHandles).toBe(0);
      await link(source, destination);
    },
    rm,
  };
}
function instrumentedFilesystem(
  write: (
    handle: Awaited<ReturnType<typeof open>>,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ) => Promise<{ bytesWritten: number }>,
): Phase3JournalFilesystem {
  return {
    lstat,
    mkdir,
    open: async (path, flags, mode) => {
      const handle = await open(path, flags, mode);
      return {
        write: async (buffer, offset, length, position) =>
          await write(handle, buffer, offset, length, position),
        sync: async () => await handle.sync(),
        close: async () => await handle.close(),
        stat: async () => await handle.stat({ bigint: true }),
        readFile: async () => await handle.readFile(),
      };
    },
    readFile,
    readdir,
    link,
    rm,
  };
}

function identitySwapFilesystem(): {
  readonly filesystem: Phase3JournalFilesystem;
  readonly wasSwapped: () => boolean;
} {
  let swapped = false;
  return {
    wasSwapped: () => swapped,
    filesystem: {
      lstat,
      mkdir,
      open: async (path, flags, mode) => {
        const handle = await open(path, flags, mode);
        return {
          write: async (buffer, offset, length, position) =>
            await handle.write(buffer, offset, length, position),
          sync: async () => await handle.sync(),
          close: async () => await handle.close(),
          stat: async () => await handle.stat({ bigint: true }),
          readFile: async () => {
            const bytes = await handle.readFile();
            if (!swapped && path.endsWith("record.json")) {
              const replacement = path + ".replaced";
              await rename(path, replacement);
              await writeFile(path, bytes, { mode: 0o600 });
              swapped = true;
            }
            return bytes;
          },
        };
      },
      readFile,
      readdir,
      link,
      rm,
    },
  };
}
