import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PHASE2_MAX_TEXT_BYTES } from "../src/phase2Contracts.js";
import type { Phase2DurabilityPort } from "../src/proposals/durability.js";
import {
  DurablePhase3Checkpoints,
  PHASE3_CHECKPOINT_LIMITS,
  Phase3CheckpointSimulatedCrash,
  type Phase3CheckpointFilesystem,
  type Phase3CheckpointHooks,
} from "../src/phase3/checkpoints.js";
import { canonicalJson, sha256 } from "../src/phase3/contracts.js";

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

describe("Phase 3D durable immutable checkpoints", () => {
  it("initializes, restarts, creates, loads, and returns caller-owned bytes", async () => {
    const root = await checkpointRoot();
    const store = new DurablePhase3Checkpoints(root, {
      durability: logicalDurability,
    });
    await expect(store.load(uuid(1))).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });
    await store.initialize();
    const firstBytes = Buffer.from("first checkpoint", "utf8");
    const secondBytes = Buffer.from("second checkpoint", "utf8");
    const first = await store.create(
      "automations/one.yaml",
      firstBytes,
      sha256(firstBytes),
      context(),
    );
    const second = await store.create(
      "automations/two.yaml",
      secondBytes,
      sha256(secondBytes),
      context(),
    );
    expect(first.checkpointId).not.toBe(second.checkpointId);
    expect(first.checkpointSha256).toBe(sha256(firstBytes));
    expect((await readdir(root)).sort()).toEqual(
      [first.checkpointId, second.checkpointId].sort(),
    );

    const restarted = await initialized(root);
    const loaded = await restarted.load(first.checkpointId);
    const loadedAgain = await restarted.load(first.checkpointId);
    loaded.fill(0);
    expect(loadedAgain).toEqual(firstBytes);
    expect(await restarted.load(first.checkpointId)).toEqual(firstBytes);
    await expect(
      restarted.load(first.checkpointId.toUpperCase()),
    ).rejects.toMatchObject({ code: "checkpoint_missing" });
    await expect(restarted.load(uuid(9999))).rejects.toMatchObject({
      code: "checkpoint_missing",
    });
  });

  it("allows empty checkpoints and validates path, digest, size, and content before disk effects", async () => {
    const root = await checkpointRoot();
    const store = await initialized(root);
    const empty = Buffer.alloc(0);
    await expect(
      store.create("empty.yaml", empty, sha256(empty), context()),
    ).resolves.toMatchObject({ checkpointSha256: sha256(empty) });

    const cases = [
      ["../bad.yaml", Buffer.from("x"), sha256("x")],
      ["bad.yaml", Buffer.from("x"), sha256("x").toUpperCase()],
      ["bad.yaml", Buffer.from("x"), sha256("y")],
      [
        "bad.yaml",
        Buffer.alloc(PHASE3_CHECKPOINT_LIMITS.contentBytes + 1),
        sha256(Buffer.alloc(PHASE3_CHECKPOINT_LIMITS.contentBytes + 1)),
      ],
    ] as const;
    for (const [path, bytes, digest] of cases) {
      const isolated = await checkpointRoot();
      const failing = await initialized(isolated);
      await expect(
        failing.create(path, bytes, digest, context()),
      ).rejects.toMatchObject({ code: "checkpoint_illegal" });
      expect(await readdir(isolated)).toEqual([]);
    }
  });

  it("gives concurrent independent creates distinct IDs without overwriting", async () => {
    const store = await initialized(await checkpointRoot());
    const bytes = Buffer.from("same source", "utf8");
    const results = await Promise.all([
      store.create("automations/shared.yaml", bytes, sha256(bytes), context()),
      store.create("automations/shared.yaml", bytes, sha256(bytes), context()),
    ]);
    expect(results[0].checkpointId).not.toBe(results[1].checkpointId);
    await expect(store.load(results[0].checkpointId)).resolves.toEqual(bytes);
    await expect(store.load(results[1].checkpointId)).resolves.toEqual(bytes);
  });

  it("closes and syncs the pending record before link and exposes the final only after link", async () => {
    const root = await checkpointRoot();
    const stages: string[] = [];
    const filesystem = closeTrackingFilesystem();
    const store = new DurablePhase3Checkpoints(root, {
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
    await store.initialize();
    const bytes = Buffer.from("ordered", "utf8");
    await store.create("ordered.yaml", bytes, sha256(bytes), context());
    expect(stages).toEqual([
      "file_synced",
      "file_closed",
      "entry_synced",
      "pre_link",
      "post_link",
      "parent_synced",
    ]);
  });

  it("handles cancellation, deadlines, short writes, EINTR, and cleanup before the link", async () => {
    const aborted = new AbortController();
    aborted.abort();
    const abortRoot = await checkpointRoot();
    const aborting = await initialized(abortRoot);
    const bytes = Buffer.from("cancel", "utf8");
    await expect(
      aborting.create("cancel.yaml", bytes, sha256(bytes), {
        signal: aborted.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "checkpoint_illegal" });
    expect(await readdir(abortRoot)).toEqual([]);

    const deadlineRoot = await checkpointRoot();
    const expired = await initialized(deadlineRoot);
    await expect(
      expired.create("deadline.yaml", bytes, sha256(bytes), {
        signal: new AbortController().signal,
        deadlineAt: Date.now() - 1,
      }),
    ).rejects.toMatchObject({ code: "checkpoint_illegal" });
    expect(await readdir(deadlineRoot)).toEqual([]);

    const writeRoot = await checkpointRoot();
    const controller = new AbortController();
    let writes = 0;
    const filesystem = instrumentedFilesystem(async (handle, ...args) => {
      writes += 1;
      if (writes === 1)
        throw Object.assign(new Error("interrupted"), { code: "EINTR" });
      const [buffer, offset, length, position] = args;
      const bounded = Math.min(length, 9);
      const result = await handle.write(buffer, offset, bounded, position);
      controller.abort();
      return result;
    });
    const writing = new DurablePhase3Checkpoints(writeRoot, {
      durability: logicalDurability,
      filesystem,
    });
    await writing.initialize();
    await expect(
      writing.create("write.yaml", bytes, sha256(bytes), {
        signal: controller.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "checkpoint_illegal" });
    expect(writes).toBeGreaterThan(1);
    expect(await readdir(writeRoot)).toEqual([]);
  });

  it.each(["file_synced", "file_closed", "entry_synced", "pre_link"] as const)(
    "cancels safely at the precommit %s stage",
    async (cancelStage) => {
      const root = await checkpointRoot();
      const controller = new AbortController();
      const store = await initialized(root, {
        afterStage: async ({ stage }) => {
          if (stage === cancelStage) controller.abort();
        },
      });
      const bytes = Buffer.from("cancel-" + cancelStage, "utf8");
      await expect(
        store.create("cancel-stage.yaml", bytes, sha256(bytes), {
          signal: controller.signal,
          deadlineAt: Date.now() + 60_000,
        }),
      ).rejects.toMatchObject({ code: "checkpoint_illegal" });
      expect(await readdir(root)).toEqual([]);
    },
  );
  it("retains simulated pre-link crash evidence but removes handled pre-link failures", async () => {
    const crashRoot = await checkpointRoot();
    const crashing = await initialized(crashRoot, {
      afterStage: async ({ stage }) => {
        if (stage === "pre_link")
          throw new Phase3CheckpointSimulatedCrash(stage);
      },
    });
    const bytes = Buffer.from("pre-link", "utf8");
    await expect(
      crashing.create("pre-link.yaml", bytes, sha256(bytes), context()),
    ).rejects.toBeInstanceOf(Phase3CheckpointSimulatedCrash);
    expect(
      (await readdir(crashRoot)).some((name) => name.startsWith(".pending-")),
    ).toBe(true);
    const observer = await initialized(crashRoot);
    expect(await readdir(crashRoot)).toHaveLength(1);
    await expect(observer.load(uuid(1))).rejects.toMatchObject({
      code: "checkpoint_missing",
    });

    const handledRoot = await checkpointRoot();
    const handled = await initialized(handledRoot, {
      afterStage: async ({ stage }) => {
        if (stage === "pre_link") throw new Error("handled");
      },
    });
    await expect(
      handled.create("handled.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_unhealthy" });
    expect(await readdir(handledRoot)).toEqual([]);
  });

  it("reports commit unknown after link, preserves evidence, and ignores caller cancellation after link", async () => {
    const unknownRoot = await checkpointRoot();
    const bytes = Buffer.from("post-link", "utf8");
    let linkedId = "";
    const unknown = await initialized(unknownRoot, {
      afterStage: async ({ stage, record }) => {
        if (stage === "post_link") {
          linkedId = record.checkpointId;
          throw new Error("lost durability result");
        }
      },
    });
    await expect(
      unknown.create("post-link.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_commit_unknown" });
    expect(linkedId).not.toBe("");
    await expect(unknown.load(linkedId)).resolves.toEqual(bytes);
    await expect(
      (await initialized(unknownRoot)).load(linkedId),
    ).resolves.toEqual(bytes);

    const cancelRoot = await checkpointRoot();
    const controller = new AbortController();
    const cancelling = await initialized(cancelRoot, {
      afterStage: async ({ stage }) => {
        if (stage === "post_link") controller.abort();
      },
    });
    await expect(
      cancelling.create("after-link.yaml", bytes, sha256(bytes), {
        signal: controller.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).resolves.toMatchObject({ checkpointSha256: sha256(bytes) });
  });

  it("reports commit unknown when post-link pending or directory cleanup fails", async () => {
    const bytes = Buffer.from("cleanup-after-link", "utf8");

    const pendingRoot = await checkpointRoot();
    const pendingFilesystem: Phase3CheckpointFilesystem = {
      ...defaultTestFilesystem(),
      rm: async () => {
        throw new Error("pending cleanup failed");
      },
    };
    let pendingId = "";
    const pendingStore = new DurablePhase3Checkpoints(pendingRoot, {
      durability: logicalDurability,
      filesystem: pendingFilesystem,
      hooks: {
        afterStage: async ({ stage, record }) => {
          if (stage === "post_link") pendingId = record.checkpointId;
        },
      },
    });
    await pendingStore.initialize();
    await expect(
      pendingStore.create(
        "pending-cleanup.yaml",
        bytes,
        sha256(bytes),
        context(),
      ),
    ).rejects.toMatchObject({ code: "checkpoint_commit_unknown" });
    expect(pendingId).not.toBe("");
    await expect(
      (await initialized(pendingRoot)).load(pendingId),
    ).resolves.toEqual(bytes);

    const syncRoot = await checkpointRoot();
    let syncs = 0;
    let syncId = "";
    const failingCleanupSync = {
      privateMode: (_mode: bigint) => true,
      syncDirectory: async (_path: string) => {
        syncs += 1;
        if (syncs === 3) throw new Error("cleanup sync failed");
      },
    } satisfies Phase2DurabilityPort;
    const syncStore = new DurablePhase3Checkpoints(syncRoot, {
      durability: failingCleanupSync,
      hooks: {
        afterStage: async ({ stage, record }) => {
          if (stage === "post_link") syncId = record.checkpointId;
        },
      },
    });
    await syncStore.initialize();
    await expect(
      syncStore.create("sync-cleanup.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_commit_unknown" });
    expect(syncId).not.toBe("");
    expect(
      (await readdir(syncRoot)).some((name) => name.startsWith(".pending-")),
    ).toBe(false);
    await expect((await initialized(syncRoot)).load(syncId)).resolves.toEqual(
      bytes,
    );
  });
  it("fails closed on pending cleanup failure", async () => {
    const root = await checkpointRoot();
    const filesystem: Phase3CheckpointFilesystem = {
      ...defaultTestFilesystem(),
      rm: async () => {
        throw new Error("cleanup failed");
      },
    };
    const store = new DurablePhase3Checkpoints(root, {
      durability: logicalDurability,
      filesystem,
      hooks: {
        afterStage: async ({ stage }) => {
          if (stage === "pre_link") throw new Error("handled");
        },
      },
    });
    await store.initialize();
    const bytes = Buffer.from("cleanup", "utf8");
    await expect(
      store.create("cleanup.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_unhealthy" });
  });

  it("fails closed for tamper, re-signed tamper, filename mismatch, and noncanonical encoding", async () => {
    const root = await checkpointRoot();
    const store = await initialized(root);
    const bytes = Buffer.from("tamper", "utf8");
    const checkpoint = await store.create(
      "tamper.yaml",
      bytes,
      sha256(bytes),
      context(),
    );
    const path = join(root, checkpoint.checkpointId);

    const tampered = JSON.parse(
      await readFile(path, "utf8"),
    ) as CheckpointRecord;
    tampered.path = "other.yaml";
    await writeFile(path, canonicalJson(tampered), { mode: 0o600 });
    await expect(initialized(root)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const resignedRoot = await checkpointRoot();
    const record = await writeValidFinal(resignedRoot, 1, Buffer.from("old"));
    const resignedPath = join(resignedRoot, record.checkpointId);
    const resigned = JSON.parse(
      await readFile(resignedPath, "utf8"),
    ) as CheckpointRecord;
    resigned.path = "resigned.yaml";
    const { storageSha256: _old, ...core } = resigned;
    resigned.storageSha256 = sha256(canonicalJson(core));
    await writeFile(resignedPath, canonicalJson(resigned), { mode: 0o600 });
    await expect(initialized(resignedRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const invalidPathRoot = await checkpointRoot();
    const invalidPath = await validRecord(20, Buffer.from("invalid-path"));
    invalidPath.path = "../invalid.yaml";
    const {
      storageSha256: _invalidStorage,
      checkpointId: _invalidCheckpointId,
      ...invalidIdentity
    } = invalidPath;
    invalidPath.checkpointId = uuidFromDigest(
      sha256(canonicalJson(invalidIdentity)),
    );
    invalidPath.storageSha256 = sha256(
      canonicalJson(withoutStorage(invalidPath)),
    );
    await writeFile(
      join(invalidPathRoot, invalidPath.checkpointId),
      canonicalJson(invalidPath),
      { mode: 0o600 },
    );
    await expect(initialized(invalidPathRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const mismatchRoot = await checkpointRoot();
    const mismatch = await validRecord(2, Buffer.from("mismatch"));
    await writeFile(join(mismatchRoot, uuid(9999)), canonicalJson(mismatch), {
      mode: 0o600,
    });
    await expect(initialized(mismatchRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const jsonRoot = await checkpointRoot();
    const pretty = await validRecord(3, Buffer.from("pretty"));
    await writeFile(
      join(jsonRoot, pretty.checkpointId),
      JSON.stringify(pretty, null, 2),
      {
        mode: 0o600,
      },
    );
    await expect(initialized(jsonRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const b64Root = await checkpointRoot();
    const b64 = await validRecord(4, Buffer.from("x"));
    b64.contentBase64 = b64.contentBase64.replace(/=+$/u, "");
    b64.storageSha256 = sha256(canonicalJson(withoutStorage(b64)));
    await writeFile(join(b64Root, b64.checkpointId), canonicalJson(b64), {
      mode: 0o600,
    });
    await expect(initialized(b64Root)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });
  });

  it("fails closed for unknown artifacts, symlinks, unrelated hardlinks, and malformed link-boundary races", async () => {
    const unknownRoot = await checkpointRoot();
    await writeFile(join(unknownRoot, "unknown"), "x");
    await expect(initialized(unknownRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const directoryRoot = await checkpointRoot();
    await mkdir(join(directoryRoot, uuid(1)), { mode: 0o700 });
    await expect(initialized(directoryRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const hardlinkRoot = await checkpointRoot();
    const outside = await checkpointRoot();
    const hardlinkRecord = await writeValidFinal(hardlinkRoot, 1);
    await link(
      join(hardlinkRoot, hardlinkRecord.checkpointId),
      join(outside, "alias"),
    );
    await expect(initialized(hardlinkRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const emptyRoot = await checkpointRoot();
    const bytes = Buffer.from("race", "utf8");
    let emptyFinal = "";
    const emptyRace = await initialized(emptyRoot, {
      afterStage: async ({ stage, finalPath }) => {
        if (stage === "pre_link") {
          emptyFinal = finalPath;
          await writeFile(finalPath, Buffer.alloc(0), { mode: 0o600 });
        }
      },
    });
    await expect(
      emptyRace.create("race.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_unhealthy" });
    expect(emptyFinal).not.toBe("");
    expect(await readFile(emptyFinal)).toEqual(Buffer.alloc(0));

    const malformedRoot = await checkpointRoot();
    const malformedRace = await initialized(malformedRoot, {
      afterStage: async ({ stage, finalPath }) => {
        if (stage === "pre_link")
          await writeFile(finalPath, "{", { mode: 0o600 });
      },
    });
    await expect(
      malformedRace.create("malformed.yaml", bytes, sha256(bytes), context()),
    ).rejects.toMatchObject({ code: "checkpoint_unhealthy" });

    if (process.platform !== "win32") {
      const symlinkRoot = await checkpointRoot();
      const symlinkOutside = await checkpointRoot();
      const linked = await writeValidFinal(symlinkOutside, 10);
      await symlink(
        join(symlinkOutside, linked.checkpointId),
        join(symlinkRoot, linked.checkpointId),
      );
      await expect(initialized(symlinkRoot)).rejects.toMatchObject({
        code: "checkpoint_unhealthy",
      });
    }
  });

  it("latches unhealthy when a hard link appears between refresh and exact load", async () => {
    const root = await checkpointRoot();
    const outside = await checkpointRoot();
    const bytes = Buffer.from("load-race", "utf8");
    const checkpoint = await (
      await initialized(root)
    ).create("load-race.yaml", bytes, sha256(bytes), context());
    const finalPath = join(root, checkpoint.checkpointId);
    const aliasPath = join(outside, "alias");
    const race = hardlinkAfterRefreshFilesystem(finalPath, aliasPath);
    const observer = new DurablePhase3Checkpoints(root, {
      durability: logicalDurability,
      filesystem: race.filesystem,
    });
    await observer.initialize();
    race.arm();
    await expect(observer.load(checkpoint.checkpointId)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });
    await expect(readFile(aliasPath)).resolves.toBeInstanceOf(Buffer);
    await expect(observer.load(checkpoint.checkpointId)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });
  });
  it("enforces checkpoint count, pending, content, record, aggregate, and scan boundaries", async () => {
    expect(PHASE3_CHECKPOINT_LIMITS.contentBytes).toBe(PHASE2_MAX_TEXT_BYTES);

    const countRoot = await checkpointRoot();
    for (
      let index = 0;
      index < PHASE3_CHECKPOINT_LIMITS.checkpoints;
      index += 1
    )
      await writeValidFinal(countRoot, index + 100);
    await expect(initialized(countRoot)).resolves.toBeInstanceOf(
      DurablePhase3Checkpoints,
    );
    await writeValidFinal(countRoot, 9999);
    await expect(initialized(countRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const pendingRoot = await checkpointRoot();
    for (
      let index = 0;
      index < PHASE3_CHECKPOINT_LIMITS.pendingEntries;
      index += 1
    )
      await mkdir(join(pendingRoot, `.pending-${uuid(index + 100)}`), {
        mode: 0o700,
      });
    await expect(initialized(pendingRoot)).resolves.toBeInstanceOf(
      DurablePhase3Checkpoints,
    );
    await mkdir(join(pendingRoot, `.pending-${uuid(999)}`), { mode: 0o700 });
    await expect(initialized(pendingRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const contentRoot = await checkpointRoot();
    const contentStore = await initialized(contentRoot);
    const maxContent = Buffer.alloc(
      PHASE3_CHECKPOINT_LIMITS.contentBytes,
      0x61,
    );
    await expect(
      contentStore.create(
        "max.yaml",
        maxContent,
        sha256(maxContent),
        context(),
      ),
    ).resolves.toMatchObject({ checkpointSha256: sha256(maxContent) });
    const tooMuch = Buffer.alloc(
      PHASE3_CHECKPOINT_LIMITS.contentBytes + 1,
      0x61,
    );
    await expect(
      contentStore.create("too-much.yaml", tooMuch, sha256(tooMuch), context()),
    ).rejects.toMatchObject({ code: "checkpoint_illegal" });

    const recordRoot = await checkpointRoot();
    await writeFile(
      join(recordRoot, uuid(1)),
      Buffer.alloc(PHASE3_CHECKPOINT_LIMITS.recordBytes),
      {
        mode: 0o600,
      },
    );
    await expect(initialized(recordRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });
    await rm(recordRoot, { recursive: true, force: true });
    await mkdir(recordRoot, { mode: 0o700 });
    await writeFile(
      join(recordRoot, uuid(1)),
      Buffer.alloc(PHASE3_CHECKPOINT_LIMITS.recordBytes + 1),
      {
        mode: 0o600,
      },
    );
    await expect(initialized(recordRoot)).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    const aggregateRoot = await checkpointRoot();
    const sizeByPath = new Map<string, bigint>();
    for (let index = 0; index < 64; index += 1) {
      const record = await writeValidFinal(aggregateRoot, index + 500);
      sizeByPath.set(
        join(aggregateRoot, record.checkpointId),
        BigInt(1024 * 1024),
      );
    }
    await expect(
      initialized(aggregateRoot, {}, sizedFilesystem(sizeByPath)),
    ).resolves.toBeInstanceOf(DurablePhase3Checkpoints);
    const extra = await writeValidFinal(aggregateRoot, 99999);
    sizeByPath.set(join(aggregateRoot, extra.checkpointId), 1n);
    await expect(
      initialized(aggregateRoot, {}, sizedFilesystem(sizeByPath)),
    ).rejects.toMatchObject({
      code: "checkpoint_unhealthy",
    });

    await expect(
      initializeWithScanNames(PHASE3_CHECKPOINT_LIMITS.scanEntries),
    ).rejects.toThrow(/unknown artifact/u);
    await expect(
      initializeWithScanNames(PHASE3_CHECKPOINT_LIMITS.scanEntries + 1),
    ).rejects.toThrow(/scan limit/u);
  });

  it.skipIf(process.platform !== "win32")(
    "fails closed when native durability is requested on Windows",
    async () => {
      const store = new DurablePhase3Checkpoints(await checkpointRoot());
      await expect(store.initialize()).rejects.toMatchObject({
        code: "checkpoint_unhealthy",
      });
    },
  );

  it.skipIf(process.platform === "win32")(
    "uses native Linux durability and rejects unsafe native modes",
    async () => {
      const root = await checkpointRoot();
      const store = new DurablePhase3Checkpoints(root);
      await store.initialize();
      const bytes = Buffer.from("native", "utf8");
      const checkpoint = await store.create(
        "native.yaml",
        bytes,
        sha256(bytes),
        context(),
      );
      await expect(
        (await nativeInitialized(root)).load(checkpoint.checkpointId),
      ).resolves.toEqual(bytes);

      const unsafe = await checkpointRoot();
      await chmod(unsafe, 0o755);
      const unsafeStore = new DurablePhase3Checkpoints(unsafe);
      await expect(unsafeStore.initialize()).rejects.toMatchObject({
        code: "checkpoint_unhealthy",
      });
    },
  );
});

async function checkpointRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "phase3-checkpoints-"));
  roots.push(root);
  return root;
}

async function initialized(
  root: string,
  hooks: Phase3CheckpointHooks = {},
  filesystem?: Phase3CheckpointFilesystem,
): Promise<DurablePhase3Checkpoints> {
  const store = new DurablePhase3Checkpoints(root, {
    durability: logicalDurability,
    ...(filesystem ? { filesystem } : {}),
    hooks,
  });
  await store.initialize();
  return store;
}

async function nativeInitialized(
  root: string,
): Promise<DurablePhase3Checkpoints> {
  const store = new DurablePhase3Checkpoints(root);
  await store.initialize();
  return store;
}

function context(): {
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
} {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 60_000,
  };
}

type CheckpointRecord = {
  schemaVersion: 1;
  nonce: string;
  checkpointId: string;
  path: string;
  expectedSha256: string;
  sourceSha256: string;
  contentSha256: string;
  contentBase64: string;
  storageSha256: string;
};

async function writeValidFinal(
  root: string,
  index: number,
  bytes = Buffer.from(`checkpoint-${index}`, "utf8"),
): Promise<CheckpointRecord> {
  const record = await validRecord(index, bytes);
  await writeFile(join(root, record.checkpointId), canonicalJson(record), {
    mode: 0o600,
  });
  return record;
}

async function validRecord(
  index: number,
  bytes: Buffer,
): Promise<CheckpointRecord> {
  await Promise.resolve();
  const digest = sha256(bytes);
  const identity = {
    schemaVersion: 1 as const,
    nonce: uuid(index),
    path: `automations/checkpoint-${index}.yaml`,
    expectedSha256: digest,
    sourceSha256: digest,
    contentSha256: digest,
    contentBase64: bytes.toString("base64"),
  };
  const core = {
    ...identity,
    checkpointId: uuidFromDigest(sha256(canonicalJson(identity))),
  };
  return {
    ...core,
    storageSha256: sha256(canonicalJson(core)),
  };
}

function withoutStorage(
  record: CheckpointRecord,
): Omit<CheckpointRecord, "storageSha256"> {
  const { storageSha256: _storageSha256, ...core } = record;
  return core;
}

function uuid(index: number): string {
  return "00000000-0000-4000-8000-" + index.toString(16).padStart(12, "0");
}

function uuidFromDigest(hex: string): string {
  const bytes = Buffer.from(hex.slice(0, 32), "hex");
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const text = bytes.toString("hex");
  bytes.fill(0);
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(
    16,
    20,
  )}-${text.slice(20, 32)}`;
}

function defaultTestFilesystem(): Phase3CheckpointFilesystem {
  return {
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
        readFile: async () => await handle.readFile(),
      };
    },
    readdir,
    link,
    rm,
  };
}

function closeTrackingFilesystem(): Phase3CheckpointFilesystem {
  let writableHandles = 0;
  return {
    ...defaultTestFilesystem(),
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
    link: async (source, destination) => {
      expect(writableHandles).toBe(0);
      await link(source, destination);
    },
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
): Phase3CheckpointFilesystem {
  return {
    ...defaultTestFilesystem(),
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
  };
}

function hardlinkAfterRefreshFilesystem(
  target: string,
  alias: string,
): {
  readonly filesystem: Phase3CheckpointFilesystem;
  readonly arm: () => void;
} {
  let armed = false;
  let targetStats = 0;
  const racedLstat = (async (path, options) => {
    if (armed && pathKey(path) === target) {
      targetStats += 1;
      if (targetStats === 3) await link(target, alias);
    }
    return await lstat(path, options);
  }) as Phase3CheckpointFilesystem["lstat"];
  return {
    arm: () => {
      armed = true;
      targetStats = 0;
    },
    filesystem: {
      ...defaultTestFilesystem(),
      lstat: racedLstat,
    },
  };
}
function sizedFilesystem(
  sizeByPath: ReadonlyMap<string, bigint>,
): Phase3CheckpointFilesystem {
  const base = defaultTestFilesystem();
  const sizedLstat = (async (path) =>
    fakeSize(
      await lstat(path, { bigint: true }),
      sizeByPath.get(pathKey(path)),
    )) as Phase3CheckpointFilesystem["lstat"];
  return {
    ...base,
    lstat: sizedLstat,
    open: async (path, flags, mode) => {
      const handle = await open(path, flags, mode);
      return {
        write: async (buffer, offset, length, position) =>
          await handle.write(buffer, offset, length, position),
        sync: async () => await handle.sync(),
        close: async () => await handle.close(),
        stat: async () =>
          fakeSize(
            await handle.stat({ bigint: true }),
            sizeByPath.get(pathKey(path)),
          ),
        readFile: async () => await handle.readFile(),
      };
    },
  };
}

function fakeSize(
  metadata: BigIntStats,
  size: bigint | undefined,
): BigIntStats {
  if (size === undefined) return metadata;
  return Object.assign(
    Object.create(Object.getPrototypeOf(metadata) as object),
    metadata,
    { size },
  ) as BigIntStats;
}

function pathKey(
  path: Parameters<Phase3CheckpointFilesystem["lstat"]>[0],
): string {
  return typeof path === "string" ? path : path.toString();
}

async function initializeWithScanNames(count: number): Promise<void> {
  const root = await checkpointRoot();
  const fakeReaddir = (async (path) => {
    if (path === root)
      return Array.from(
        { length: count },
        (_value, index) => `unknown-${index}`,
      );
    return [];
  }) as Phase3CheckpointFilesystem["readdir"];
  const filesystem: Phase3CheckpointFilesystem = {
    ...defaultTestFilesystem(),
    readdir: fakeReaddir,
  };
  const store = new DurablePhase3Checkpoints(root, {
    durability: logicalDurability,
    filesystem,
  });
  await store.initialize();
}
