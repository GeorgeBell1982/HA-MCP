import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PHASE3_APPROVAL_KEY_BYTES,
  PHASE3_APPROVAL_KEY_IO_ATTEMPTS,
  Phase3ApprovalKeyError,
  loadPhase3ApprovalKey,
  phase3ApprovalKeyErrorCodes,
  provisionPhase3ApprovalKey,
  type Phase3ApprovalKeyErrorCode,
  type Phase3ApprovalKeyFileHandle,
  type Phase3ApprovalKeyFilesystem,
  type Phase3ApprovalKeyMetadata,
  type Phase3ApprovalKeyOptions,
} from "../src/phase3/approvalKey.js";
import { DurablePhase3ApprovalGrants } from "../src/phase3/durableApproval.js";

const UID = 1000;
const STATE_DIRECTORY = resolve(".phase3-approval-key-test-state");
const KEY_PATH = join(STATE_DIRECTORY, "approval.key");
const KEY_BYTES = Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES, 0x5a);
const FLAGS = Object.freeze({
  O_RDONLY: 1,
  O_DIRECTORY: 2,
  O_NOFOLLOW: 4,
  O_CREAT: 8,
  O_EXCL: 16,
  O_WRONLY: 32,
});
const PROCESS = Object.freeze({
  platform: "linux" as const,
  getuid: () => UID,
  geteuid: () => UID,
});

const fixedMessages: Readonly<Record<Phase3ApprovalKeyErrorCode, string>> =
  Object.freeze({
    approval_key_invalid: "Phase 3 approval key input is invalid",
    approval_key_missing: "Phase 3 approval key is missing",
    approval_key_exists: "Phase 3 approval key already exists",
    approval_key_unsafe: "Phase 3 approval key state is unsafe",
    approval_key_corrupt: "Phase 3 approval key is corrupt",
    approval_key_commit_unknown: "Phase 3 approval key commit is unknown",
    approval_key_io_failure: "Phase 3 approval key I/O failed",
  });

describe("Phase 3P approval key contract", () => {
  it("exports one closed fixed-message error without a cause", () => {
    expect(phase3ApprovalKeyErrorCodes).toEqual([
      "approval_key_invalid",
      "approval_key_missing",
      "approval_key_exists",
      "approval_key_unsafe",
      "approval_key_corrupt",
      "approval_key_commit_unknown",
      "approval_key_io_failure",
    ]);
    expect(Object.isFrozen(phase3ApprovalKeyErrorCodes)).toBe(true);
    for (const code of phase3ApprovalKeyErrorCodes) {
      const error = new Phase3ApprovalKeyError(code);
      expect(error).toMatchObject({
        name: "Phase3ApprovalKeyError",
        code,
        message: fixedMessages[code],
      });
      expect(Object.hasOwn(error, "cause")).toBe(false);
    }
  });

  it("provisions once with exact flags, persists only nonzero bytes, and wipes scratch", async () => {
    const filesystem = new FakeFilesystem();
    const scratch = Buffer.from(KEY_BYTES);
    Object.defineProperty(scratch, "byteLength", { value: 0 });
    await expect(
      provisionPhase3ApprovalKey(fakeOptions(filesystem, () => scratch)),
    ).resolves.toBeUndefined();

    expect(filesystem.key?.bytes).toEqual(KEY_BYTES);
    expectIndexedZero(scratch, PHASE3_APPROVAL_KEY_BYTES);
    expect(filesystem.opens).toEqual([
      {
        path: STATE_DIRECTORY,
        flags: FLAGS.O_RDONLY | FLAGS.O_DIRECTORY | FLAGS.O_NOFOLLOW,
        mode: undefined,
      },
      {
        path: KEY_PATH,
        flags: FLAGS.O_CREAT | FLAGS.O_EXCL | FLAGS.O_WRONLY | FLAGS.O_NOFOLLOW,
        mode: 0o600,
      },
    ]);
    expect(
      filesystem.events.filter((event) => event.startsWith("random")),
    ).toEqual([]);
  });

  it("loads existing-only into one exact frozen mutable lease and repeatedly wipes the same buffer", async () => {
    const filesystem = new FakeFilesystem(KEY_BYTES);
    const lease = await loadPhase3ApprovalKey(fakeOptions(filesystem));
    const reference = lease.key;

    expect(Reflect.ownKeys(lease)).toEqual(["key", "release"]);
    expect(Object.isFrozen(lease)).toBe(true);
    expect(Object.getOwnPropertyDescriptors(lease)).toMatchObject({
      key: {
        value: reference,
        writable: false,
        enumerable: true,
        configurable: false,
      },
      release: {
        writable: false,
        enumerable: true,
        configurable: false,
      },
    });
    expect(Buffer.isBuffer(reference)).toBe(true);
    expect(reference).toEqual(KEY_BYTES);
    reference[0] = 0x7f;
    expect(lease.release()).toBeUndefined();
    expect(reference).toEqual(Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES));
    for (let index = 0; index < PHASE3_APPROVAL_KEY_BYTES; index += 1)
      reference[index] = 0x6f;
    Object.defineProperty(reference, "byteLength", { value: 0 });
    Object.defineProperty(reference, "length", { value: 0 });
    Object.defineProperty(reference, "fill", {
      value: () => {
        throw new Error("caller fill canary");
      },
      configurable: true,
    });
    Object.setPrototypeOf(reference, null);
    expect(lease.release()).toBeUndefined();
    expectIndexedZero(reference, PHASE3_APPROVAL_KEY_BYTES);
    reference[PHASE3_APPROVAL_KEY_BYTES - 1] = 0x4f;
    expect(lease.release()).toBeUndefined();
    expectIndexedZero(reference, PHASE3_APPROVAL_KEY_BYTES);
  });

  it("opens successful loads with exact no-follow flags and rejects a regular-file-to-symlink substitution", async () => {
    const successful = new FakeFilesystem(KEY_BYTES);
    const lease = await loadPhase3ApprovalKey(fakeOptions(successful));
    expect(successful.opens).toEqual([
      {
        path: STATE_DIRECTORY,
        flags: FLAGS.O_RDONLY | FLAGS.O_DIRECTORY | FLAGS.O_NOFOLLOW,
        mode: undefined,
      },
      {
        path: KEY_PATH,
        flags: FLAGS.O_RDONLY | FLAGS.O_NOFOLLOW,
        mode: undefined,
      },
    ]);
    lease.release();

    const substituted = new FakeFilesystem(KEY_BYTES);
    substituted.hooks.set("key.open.read:1", () => {
      substituted.key!.metadata = keyMetadata({ kind: "other" });
    });
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(substituted)),
      "approval_key_unsafe",
    );
    expect(substituted.opens.at(-1)?.flags).toBe(
      FLAGS.O_RDONLY | FLAGS.O_NOFOLLOW,
    );
  });

  it("never creates on load and maps only initial key ENOENT to missing", async () => {
    const filesystem = new FakeFilesystem();
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(filesystem)),
      "approval_key_missing",
    );
    expect(filesystem.key).toBeUndefined();
    expect(filesystem.opens.some((entry) => entry.path === KEY_PATH)).toBe(
      false,
    );

    const disappeared = new FakeFilesystem(KEY_BYTES);
    disappeared.failures.set("key.open.read:1", errno("ENOENT"));
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(disappeared)),
      "approval_key_unsafe",
    );

    const finalDisappearance = new FakeFilesystem(KEY_BYTES);
    finalDisappearance.failures.set("key.lstat:2", errno("ENOENT"));
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(finalDisappearance)),
      "approval_key_unsafe",
    );
  });

  it("maps exclusive EEXIST, including a symlink-shaped artifact, to exists without inspection", async () => {
    for (const kind of ["regular", "other"] as const) {
      const filesystem = new FakeFilesystem(KEY_BYTES);
      filesystem.key!.metadata = keyMetadata({ kind });
      await expectCode(
        provisionPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_exists",
      );
      expect(
        filesystem.events.some((event) => event.startsWith("key.lstat")),
      ).toBe(false);
      expect(filesystem.key?.bytes).toEqual(KEY_BYTES);
    }
  });

  it("rejects invalid paths, platform, UID identity, flags, and random contracts before key effects", async () => {
    const cases: Array<Partial<Phase3ApprovalKeyOptions>> = [
      { stateDirectory: "relative", keyPath: "relative/approval.key" },
      { stateDirectory: STATE_DIRECTORY, keyPath: STATE_DIRECTORY },
      {
        stateDirectory: STATE_DIRECTORY,
        keyPath: join(dirname(STATE_DIRECTORY), "outside.key"),
      },
      {
        stateDirectory: `${STATE_DIRECTORY}${sep}..${sep}${dirname(STATE_DIRECTORY)}`,
        keyPath: KEY_PATH,
      },
      { stateDirectory: `${STATE_DIRECTORY}\0canary`, keyPath: KEY_PATH },
      {
        process: {
          platform: "win32",
          getuid: () => UID,
          geteuid: () => UID,
        },
      },
      {
        process: {
          platform: "linux",
          getuid: undefined,
          geteuid: () => UID,
        },
      },
      {
        process: {
          platform: "linux",
          getuid: () => UID,
          geteuid: () => UID + 1,
        },
      },
      {
        filesystem: Object.assign(new FakeFilesystem(), {
          flags: { ...FLAGS, O_NOFOLLOW: undefined },
        }),
      },
    ];

    for (const patch of cases) {
      const filesystem = new FakeFilesystem();
      let randomCalls = 0;
      await expectCode(
        provisionPhase3ApprovalKey({
          ...fakeOptions(filesystem, () => {
            randomCalls += 1;
            return Buffer.from(KEY_BYTES);
          }),
          ...patch,
        }),
        "approval_key_invalid",
      );
      expect(filesystem.events).toEqual([]);
      expect(randomCalls).toBe(0);
    }

    const flagGetterFilesystem = new FakeFilesystem();
    const hostileFlags = { ...FLAGS };
    Object.defineProperty(hostileFlags, "O_NOFOLLOW", {
      get: () => {
        throw new Error("flag getter canary");
      },
    });
    Object.defineProperty(flagGetterFilesystem, "flags", {
      value: hostileFlags,
    });
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(flagGetterFilesystem)),
      "approval_key_invalid",
    );
    expect(flagGetterFilesystem.events).toEqual([]);

    for (const scratch of [
      Buffer.alloc(31, 0x4a),
      Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES),
    ]) {
      const filesystem = new FakeFilesystem();
      await expectCode(
        provisionPhase3ApprovalKey(fakeOptions(filesystem, () => scratch)),
        "approval_key_invalid",
      );
      expect(scratch.every((byte) => byte === 0)).toBe(true);
      expect(filesystem.key).toBeUndefined();
    }

    const nonBuffer = new Uint8Array(PHASE3_APPROVAL_KEY_BYTES).fill(0x4a);
    await expectCode(
      provisionPhase3ApprovalKey(
        fakeOptions(new FakeFilesystem(), () => nonBuffer as unknown as Buffer),
      ),
      "approval_key_invalid",
    );
    expect(nonBuffer.every((byte) => byte === 0)).toBe(true);

    const malformedBuffer = Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES, 0x4b);
    const retainedView = new Uint8Array(
      malformedBuffer.buffer,
      malformedBuffer.byteOffset,
      malformedBuffer.byteLength,
    );
    Object.setPrototypeOf(malformedBuffer, null);
    expect(Buffer.isBuffer(malformedBuffer)).toBe(false);
    expect(malformedBuffer instanceof Uint8Array).toBe(false);
    await expectCode(
      provisionPhase3ApprovalKey(
        fakeOptions(new FakeFilesystem(), () => malformedBuffer),
      ),
      "approval_key_invalid",
    );
    expectIndexedZero(retainedView, PHASE3_APPROVAL_KEY_BYTES);

    const dataViewBacking = new ArrayBuffer(PHASE3_APPROVAL_KEY_BYTES);
    const dataViewBytes = new Uint8Array(dataViewBacking).fill(0x4c);
    const dataView = new DataView(dataViewBacking);
    await expectCode(
      provisionPhase3ApprovalKey(
        fakeOptions(new FakeFilesystem(), () => dataView as unknown as Buffer),
      ),
      "approval_key_invalid",
    );
    expectIndexedZero(dataViewBytes, PHASE3_APPROVAL_KEY_BYTES);
  });

  it("rejects unsafe parent metadata and initial descriptor/path substitution before randomness", async () => {
    for (const metadata of [
      directoryMetadata({ kind: "regular" }),
      directoryMetadata({ uid: BigInt(UID + 1) }),
      directoryMetadata({ mode: 0o40755n }),
    ]) {
      const filesystem = new FakeFilesystem();
      filesystem.directoryPathMetadata = metadata;
      let randomCalls = 0;
      await expectCode(
        provisionPhase3ApprovalKey(
          fakeOptions(filesystem, () => {
            randomCalls += 1;
            return Buffer.from(KEY_BYTES);
          }),
        ),
        "approval_key_unsafe",
      );
      expect(randomCalls).toBe(0);
    }

    const descriptorSwap = new FakeFilesystem();
    descriptorSwap.directoryDescriptorMetadata = directoryMetadata({
      ino: 99n,
    });
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(descriptorSwap)),
      "approval_key_unsafe",
    );

    const pathSwap = new FakeFilesystem();
    pathSwap.hooks.set("directory.lstat:2", () => {
      pathSwap.directoryPathMetadata = directoryMetadata({ ino: 99n });
    });
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(pathSwap)),
      "approval_key_unsafe",
    );
  });

  it("rejects key type, owner, mode, links, wrong size, zero bytes, and static identity substitution", async () => {
    for (const metadata of [
      keyMetadata({ kind: "other" }),
      keyMetadata({ uid: BigInt(UID + 1) }),
      keyMetadata({ mode: 0o100640n }),
      keyMetadata({ nlink: 2n }),
    ]) {
      const filesystem = new FakeFilesystem(KEY_BYTES);
      filesystem.key!.metadata = metadata;
      await expectCode(
        loadPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_unsafe",
      );
    }

    for (const size of [31n, 33n]) {
      const filesystem = new FakeFilesystem(KEY_BYTES);
      filesystem.key!.metadata = keyMetadata({ size });
      await expectCode(
        loadPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_corrupt",
      );
    }

    await expectCode(
      loadPhase3ApprovalKey(
        fakeOptions(
          new FakeFilesystem(Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES)),
        ),
      ),
      "approval_key_corrupt",
    );

    const descriptorSwap = new FakeFilesystem(KEY_BYTES);
    descriptorSwap.hooks.set("key.stat:1", () => {
      descriptorSwap.key!.metadata = keyMetadata({ ino: 99n });
    });
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(descriptorSwap)),
      "approval_key_unsafe",
    );
  });

  it("detects post-read key drift, final path substitution, and parent substitution", async () => {
    const postRead = new FakeFilesystem(KEY_BYTES);
    postRead.hooks.set("key.stat:2", () => {
      postRead.key!.metadata = keyMetadata({ ino: 70n });
    });
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(postRead)),
      "approval_key_unsafe",
    );

    const finalPath = new FakeFilesystem(KEY_BYTES);
    finalPath.hooks.set("key.lstat:2", () => {
      finalPath.key!.metadata = keyMetadata({ ino: 71n });
    });
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(finalPath)),
      "approval_key_unsafe",
    );

    const parent = new FakeFilesystem(KEY_BYTES);
    parent.hooks.set("directory.lstat:3", () => {
      parent.directoryPathMetadata = directoryMetadata({ ino: 72n });
    });
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(parent)),
      "approval_key_unsafe",
    );
  });

  it("handles bounded short writes and EINTR, and rejects no-progress, overrun, and exhaustion", async () => {
    const short = new FakeFilesystem();
    short.writeScript.push(7, 25);
    await expect(
      provisionPhase3ApprovalKey(fakeOptions(short)),
    ).resolves.toBeUndefined();
    expect(short.key?.bytes).toEqual(KEY_BYTES);

    const interrupted = new FakeFilesystem();
    interrupted.writeScript.push(
      errno("EINTR"),
      errno("EINTR"),
      PHASE3_APPROVAL_KEY_BYTES,
    );
    await expect(
      provisionPhase3ApprovalKey(fakeOptions(interrupted)),
    ).resolves.toBeUndefined();

    for (const script of [
      [0],
      [PHASE3_APPROVAL_KEY_BYTES + 1],
      Array.from({ length: PHASE3_APPROVAL_KEY_IO_ATTEMPTS }, () =>
        errno("EINTR"),
      ),
    ]) {
      const filesystem = new FakeFilesystem();
      filesystem.writeScript.push(...script);
      await expectCode(
        provisionPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_commit_unknown",
      );
      expect(filesystem.key).toBeDefined();
    }
  });

  it("maps unsafe post-write descriptor metadata and final key identity substitution to commit unknown", async () => {
    for (const patch of [
      { kind: "other" as const },
      { uid: BigInt(UID + 1) },
      { mode: 0o100640n },
      { nlink: 2n },
      { size: 31n },
    ]) {
      const filesystem = new FakeFilesystem();
      filesystem.hooks.set("key.stat:1", () => {
        filesystem.key!.metadata = keyMetadata(patch);
      });
      await expectCode(
        provisionPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_commit_unknown",
      );
      expect(filesystem.key?.bytes).toEqual(KEY_BYTES);
    }

    const substituted = new FakeFilesystem();
    substituted.hooks.set("key.lstat:1", () => {
      substituted.key!.metadata = keyMetadata({ dev: 9n, ino: 90n });
    });
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(substituted)),
      "approval_key_commit_unknown",
    );
    expect(substituted.key?.bytes).toEqual(KEY_BYTES);
  });

  it("handles bounded short reads and EINTR, and rejects no-progress, overrun, truncation, and trailing data", async () => {
    const short = new FakeFilesystem(KEY_BYTES);
    short.readScript.push(7, 25, 0);
    const shortLease = await loadPhase3ApprovalKey(fakeOptions(short));
    expect(shortLease.key).toEqual(KEY_BYTES);
    shortLease.release();

    const interrupted = new FakeFilesystem(KEY_BYTES);
    interrupted.readScript.push(
      errno("EINTR"),
      errno("EINTR"),
      PHASE3_APPROVAL_KEY_BYTES,
      0,
    );
    const interruptedLease = await loadPhase3ApprovalKey(
      fakeOptions(interrupted),
    );
    interruptedLease.release();

    const noProgress = new FakeFilesystem(KEY_BYTES);
    noProgress.readScript.push(0);
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(noProgress)),
      "approval_key_corrupt",
    );

    const overrun = new FakeFilesystem(KEY_BYTES);
    overrun.readScript.push(PHASE3_APPROVAL_KEY_BYTES + 1);
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(overrun)),
      "approval_key_io_failure",
    );

    const exhausted = new FakeFilesystem(KEY_BYTES);
    exhausted.readScript.push(
      ...Array.from({ length: PHASE3_APPROVAL_KEY_IO_ATTEMPTS }, () =>
        errno("EINTR"),
      ),
    );
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(exhausted)),
      "approval_key_io_failure",
    );

    const truncated = new FakeFilesystem(Buffer.alloc(10, 0x5a));
    truncated.key!.metadata = keyMetadata();
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(truncated)),
      "approval_key_corrupt",
    );

    const trailing = new FakeFilesystem(Buffer.alloc(33, 0x5a));
    trailing.key!.metadata = keyMetadata();
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(trailing)),
      "approval_key_corrupt",
    );
  });

  it("classifies every provision filesystem boundary by pre/post exclusive-open state", async () => {
    const baseline = new FakeFilesystem();
    await provisionPhase3ApprovalKey(fakeOptions(baseline));
    const createIndex = baseline.events.findIndex((event) =>
      event.startsWith("key.open.create"),
    );
    expect(createIndex).toBeGreaterThan(-1);

    for (const [index, event] of baseline.events.entries()) {
      const filesystem = new FakeFilesystem();
      filesystem.failures.set(event, errno("EIO", `canary ${event}`));
      const expected =
        index > createIndex
          ? "approval_key_commit_unknown"
          : "approval_key_io_failure";
      await expectCode(
        provisionPhase3ApprovalKey(fakeOptions(filesystem)),
        expected,
      );
      if (event.startsWith("key.close"))
        expect(
          filesystem.events.filter((seen) => seen.startsWith("key.close")),
        ).toHaveLength(1);
      if (event.startsWith("directory.close"))
        expect(
          filesystem.events.filter((seen) =>
            seen.startsWith("directory.close"),
          ),
        ).toHaveLength(1);
    }
  });

  it("classifies every load filesystem boundary as I/O and never returns a lease", async () => {
    const baseline = new FakeFilesystem(KEY_BYTES);
    const lease = await loadPhase3ApprovalKey(fakeOptions(baseline));
    lease.release();

    for (const event of baseline.events) {
      const filesystem = new FakeFilesystem(KEY_BYTES);
      filesystem.failures.set(event, errno("EIO", `canary ${event}`));
      await expectCode(
        loadPhase3ApprovalKey(fakeOptions(filesystem)),
        "approval_key_io_failure",
      );
      if (event.startsWith("key.close"))
        expect(
          filesystem.events.filter((seen) => seen.startsWith("key.close")),
        ).toHaveLength(1);
      if (event.startsWith("directory.close"))
        expect(
          filesystem.events.filter((seen) =>
            seen.startsWith("directory.close"),
          ),
        ).toHaveLength(1);
      for (const target of filesystem.readTargets)
        expect(target.every((byte) => byte === 0)).toBe(true);
    }
  });

  it("preserves first-primary precedence through cleanup and wipes failed candidates", async () => {
    const corrupt = new FakeFilesystem(Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES));
    corrupt.failures.set("key.close:1", errno("EIO", "close canary"));
    corrupt.failures.set("directory.close:1", errno("EIO", "directory canary"));
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(corrupt)),
      "approval_key_corrupt",
    );

    const afterRead = new FakeFilesystem(KEY_BYTES);
    afterRead.failures.set("key.stat:2", errno("EIO", "post-read canary"));
    await expectCode(
      loadPhase3ApprovalKey(fakeOptions(afterRead)),
      "approval_key_io_failure",
    );
    expect(afterRead.readTargets).toHaveLength(2);
    expect(afterRead.readTargets[0]!.every((byte) => byte === 0)).toBe(true);

    const invalid = new FakeFilesystem();
    invalid.failures.set("directory.close:1", errno("EIO", "cleanup canary"));
    await expectCode(
      provisionPhase3ApprovalKey(
        fakeOptions(invalid, () => Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES)),
      ),
      "approval_key_invalid",
    );

    const postClaim = new FakeFilesystem();
    postClaim.writeScript.push(0);
    postClaim.failures.set("key.close:1", errno("EIO", "key close canary"));
    postClaim.failures.set(
      "directory.close:1",
      errno("EIO", "directory close canary"),
    );
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(postClaim)),
      "approval_key_commit_unknown",
    );
  });

  it("sanitizes injected filesystem, random, and process text", async () => {
    const canary = `${KEY_PATH}:random-secret-canary`;
    const boundaries: Array<Promise<unknown>> = [];

    const filesystem = new FakeFilesystem();
    filesystem.failures.set("directory.lstat:1", errno("EIO", canary));
    boundaries.push(provisionPhase3ApprovalKey(fakeOptions(filesystem)));
    boundaries.push(
      provisionPhase3ApprovalKey(
        fakeOptions(new FakeFilesystem(), () => {
          throw new Error(canary);
        }),
      ),
    );
    boundaries.push(
      provisionPhase3ApprovalKey({
        ...fakeOptions(new FakeFilesystem()),
        process: {
          platform: "linux",
          getuid: () => {
            throw new Error(canary);
          },
          geteuid: () => UID,
        },
      }),
    );

    for (const promise of boundaries) {
      const error = await rejected(promise);
      expect(error).toBeInstanceOf(Phase3ApprovalKeyError);
      expect(String(error)).not.toContain(canary);
      expect(JSON.stringify(error)).not.toContain(canary);
      expect((error as Error).stack ?? "").not.toContain(canary);
      expect(Object.hasOwn(error as object, "cause")).toBe(false);
    }
  });

  it("leaves commit-unknown artifacts untouched; retry is exists and load is readability-only", async () => {
    const filesystem = new FakeFilesystem();
    filesystem.failures.set("key.sync:1", errno("EIO"));
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(filesystem)),
      "approval_key_commit_unknown",
    );
    expect(filesystem.key?.bytes).toEqual(KEY_BYTES);

    filesystem.failures.clear();
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(filesystem)),
      "approval_key_exists",
    );
    const lease = await loadPhase3ApprovalKey(fakeOptions(filesystem));
    expect(lease.key).toEqual(KEY_BYTES);
    lease.release();
  });

  it("allows only a readability lease in the deterministic pre-sync race, then reports commit unknown", async () => {
    const filesystem = new FakeFilesystem();
    const syncEntered = deferred<void>();
    const releaseSync = deferred<void>();
    filesystem.hooks.set("key.sync:1", async () => {
      syncEntered.resolve();
      await releaseSync.promise;
      throw errno("EIO");
    });

    const provision = provisionPhase3ApprovalKey(fakeOptions(filesystem));
    await syncEntered.promise;
    const lease = await loadPhase3ApprovalKey(fakeOptions(filesystem));
    expect(lease.key).toEqual(KEY_BYTES);
    releaseSync.resolve();
    await expectCode(provision, "approval_key_commit_unknown");
    lease.release();
  });

  it("has exact contention outcomes: one provision success and one exists", async () => {
    const filesystem = new FakeFilesystem();
    const results = await Promise.allSettled([
      provisionPhase3ApprovalKey(fakeOptions(filesystem)),
      provisionPhase3ApprovalKey(fakeOptions(filesystem)),
    ]);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejection = results.find(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    expect(rejection?.reason).toMatchObject({ code: "approval_key_exists" });
    expect(filesystem.key?.bytes).toEqual(KEY_BYTES);
  });

  it("turns persistent parent substitution after create into commit unknown", async () => {
    const filesystem = new FakeFilesystem();
    filesystem.hooks.set("directory.lstat:4", () => {
      filesystem.directoryPathMetadata = directoryMetadata({ ino: 81n });
    });
    await expectCode(
      provisionPhase3ApprovalKey(fakeOptions(filesystem)),
      "approval_key_commit_unknown",
    );
    expect(filesystem.key?.bytes).toEqual(KEY_BYTES);
  });
});

const nativeRoots: string[] = [];
const nativeAvailable =
  process.platform === "linux" &&
  process.getuid !== undefined &&
  process.geteuid !== undefined &&
  process.getuid() === process.geteuid();

describe.skipIf(!nativeAvailable)(
  "Phase 3P native Linux syscall evidence",
  () => {
    afterEach(async () => {
      const roots = nativeRoots.splice(0);
      for (const root of roots) {
        await rm(root, { recursive: true });
        await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
      }
    });

    it("uses native O_EXCL contention and returns a stable load lease", async () => {
      const stateDirectory = await nativeStateDirectory();
      const keyPath = join(stateDirectory, "approval.key");
      const options = { stateDirectory, keyPath };
      const results = await Promise.allSettled([
        provisionPhase3ApprovalKey(options),
        provisionPhase3ApprovalKey(options),
      ]);

      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        results.find(
          (result): result is PromiseRejectedResult =>
            result.status === "rejected",
        )?.reason,
      ).toMatchObject({ code: "approval_key_exists" });
      const bytes = await readFile(keyPath);
      expect(bytes).toHaveLength(PHASE3_APPROVAL_KEY_BYTES);
      expect(bytes.some((byte) => byte !== 0)).toBe(true);
      const lease = await loadPhase3ApprovalKey(options);
      expect(lease.key).toEqual(bytes);
      lease.release();
    });

    it("provides native nofollow, symlink, and mode evidence", async () => {
      const stateDirectory = await nativeStateDirectory();
      const keyPath = join(stateDirectory, "approval.key");
      const target = join(dirname(stateDirectory), "symlink-target");
      await writeFile(target, KEY_BYTES, { flag: "wx", mode: 0o600 });
      await symlink(target, keyPath);

      await expectCode(
        provisionPhase3ApprovalKey({ stateDirectory, keyPath }),
        "approval_key_exists",
      );
      await expectCode(
        loadPhase3ApprovalKey({ stateDirectory, keyPath }),
        "approval_key_unsafe",
      );

      const modeRoot = await nativeStateDirectory();
      const modeKey = join(modeRoot, "approval.key");
      await provisionPhase3ApprovalKey({
        stateDirectory: modeRoot,
        keyPath: modeKey,
      });
      await chmod(modeKey, 0o640);
      await expectCode(
        loadPhase3ApprovalKey({
          stateDirectory: modeRoot,
          keyPath: modeKey,
        }),
        "approval_key_unsafe",
      );
    });

    it("bridges only after known provision success to a distinct pre-existing durable-store root", async () => {
      const parent = await nativeParent("phase3-key-bridge-");
      const stateDirectory = join(parent, "key-state");
      const storeRoot = join(parent, "approval-store");
      await mkdir(stateDirectory, { mode: 0o700 });
      await mkdir(storeRoot, { mode: 0o700 });
      expect(dirname(storeRoot)).toBe(dirname(stateDirectory));
      expect(storeRoot.startsWith(`${stateDirectory}${sep}`)).toBe(false);
      expect(stateDirectory.startsWith(`${storeRoot}${sep}`)).toBe(false);

      const keyPath = join(stateDirectory, "approval.key");
      await provisionPhase3ApprovalKey({ stateDirectory, keyPath });
      const lease = await loadPhase3ApprovalKey({ stateDirectory, keyPath });
      const storeA = new DurablePhase3ApprovalGrants(storeRoot, lease.key);
      const storeB = new DurablePhase3ApprovalGrants(storeRoot, lease.key);
      const wrongKey = Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES, 0x3c);
      const wrong = new DurablePhase3ApprovalGrants(storeRoot, wrongKey);
      try {
        await storeA.initialize();
        await storeB.initialize();
        await expect(wrong.initialize()).rejects.toMatchObject({
          code: "approval_store_unhealthy",
        });
      } finally {
        await wrong.close();
        await storeB.close();
        await storeA.close();
        expect(lease.key.some((byte) => byte !== 0)).toBe(true);
        lease.release();
      }
      expect(lease.key).toEqual(Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES));
      expect(wrongKey).toEqual(Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES, 0x3c));
    });
  },
);

function fakeOptions(
  filesystem: FakeFilesystem,
  randomBytes: () => Buffer = () => Buffer.from(KEY_BYTES),
): Phase3ApprovalKeyOptions {
  return {
    stateDirectory: STATE_DIRECTORY,
    keyPath: KEY_PATH,
    filesystem,
    randomBytes,
    process: PROCESS,
  };
}

async function expectCode(
  promise: Promise<unknown>,
  code: Phase3ApprovalKeyErrorCode,
): Promise<void> {
  const error = await rejected(promise);
  expect(error).toBeInstanceOf(Phase3ApprovalKeyError);
  expect(error).toMatchObject({
    code,
    message: fixedMessages[code],
  });
}

async function rejected(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected promise rejection");
}

function errno(code: string, message = `injected ${code}`): Error {
  return Object.assign(new Error(message), { code });
}

function directoryMetadata(
  patch: Partial<Phase3ApprovalKeyMetadata> = {},
): Phase3ApprovalKeyMetadata {
  return {
    dev: 1n,
    ino: 1n,
    mode: 0o40700n,
    uid: BigInt(UID),
    nlink: 2n,
    size: 0n,
    kind: "directory",
    ...patch,
  };
}

function keyMetadata(
  patch: Partial<Phase3ApprovalKeyMetadata> = {},
): Phase3ApprovalKeyMetadata {
  return {
    dev: 1n,
    ino: 2n,
    mode: 0o100600n,
    uid: BigInt(UID),
    nlink: 1n,
    size: BigInt(PHASE3_APPROVAL_KEY_BYTES),
    kind: "regular",
    ...patch,
  };
}

interface FakeKey {
  bytes: Buffer;
  metadata: Phase3ApprovalKeyMetadata;
}

type ScriptResult = number | Error;

class FakeFilesystem implements Phase3ApprovalKeyFilesystem {
  readonly flags = FLAGS;
  readonly events: string[] = [];
  readonly opens: Array<{
    readonly path: string;
    readonly flags: number;
    readonly mode: number | undefined;
  }> = [];
  readonly failures = new Map<string, Error>();
  readonly hooks = new Map<string, () => void | Promise<void>>();
  readonly writeScript: ScriptResult[] = [];
  readonly readScript: ScriptResult[] = [];
  readonly readTargets: Buffer[] = [];
  directoryPathMetadata = directoryMetadata();
  directoryDescriptorMetadata = directoryMetadata();
  key: FakeKey | undefined;
  private readonly counts = new Map<string, number>();

  constructor(bytes?: Buffer) {
    if (bytes !== undefined)
      this.key = {
        bytes: Buffer.from(bytes),
        metadata: keyMetadata({ size: BigInt(bytes.byteLength) }),
      };
  }

  async lstat(path: string): Promise<Phase3ApprovalKeyMetadata> {
    if (path === STATE_DIRECTORY) {
      await this.event("directory.lstat");
      return { ...this.directoryPathMetadata };
    }
    if (path === KEY_PATH) {
      await this.event("key.lstat");
      if (this.key === undefined) throw errno("ENOENT");
      return { ...this.key.metadata };
    }
    throw errno("ENOENT");
  }

  async open(
    path: string,
    flags: number,
    mode?: number,
  ): Promise<Phase3ApprovalKeyFileHandle> {
    this.opens.push({ path, flags, mode });
    if (path === STATE_DIRECTORY) {
      await this.event("directory.open");
      return this.directoryHandle();
    }
    if (path !== KEY_PATH) throw errno("ENOENT");
    const create = (flags & FLAGS.O_CREAT) !== 0;
    if (create) {
      await this.event("key.open.create");
      if (this.key !== undefined) throw errno("EEXIST");
      this.key = {
        bytes: Buffer.alloc(0),
        metadata: keyMetadata({ size: 0n }),
      };
      return this.keyHandle(true);
    }
    await this.event("key.open.read");
    if (this.key === undefined) throw errno("ENOENT");
    if (
      this.key.metadata.kind !== "regular" &&
      (flags & FLAGS.O_NOFOLLOW) !== 0
    )
      throw errno("ELOOP");
    return this.keyHandle(false);
  }

  private directoryHandle(): Phase3ApprovalKeyFileHandle {
    return {
      read: async () => {
        await this.event("directory.read");
        return { bytesRead: 0 };
      },
      write: async () => {
        await this.event("directory.write");
        return { bytesWritten: 0 };
      },
      sync: async () => {
        await this.event("directory.sync");
      },
      stat: async () => {
        await this.event("directory.stat");
        return { ...this.directoryDescriptorMetadata };
      },
      close: async () => {
        await this.event("directory.close");
      },
    };
  }

  private keyHandle(writable: boolean): Phase3ApprovalKeyFileHandle {
    return {
      read: async (buffer, offset, length, position) => {
        await this.event("key.read");
        const target = buffer as Buffer;
        this.readTargets.push(target);
        const scripted = this.readScript.shift();
        if (scripted instanceof Error) throw scripted;
        const available = Math.max(
          0,
          (this.key?.bytes.byteLength ?? 0) - position,
        );
        const bytesRead =
          scripted === undefined ? Math.min(length, available) : scripted;
        if (bytesRead <= length && bytesRead <= available && this.key)
          this.key.bytes.copy(target, offset, position, position + bytesRead);
        return { bytesRead };
      },
      write: async (buffer, offset, length, position) => {
        await this.event("key.write");
        if (!writable || this.key === undefined) throw errno("EBADF");
        const scripted = this.writeScript.shift();
        if (scripted instanceof Error) throw scripted;
        const bytesWritten = scripted === undefined ? length : scripted;
        if (bytesWritten <= length) {
          const required = position + bytesWritten;
          if (this.key.bytes.byteLength < required) {
            const expanded = Buffer.alloc(required);
            this.key.bytes.copy(expanded);
            this.key.bytes = expanded;
          }
          Buffer.from(buffer).copy(
            this.key.bytes,
            position,
            offset,
            offset + bytesWritten,
          );
          this.key.metadata = {
            ...this.key.metadata,
            size: BigInt(this.key.bytes.byteLength),
          };
        }
        return { bytesWritten };
      },
      sync: async () => {
        await this.event("key.sync");
      },
      stat: async () => {
        await this.event("key.stat");
        if (this.key === undefined) throw errno("ENOENT");
        return { ...this.key.metadata };
      },
      close: async () => {
        await this.event("key.close");
      },
    };
  }

  private async event(name: string): Promise<void> {
    const count = (this.counts.get(name) ?? 0) + 1;
    this.counts.set(name, count);
    const token = `${name}:${count}`;
    this.events.push(token);
    const hook = this.hooks.get(token);
    if (hook !== undefined) await hook();
    const failure = this.failures.get(token);
    if (failure !== undefined) throw failure;
  }
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value?: T) => void;
} {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolvePromiseValue) => {
    resolvePromise = resolvePromiseValue;
  });
  return {
    promise,
    resolve: (value?: T) => {
      if (resolvePromise === undefined)
        throw new Error("deferred is unavailable");
      const resolveNow = resolvePromise;
      resolvePromise = undefined;
      resolveNow(value as T);
    },
  };
}

async function nativeStateDirectory(): Promise<string> {
  const parent = await nativeParent("phase3-approval-key-");
  const stateDirectory = join(parent, "state");
  await mkdir(stateDirectory, { mode: 0o700 });
  return stateDirectory;
}

async function nativeParent(prefix: string): Promise<string> {
  const parent = await mkdtemp(join(tmpdir(), prefix));
  nativeRoots.push(parent);
  await chmod(parent, 0o700);
  return parent;
}

function expectIndexedZero(bytes: Uint8Array, byteLength: number): void {
  for (let index = 0; index < byteLength; index += 1)
    expect(bytes[index]).toBe(0);
}
