import { EventEmitter } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  PHASE3_APPROVAL_CUSTODY_LIMITS,
  Phase3ApprovalCustodyError,
  createLinuxPhase3ApprovalCustodyProvider,
  type Phase3ApprovalCustodyChild,
  type Phase3ApprovalCustodyMetadata,
  type Phase3ApprovalCustodyRunner,
} from "../src/phase3/approvalCustody.js";
import {
  DurablePhase3ApprovalGrants,
  type Phase3ApprovalCustodyLease,
} from "../src/phase3/durableApproval.js";

const ROOT = resolve("phase3-custody-root");
const HELPER = resolve("phase3-custody-helper");
const UID = 1000n;
const FS_TYPE = 0xef53n;
const rootMetadata = metadata({
  kind: "directory",
  mode: 0o040700n,
  size: 0n,
});
const helperMetadata = metadata({
  kind: "regular",
  mode: 0o100700n,
  ino: 2n,
  size: 42n,
});

const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map(async (path) => {
      await rm(path, { recursive: true, force: true });
    }),
  );
});

describe("Phase 3O conditional Linux approval custody", () => {
  it("U001 actual-platform real-runner gate", async () => {
    expect(() =>
      createLinuxPhase3ApprovalCustodyProvider({
        helperPath: HELPER,
        platform: "linux",
      }),
    ).toThrowError(Phase3ApprovalCustodyError);
    const runner = new FakeRunner();
    const provider = providerFor(runner, { platform: "win32" });
    await expect(provider(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
    expect(runner.spawnCalls).toHaveLength(0);
  });

  it("U002 root validation", async () => {
    const runner = new FakeRunner();
    const provider = providerFor(runner);
    await expect(provider("relative")).rejects.toMatchObject({
      code: "startup_failed",
    });
    runner.setMetadata(ROOT, [{ ...rootMetadata, mode: 0o040755n }]);
    await expect(provider(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
    expect(runner.spawnCalls).toHaveLength(0);
  });

  it("U003 helper path validation", () => {
    expect(() =>
      createLinuxPhase3ApprovalCustodyProvider({
        helperPath: "relative",
        runner: new FakeRunner(),
        platform: "linux",
      }),
    ).toThrowError(Phase3ApprovalCustodyError);
    expect(() =>
      createLinuxPhase3ApprovalCustodyProvider({
        helperPath: `${HELPER}\0canary`,
        runner: new FakeRunner(),
        platform: "linux",
      }),
    ).toThrowError(Phase3ApprovalCustodyError);
  });

  it("U004 helper symlink rejection", async () => {
    const runner = new FakeRunner();
    runner.setMetadata(HELPER, [{ ...helperMetadata, kind: "other" }]);
    await expect(providerFor(runner)(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
    expect(runner.spawnCalls).toHaveLength(0);
  });

  it("U005 helper nonregular rejection", async () => {
    const runner = new FakeRunner();
    runner.setMetadata(HELPER, [{ ...helperMetadata, kind: "directory" }]);
    await expect(providerFor(runner)(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
  });

  it("U006 helper owner mode and link-count rejection", async () => {
    for (const unsafe of [
      { ...helperMetadata, uid: UID + 1n },
      { ...helperMetadata, mode: 0o100722n },
      { ...helperMetadata, mode: 0o100600n },
      { ...helperMetadata, nlink: 2n },
    ]) {
      const runner = new FakeRunner();
      runner.setMetadata(HELPER, [unsafe]);
      await expect(providerFor(runner)(ROOT)).rejects.toMatchObject({
        code: "startup_failed",
      });
      expect(runner.spawnCalls).toHaveLength(0);
    }
  });

  it("U007 exact ready frame and clean release", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    child.stdout.write(readyFrame());
    const lease = await acquired;
    const release = lease.release();
    expect(child.stdinBytes()).toEqual(Buffer.from([0x52]));
    child.finish(0, null);
    await expect(release).resolves.toBeUndefined();
    expect(runner.spawnCalls).toEqual([
      { helperPath: HELPER, root: ROOT, parentPid: process.pid },
    ]);
  });

  it("U008 matching failure frame and exit", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    child.stdout.write(failureFrame("filesystem_unsupported"));
    child.finish(67, null);
    await expect(acquired).rejects.toMatchObject({
      code: "startup_failed",
      helperCode: "filesystem_unsupported",
      message: "Approval custody helper failed during startup",
    });
  });

  it("U009 numeric and frame canonicality", async () => {
    const invalidFrames = [
      readyFrame().replace("dev=1", "dev=01"),
      readyFrame().replace("ctime_nsec=3", "ctime_nsec=1000000000"),
      readyFrame().replace("\n", "\ntrailing"),
      failureFrame("filesystem_unsupported").replace(
        "filesystem_unsupported",
        "unknown",
      ),
      readyFrame().replace("ino=1", `ino=${"9".repeat(21)}`),
    ];
    for (const frame of invalidFrames) {
      const runner = new FakeRunner();
      const child = runner.enqueue();
      const acquired = providerFor(runner)(ROOT);
      child.stdout.write(frame);
      child.finish(71, null);
      await expect(acquired).rejects.toMatchObject({ code: "protocol" });
    }
  });

  it("U010 stdout and stderr bounds", async () => {
    {
      const runner = new FakeRunner();
      const child = runner.enqueue();
      const acquired = providerFor(runner)(ROOT);
      child.stdout.write(Buffer.alloc(513, 0x61));
      child.finish(71, null);
      await expect(acquired).rejects.toMatchObject({ code: "protocol" });
    }
    {
      const runner = new FakeRunner();
      const child = runner.enqueue();
      const acquired = providerFor(runner)(ROOT);
      child.stderr.write(Buffer.alloc(1025, 0x61));
      child.finish(71, null);
      await expect(acquired).rejects.toMatchObject({ code: "protocol" });
    }
  });

  it("U011 pre-ready and post-ready root drift", async () => {
    const runner = new FakeRunner();
    runner.setMetadata(ROOT, [
      rootMetadata,
      { ...rootMetadata, ino: rootMetadata.ino + 1n },
    ]);
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    child.stdout.write(readyFrame());
    await flush();
    child.finish(null, "SIGTERM");
    await expect(acquired).rejects.toMatchObject({ code: "protocol" });

    const fsRunner = new FakeRunner();
    fsRunner.fsTypes = [FS_TYPE, 0x01021994n];
    const fsChild = fsRunner.enqueue();
    const fsAcquired = providerFor(fsRunner)(ROOT);
    fsChild.stdout.write(readyFrame());
    await flush();
    fsChild.finish(71, null);
    await expect(fsAcquired).rejects.toMatchObject({ code: "protocol" });

    const deferredRunner = new FakeRunner();
    const deferredRoot = deferred<Phase3ApprovalCustodyMetadata>();
    deferredRunner.setMetadata(ROOT, [rootMetadata, deferredRoot.promise]);
    const deferredChild = deferredRunner.enqueue();
    deferredChild.killResult = (signal) => {
      if (signal === "SIGTERM")
        queueMicrotask(() => deferredChild.finish(null, "SIGTERM"));
      return true;
    };
    const deferredAcquisition = providerFor(deferredRunner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    })(ROOT);
    deferredChild.stdout.write(readyFrame());
    await expect(deferredAcquisition).rejects.toMatchObject({
      code: "timeout",
    });
    deferredRoot.resolve(rootMetadata);
    await flush();
    expect(deferredChild.kills).toEqual(["SIGTERM"]);

    const deferredFailureCases: ReadonlyArray<{
      readonly name: string;
      readonly fail: (child: FakeChild) => void;
    }> = [
      {
        name: "trailing stdout",
        fail: (pendingChild) => pendingChild.stdout.write("trailing"),
      },
      {
        name: "stderr",
        fail: (pendingChild) => pendingChild.stderr.write("failure"),
      },
      {
        name: "child error",
        fail: (pendingChild) =>
          pendingChild.emit(
            "error",
            Object.assign(new Error("canary"), { code: "EIO" }),
          ),
      },
      {
        name: "stdin error",
        fail: (pendingChild) =>
          pendingChild.stdin.emit(
            "error",
            Object.assign(new Error("canary"), { code: "EPIPE" }),
          ),
      },
    ];
    for (const failureCase of deferredFailureCases) {
      const pendingRunner = new FakeRunner();
      const pendingRoot = deferred<Phase3ApprovalCustodyMetadata>();
      pendingRunner.setMetadata(ROOT, [rootMetadata, pendingRoot.promise]);
      const pendingChild = pendingRunner.enqueue();
      pendingChild.killResult = () => true;
      let leaseResolved = false;
      const pendingAcquisition = providerFor(pendingRunner, {
        operationTimeoutMs: 100,
        terminationGraceMs: 10,
      })(ROOT);
      void pendingAcquisition.then(
        () => {
          leaseResolved = true;
        },
        () => undefined,
      );
      pendingChild.stdout.write(readyFrame());
      await flush();
      failureCase.fail(pendingChild);
      pendingRoot.resolve(rootMetadata);
      await expect(pendingAcquisition, failureCase.name).rejects.toMatchObject({
        code: "cleanup_unproved",
      });
      expect(leaseResolved, failureCase.name).toBe(false);
      expect(pendingChild.kills, failureCase.name).toEqual([
        "SIGTERM",
        "SIGKILL",
      ]);
      pendingChild.finish(null, "SIGKILL");
    }

    const ignoredTimeoutRunner = new FakeRunner();
    const ignoredTimeoutRoot = deferred<Phase3ApprovalCustodyMetadata>();
    ignoredTimeoutRunner.setMetadata(ROOT, [
      rootMetadata,
      ignoredTimeoutRoot.promise,
    ]);
    const ignoredTimeoutChild = ignoredTimeoutRunner.enqueue();
    ignoredTimeoutChild.killResult = () => true;
    const ignoredTimeoutAcquisition = providerFor(ignoredTimeoutRunner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    })(ROOT);
    ignoredTimeoutChild.stdout.write(readyFrame());
    await expect(ignoredTimeoutAcquisition).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(ignoredTimeoutChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    ignoredTimeoutRoot.resolve(rootMetadata);
    await flush();
    expect(ignoredTimeoutChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    ignoredTimeoutChild.finish(null, "SIGKILL");
  });

  it("U012 synchronous spawn throw", async () => {
    const runner = new FakeRunner();
    runner.spawnError = new Error("spawn canary");
    await expect(providerFor(runner)(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
      message: "Approval custody helper failed during startup",
    });
  });

  it("U013 missing PID remains tracked until close", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    child.pid = undefined;
    const acquired = providerFor(runner)(ROOT);
    child.finish(null, null);
    await expect(acquired).rejects.toMatchObject({ code: "startup_failed" });
    expect(child.kills).toHaveLength(0);
  });

  it("U014 error-before-close waits for close", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    let settled = false;
    void acquired.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    child.emit("error", Object.assign(new Error("canary"), { code: "ENOENT" }));
    await flush();
    expect(settled).toBe(false);
    child.finish(null, null);
    await expect(acquired).rejects.toMatchObject({ code: "startup_failed" });
  });

  it("U015 close-before-ready is protocol failure", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    child.finish(0, null);
    await expect(acquired).rejects.toMatchObject({ code: "protocol" });
  });

  it("U016 contention timeout terminates a running waiter", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    child.killResult = (signal) => {
      if (signal === "SIGTERM")
        queueMicrotask(() => child.finish(null, "SIGTERM"));
      return true;
    };
    const acquired = providerFor(runner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    })(ROOT);
    await expect(acquired).rejects.toMatchObject({ code: "timeout" });
    expect(child.kills).toEqual(["SIGTERM"]);

    const deferredRunner = new FakeRunner();
    const helperPreflight = deferred<Phase3ApprovalCustodyMetadata>();
    deferredRunner.setMetadata(HELPER, [helperPreflight.promise]);
    const deferredAcquisition = providerFor(deferredRunner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 50,
    })(ROOT);
    await expect(deferredAcquisition).rejects.toMatchObject({
      code: "timeout",
    });
    expect(deferredRunner.spawnCalls).toHaveLength(0);
    helperPreflight.resolve(helperMetadata);
    await flush();
    expect(deferredRunner.spawnCalls).toHaveLength(0);
  });

  it("U017 ready unexpected exit and exit-before-close suppress KILL", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner, {
      operationTimeoutMs: 20,
      terminationGraceMs: 20,
    })(ROOT);
    child.stdout.write(readyFrame());
    const lease = await acquired;
    child.emitExit(1, null);
    const release = lease.release();
    await delay(5);
    child.emitClose(1, null);
    await expect(release).rejects.toMatchObject({ code: "holder_lost" });
    expect(child.kills).toHaveLength(0);

    const secondRunner = new FakeRunner();
    const secondChild = secondRunner.enqueue();
    const secondAcquired = providerFor(secondRunner, {
      operationTimeoutMs: 20,
      terminationGraceMs: 20,
    })(ROOT);
    secondChild.stdout.write(readyFrame());
    const secondLease = await secondAcquired;
    secondChild.emitExit(0, null);
    const secondRelease = secondLease.release();
    expect(secondChild.stdinBytes()).toHaveLength(0);
    secondChild.emitClose(0, null);
    await expect(secondRelease).rejects.toMatchObject({
      code: "holder_lost",
    });
    expect(secondChild.kills).toHaveLength(0);

    const protocolRunner = new FakeRunner();
    const protocolChild = protocolRunner.enqueue();
    const protocolAcquired = providerFor(protocolRunner, {
      operationTimeoutMs: 50,
      terminationGraceMs: 20,
    })(ROOT);
    protocolChild.stdout.write(readyFrame());
    const protocolLease = await protocolAcquired;
    protocolChild.stdout.write("late");
    await flush();
    protocolChild.finish(null, "SIGTERM");
    const protocolRelease = protocolLease.release();
    expect(protocolChild.stdinBytes()).toHaveLength(0);
    await expect(protocolRelease).rejects.toMatchObject({ code: "protocol" });
    expect(protocolChild.kills).toEqual(["SIGTERM"]);
  });

  it("U018 stdin EPIPE is classified", async () => {
    {
      const runner = new FakeRunner();
      const child = runner.enqueue();
      const acquired = providerFor(runner)(ROOT);
      child.stdin.emit(
        "error",
        Object.assign(new Error("canary"), { code: "EPIPE" }),
      );
      child.finish(70, null);
      await expect(acquired).rejects.toMatchObject({ code: "stdin" });
    }
    {
      const runner = new FakeRunner();
      const child = runner.enqueue();
      const acquired = providerFor(runner)(ROOT);
      child.stdout.write(readyFrame());
      const lease = await acquired;
      const release = lease.release();
      child.stdin.emit(
        "error",
        Object.assign(new Error("canary"), { code: "EPIPE" }),
      );
      child.finish(70, null);
      await expect(release).rejects.toMatchObject({
        code: "stdin",
        message: "Approval custody helper control failed",
      });
    }
  });

  it("U019 operation timeout escalates TERM to KILL", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    })(ROOT);
    await expect(acquired).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(child.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(child.unrefCalls).toBe(1);
    expect(child.stdin.unrefCalls).toBe(1);
    expect(child.stdout.unrefCalls).toBe(1);
    expect(child.stderr.unrefCalls).toBe(1);
    child.stdout.emit("data", Buffer.from("late"));
    child.stderr.emit("data", Buffer.from("late"));
    child.emit("error", Object.assign(new Error("late"), { code: "EIO" }));
    child.stdin.emit(
      "error",
      Object.assign(new Error("late"), { code: "EPIPE" }),
    );
    await delay(25);
    expect(child.kills).toEqual(["SIGTERM", "SIGKILL"]);
    child.finish(null, "SIGKILL");

    const releaseRunner = new FakeRunner();
    const releaseChild = releaseRunner.enqueue();
    const releaseAcquired = providerFor(releaseRunner, {
      operationTimeoutMs: 100,
      terminationGraceMs: 15,
    })(ROOT);
    releaseChild.stdout.write(readyFrame());
    const lease = await releaseAcquired;
    releaseChild.stdout.write("late");
    await flush();
    expect(releaseChild.kills).toEqual(["SIGTERM"]);
    const release = lease.release();
    expect(lease.release()).toBe(release);
    expect(releaseChild.stdinBytes()).toHaveLength(0);
    await expect(release).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(releaseChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(releaseChild.unrefCalls).toBe(1);
    expect(releaseChild.stdin.unrefCalls).toBe(1);
    expect(releaseChild.stdout.unrefCalls).toBe(1);
    expect(releaseChild.stderr.unrefCalls).toBe(1);
    await delay(25);
    expect(releaseChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    releaseChild.emitClose(null, "SIGKILL");
  });

  it("U020 kill failure is tracked as unproved cleanup", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    child.killResult = () => {
      queueMicrotask(() => child.finish(null, null));
      return false;
    };
    const acquired = providerFor(runner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    })(ROOT);
    await expect(acquired).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(child.kills).toEqual(["SIGTERM"]);
  });

  it("U021 close timeout after exit sends no signal", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const provider = providerFor(runner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    });
    const acquired = provider(ROOT);
    child.stdout.write(readyFrame());
    const lease = await acquired;
    child.emitExit(1, null);
    const release = lease.release();
    await expect(release).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(child.kills).toHaveLength(0);
    expect(child.unrefCalls).toBe(1);
    expect(child.stdin.destroyed).toBe(true);
    expect(child.stdout.destroyed).toBe(true);
    expect(child.stderr.destroyed).toBe(true);
    expect(child.stdin.unrefCalls).toBe(1);
    expect(child.stdout.unrefCalls).toBe(1);
    expect(child.stderr.unrefCalls).toBe(1);
    child.stdout.emit("data", Buffer.from("late"));
    child.stderr.emit("data", Buffer.from("late"));
    child.emit("error", Object.assign(new Error("late"), { code: "EIO" }));
    child.stdin.emit(
      "error",
      Object.assign(new Error("late"), { code: "EPIPE" }),
    );
    await delay(25);
    expect(child.kills).toHaveLength(0);
    child.emitClose(1, null);

    const replacement = runner.enqueue();
    const next = provider(ROOT);
    replacement.stdout.write(failureFrame("lock_failed"));
    replacement.finish(68, null);
    await expect(next).rejects.toMatchObject({ helperCode: "lock_failed" });
  });

  it("U022 grace-expired release retains its slot until late close", async () => {
    const runner = new FakeRunner();
    const provider = providerFor(runner, {
      operationTimeoutMs: 200,
      terminationGraceMs: 10,
    });
    const firstChild = runner.enqueue();
    const firstAcquired = provider(ROOT);
    firstChild.stdout.write(readyFrame());
    const firstLease = await firstAcquired;
    firstChild.stdout.write("late");
    await delay(25);
    expect(firstChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(firstChild.stdinBytes()).toHaveLength(0);
    expect(firstChild.unrefCalls).toBe(1);
    expect(firstChild.stdin.destroyed).toBe(true);
    expect(firstChild.stdout.destroyed).toBe(true);
    expect(firstChild.stderr.destroyed).toBe(true);
    const firstRelease = firstLease.release();
    const repeatedRelease = firstLease.release();
    expect(repeatedRelease).toBe(firstRelease);
    const immediateResult = Promise.race([
      firstRelease.then(
        () => "resolved",
        () => "rejected",
      ),
      delay(0).then(() => "timer"),
    ]);
    await expect(immediateResult).resolves.toBe("rejected");
    await expect(firstRelease).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(firstLease.release()).toBe(firstRelease);
    await delay(25);
    expect(firstChild.kills).toEqual(["SIGTERM", "SIGKILL"]);
    expect(firstChild.unrefCalls).toBe(1);
    expect(firstChild.stdin.unrefCalls).toBe(1);
    expect(firstChild.stdout.unrefCalls).toBe(1);
    expect(firstChild.stderr.unrefCalls).toBe(1);

    const held: Array<{
      readonly child: FakeChild;
      readonly lease: Phase3ApprovalCustodyLease;
    }> = [];
    for (
      let index = 1;
      index < PHASE3_APPROVAL_CUSTODY_LIMITS.providerLive;
      index += 1
    ) {
      const child = runner.enqueue();
      const acquired = provider(ROOT);
      child.stdout.write(readyFrame());
      held.push({ child, lease: await acquired });
    }
    await expect(provider(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
    expect(runner.spawnCalls).toHaveLength(
      PHASE3_APPROVAL_CUSTODY_LIMITS.providerLive,
    );

    firstChild.emitClose(null, "SIGKILL");
    const replacementChild = runner.enqueue();
    const replacement = provider(ROOT);
    replacementChild.stdout.write(failureFrame("lock_failed"));
    replacementChild.finish(68, null);
    await expect(replacement).rejects.toMatchObject({
      helperCode: "lock_failed",
    });

    for (const item of held) {
      const released = item.lease.release();
      item.child.finish(0, null);
      await released;
    }
  });

  it("U023 concurrent release calls share one successful Promise", async () => {
    const { lease, child } = await acquireLease();
    const first = lease.release();
    const second = lease.release();
    expect(second).toBe(first);
    child.finish(0, null);
    await expect(first).resolves.toBeUndefined();
    expect(lease.release()).toBe(first);
  });

  it("U024 concurrent release calls share one failed Promise", async () => {
    const { lease, child } = await acquireLease();
    const first = lease.release();
    const second = lease.release();
    child.emit("error", Object.assign(new Error("canary"), { code: "EIO" }));
    child.finish(0, null);
    expect(second).toBe(first);
    await expect(first).rejects.toMatchObject({ code: "holder_lost" });
    expect(lease.release()).toBe(first);
  });

  it("U025 lease is an exact frozen one-property object", async () => {
    const { lease, child } = await acquireLease();
    expect(Object.isFrozen(lease)).toBe(true);
    expect(Reflect.ownKeys(lease)).toEqual(["release"]);
    expect(Object.getOwnPropertyDescriptor(lease, "release")).toMatchObject({
      enumerable: true,
      configurable: false,
      writable: false,
    });
    const release = lease.release();
    child.finish(0, null);
    await release;
  });

  it("U026 unsupported filesystem frame is preserved", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner)(ROOT);
    child.stdout.write(failureFrame("filesystem_unsupported"));
    child.finish(67, null);
    await expect(acquired).rejects.toEqual(
      expect.objectContaining({
        code: "startup_failed",
        helperCode: "filesystem_unsupported",
      }),
    );
  });

  it("U027 boundary canaries are sanitized", async () => {
    const runner = new FakeRunner();
    runner.lstatError = new Error("SECRET-CANARY");
    let error: unknown;
    try {
      await providerFor(runner)(ROOT);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(Phase3ApprovalCustodyError);
    expect(JSON.stringify(error)).not.toContain("SECRET-CANARY");
    expect(String(error)).not.toContain("SECRET-CANARY");
  });

  it("U028 Durable Phase3N API mechanics invoke and release custody", async () => {
    const root = await makePrivateRoot();
    const runner = new FakeRunner();
    runner.setMetadata(root, [
      { ...rootMetadata, ino: 10n },
      { ...rootMetadata, ino: 10n },
    ]);
    const child = runner.enqueue();
    child.closeOnInputEnd = true;
    const provider = providerFor(runner);
    const store = new DurablePhase3ApprovalGrants(
      root,
      Buffer.alloc(32, 0x44),
      {
        acquireExclusiveRootCustody: provider,
        durability: {
          privateMode: (mode) => (mode & 0o077n) === 0n,
          syncDirectory: async () => undefined,
        },
      },
    );
    const remediation = store.remediateStaleStages();
    child.stdout.write(readyFrame({ ino: 10n }));
    await expect(remediation).rejects.toThrow(
      "Approval stale-stage remediation failed",
    );
    expect(child.stdinBytes()).toEqual(Buffer.from([0x52]));
    expect(runner.spawnCalls[0]?.root).toBe(root);
    await store.close();
  });

  it("U029 provider and module-global live caps apply before spawn", async () => {
    const providers = Array.from({ length: 4 }, () => {
      const runner = new FakeRunner();
      return { runner, provider: providerFor(runner) };
    });
    const held: Array<{
      readonly child: FakeChild;
      readonly lease: Phase3ApprovalCustodyLease;
    }> = [];
    for (const entry of providers) {
      for (
        let index = 0;
        index < PHASE3_APPROVAL_CUSTODY_LIMITS.providerLive;
        index += 1
      ) {
        const child = entry.runner.enqueue();
        const acquired = entry.provider(ROOT);
        child.stdout.write(readyFrame());
        held.push({ child, lease: await acquired });
      }
      await expect(entry.provider(ROOT)).rejects.toMatchObject({
        code: "startup_failed",
      });
      expect(entry.runner.spawnCalls).toHaveLength(8);
    }
    const overflowRunner = new FakeRunner();
    await expect(providerFor(overflowRunner)(ROOT)).rejects.toMatchObject({
      code: "startup_failed",
    });
    expect(overflowRunner.spawnCalls).toHaveLength(0);
    for (const item of held) {
      const released = item.lease.release();
      item.child.finish(0, null);
      await released;
    }
  });

  it("U030 post-reject records remain until later close removes them", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const provider = providerFor(runner, {
      operationTimeoutMs: 10,
      terminationGraceMs: 10,
    });
    const acquired = provider(ROOT);
    await expect(acquired).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(runner.spawnCalls).toHaveLength(1);
    child.finish(null, "SIGKILL");
    const next = runner.enqueue();
    const nextAcquired = provider(ROOT);
    next.stdout.write(failureFrame("lock_failed"));
    next.finish(68, null);
    await expect(nextAcquired).rejects.toMatchObject({
      helperCode: "lock_failed",
    });
    expect(runner.spawnCalls).toHaveLength(2);
  });

  it("U031 failed acquisition uses the same bounded termination lifecycle", async () => {
    const runner = new FakeRunner();
    const child = runner.enqueue();
    const acquired = providerFor(runner, {
      operationTimeoutMs: 50,
      terminationGraceMs: 10,
    })(ROOT);
    child.stdout.write("malformed\n");
    await expect(acquired).rejects.toMatchObject({
      code: "cleanup_unproved",
    });
    expect(child.kills).toEqual(["SIGTERM", "SIGKILL"]);
    child.finish(null, "SIGKILL");
  });

  it("U032 orphan-only parent loss terminates the helper and permits reacquire", async () => {
    const runner = new FakeRunner();
    const first = runner.enqueue();
    const firstAcquired = providerFor(runner)(ROOT);
    first.stdout.write(readyFrame());
    const firstLease = await firstAcquired;
    first.finish(null, "SIGTERM");
    await expect(firstLease.release()).rejects.toMatchObject({
      code: "holder_lost",
    });

    const second = runner.enqueue();
    const secondAcquired = providerFor(runner)(ROOT);
    second.stdout.write(readyFrame());
    const secondLease = await secondAcquired;
    const released = secondLease.release();
    second.finish(0, null);
    await expect(released).resolves.toBeUndefined();
  });

  it("U033 C source excludes process, execution, and thread creation APIs", async () => {
    const source = await readFile(
      "src/phase3/native/approval-custody.c",
      "utf8",
    );
    for (const forbidden of [
      /\bfork\s*\(/u,
      /\bvfork\s*\(/u,
      /\bclone\s*\(/u,
      /\bexec[a-z]*\s*\(/u,
      /\bposix_spawn[a-z]*\s*\(/u,
      /\bpthread_[a-z_]+\s*\(/u,
      /\bdlopen\s*\(/u,
    ])
      expect(source).not.toMatch(forbidden);

    const harness = (await import(
      pathToFileURL(resolve("scripts/linux/phase3-custody-harness.mjs")).href
    )) as {
      readonly detectLibc: (boundaries: {
        readonly report: unknown;
        readonly runLdd: () => {
          readonly status: number | null;
          readonly stdout?: string;
          readonly stderr?: string;
        };
        readonly loadedLibraries?: readonly string[];
      }) => string | undefined;
    };
    for (const result of [
      { status: null, stdout: "", stderr: "" },
      { status: 1, stdout: "musl libc", stderr: "" },
      { status: 0, stdout: "", stderr: "" },
      { status: 0, stdout: "unknown implementation", stderr: "" },
    ])
      expect(
        harness.detectLibc({
          report: undefined,
          runLdd: () => result,
          loadedLibraries: [],
        }),
      ).toBeUndefined();
    for (const contradictory of [
      {
        report: undefined,
        runLdd: () => ({
          status: 0,
          stdout: "musl libc\nldd (GNU libc) 2.39",
          stderr: "",
        }),
        loadedLibraries: [],
      },
      {
        report: undefined,
        runLdd: () => ({ status: null, stdout: "", stderr: "" }),
        loadedLibraries: ["/lib/ld-musl-x86_64.so.1", "/lib/libc.so.6"],
      },
      {
        report: { header: { glibcVersionRuntime: "2.39" } },
        runLdd: () => ({
          status: 0,
          stdout: "musl libc (x86_64)",
          stderr: "",
        }),
        loadedLibraries: ["/lib/ld-musl-x86_64.so.1"],
      },
    ])
      expect(harness.detectLibc(contradictory)).toBeUndefined();
    expect(
      harness.detectLibc({
        report: undefined,
        runLdd: () => ({
          status: 0,
          stdout: "musl libc (x86_64)\nVersion 1.2.5",
          stderr: "",
        }),
      }),
    ).toContain("musl");
  });
});

class TrackingPassThrough extends PassThrough {
  unrefCalls = 0;

  override emit(event: string | symbol, ...arguments_: unknown[]): boolean {
    if (event === "error" && this.listenerCount(event) === 0) {
      setImmediate(() => super.emit(event, ...arguments_));
      return false;
    }
    return super.emit(event, ...arguments_);
  }

  unref(): void {
    this.unrefCalls += 1;
  }
}

class FakeChild extends EventEmitter implements Phase3ApprovalCustodyChild {
  readonly stdin = new TrackingPassThrough();
  readonly stdout = new TrackingPassThrough();
  readonly stderr = new TrackingPassThrough();
  pid: number | undefined = 4321;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  readonly kills: NodeJS.Signals[] = [];
  killResult: (signal: NodeJS.Signals) => boolean = () => true;
  closeOnInputEnd = false;
  unrefCalls = 0;
  private readonly input: Buffer[] = [];
  private exited = false;
  private closed = false;

  constructor() {
    super();
    this.stdin.on("data", (chunk: Buffer) => {
      this.input.push(Buffer.from(chunk));
    });
    this.stdin.on("finish", () => {
      if (this.closeOnInputEnd) queueMicrotask(() => this.finish(0, null));
    });
  }

  override emit(event: string | symbol, ...arguments_: unknown[]): boolean {
    if (
      (event === "error" || event === "exit" || event === "close") &&
      this.listenerCount(event) === 0
    ) {
      setImmediate(() => super.emit(event, ...arguments_));
      return false;
    }
    return super.emit(event, ...arguments_);
  }

  kill(signal: NodeJS.Signals | number = "SIGTERM"): boolean {
    const normalized =
      typeof signal === "number" ? ("SIGTERM" as const) : signal;
    this.kills.push(normalized);
    return this.killResult(normalized);
  }

  unref(): void {
    this.unrefCalls += 1;
  }

  stdinBytes(): Buffer {
    return Buffer.concat(this.input);
  }

  emitExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.exited) return;
    this.exited = true;
    this.exitCode = code;
    this.signalCode = signal;
    this.emit("exit", code, signal);
  }

  emitClose(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.closed) return;
    this.closed = true;
    this.exitCode = code;
    this.signalCode = signal;
    this.emit("close", code, signal);
  }

  finish(code: number | null, signal: NodeJS.Signals | null): void {
    this.emitExit(code, signal);
    this.emitClose(code, signal);
  }
}

class FakeRunner implements Phase3ApprovalCustodyRunner {
  readonly spawnCalls: Array<{
    readonly helperPath: string;
    readonly root: string;
    readonly parentPid: number;
  }> = [];
  readonly queued: FakeChild[] = [];
  readonly metadataByPath = new Map<
    string,
    Array<
      Phase3ApprovalCustodyMetadata | Promise<Phase3ApprovalCustodyMetadata>
    >
  >([
    [ROOT, [rootMetadata]],
    [HELPER, [helperMetadata]],
  ]);
  fsTypes: bigint[] = [FS_TYPE];
  spawnError: unknown;
  lstatError: unknown;

  enqueue(): FakeChild {
    const child = new FakeChild();
    this.queued.push(child);
    return child;
  }

  setMetadata(
    path: string,
    values: Array<
      Phase3ApprovalCustodyMetadata | Promise<Phase3ApprovalCustodyMetadata>
    >,
  ): void {
    this.metadataByPath.set(path, values);
  }

  spawn(
    helperPath: string,
    root: string,
    parentPid: number,
  ): Phase3ApprovalCustodyChild {
    this.spawnCalls.push({ helperPath, root, parentPid });
    if (this.spawnError) throw this.spawnError;
    return this.queued.shift() ?? new FakeChild();
  }

  async lstat(path: string): Promise<Phase3ApprovalCustodyMetadata> {
    if (this.lstatError) throw this.lstatError;
    const values = this.metadataByPath.get(path);
    if (!values || values.length === 0) {
      if (path === HELPER) return helperMetadata;
      return rootMetadata;
    }
    return values.length > 1 ? await values.shift()! : await values[0]!;
  }

  async statfsType(): Promise<bigint> {
    return this.fsTypes.length > 1
      ? (this.fsTypes.shift() as bigint)
      : this.fsTypes[0]!;
  }

  currentUid(): bigint {
    return UID;
  }
}

function providerFor(
  runner: FakeRunner,
  options: Readonly<{
    readonly platform?: NodeJS.Platform;
    readonly operationTimeoutMs?: number;
    readonly terminationGraceMs?: number;
  }> = {},
) {
  return createLinuxPhase3ApprovalCustodyProvider({
    helperPath: HELPER,
    runner,
    platform: options.platform ?? "linux",
    operationTimeoutMs: options.operationTimeoutMs ?? 200,
    terminationGraceMs: options.terminationGraceMs ?? 20,
  });
}

function metadata(
  overrides: Partial<Phase3ApprovalCustodyMetadata>,
): Phase3ApprovalCustodyMetadata {
  return Object.freeze({
    dev: 1n,
    ino: 1n,
    mode: 0o040700n,
    uid: UID,
    gid: UID,
    nlink: 1n,
    size: 0n,
    ctimeNs: 2_000_000_003n,
    kind: "directory" as const,
    ...overrides,
  });
}

function readyFrame(
  overrides: Partial<{
    readonly dev: bigint;
    readonly ino: bigint;
    readonly mode: bigint;
    readonly uid: bigint;
    readonly gid: bigint;
    readonly nlink: bigint;
    readonly ctimeSec: bigint;
    readonly ctimeNsec: bigint;
    readonly fsType: bigint;
  }> = {},
): string {
  const value = {
    dev: rootMetadata.dev,
    ino: rootMetadata.ino,
    mode: rootMetadata.mode,
    uid: rootMetadata.uid,
    gid: rootMetadata.gid,
    nlink: rootMetadata.nlink,
    ctimeSec: rootMetadata.ctimeNs / 1_000_000_000n,
    ctimeNsec: rootMetadata.ctimeNs % 1_000_000_000n,
    fsType: FS_TYPE,
    ...overrides,
  };
  return (
    "phase3-approval-custody-v1\tready" +
    `\tdev=${value.dev}\tino=${value.ino}\tmode=${value.mode}` +
    `\tuid=${value.uid}\tgid=${value.gid}\tnlink=${value.nlink}` +
    `\tctime_sec=${value.ctimeSec}\tctime_nsec=${value.ctimeNsec}` +
    `\tfs_type=${value.fsType}\n`
  );
}

function failureFrame(code: string): string {
  return `phase3-approval-custody-v1\tfailure\tcode=${code}\n`;
}

async function acquireLease(): Promise<{
  readonly runner: FakeRunner;
  readonly child: FakeChild;
  readonly lease: Phase3ApprovalCustodyLease;
}> {
  const runner = new FakeRunner();
  const child = runner.enqueue();
  const acquired = providerFor(runner)(ROOT);
  child.stdout.write(readyFrame());
  return { runner, child, lease: await acquired };
}

async function flush(): Promise<void> {
  await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise<void>((resolvePromise) =>
    setTimeout(resolvePromise, milliseconds),
  );
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
} {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolveValue) => {
    resolvePromise = resolveValue;
  });
  return {
    promise,
    resolve: (value) => resolvePromise?.(value),
  };
}

async function makePrivateRoot(): Promise<string> {
  const base = await mkdtemp(join(tmpdir(), "phase3-custody-"));
  temporaryRoots.push(base);
  const root = join(base, "root");
  await mkdir(root, { mode: 0o700 });
  await chmod(root, 0o700);
  await writeFile(join(base, "marker"), "", { mode: 0o600 });
  return root;
}
