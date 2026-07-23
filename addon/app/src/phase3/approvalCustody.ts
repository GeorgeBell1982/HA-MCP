import { spawn } from "node:child_process";
import type { BigIntStats } from "node:fs";
import { lstat, statfs } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import type { Readable, Writable } from "node:stream";
import type {
  Phase3ApprovalCustodyLease,
  Phase3ApprovalCustodyProvider,
} from "./durableApproval.js";

export const PHASE3_APPROVAL_CUSTODY_LIMITS = Object.freeze({
  stdoutBytes: 512,
  stderrBytes: 1024,
  providerLive: 8,
  moduleLive: 32,
});

export const phase3ApprovalCustodyHelperCodes = [
  "invalid_arguments",
  "parent_invalid",
  "parent_changed",
  "root_open_failed",
  "root_unsafe",
  "filesystem_unsupported",
  "lock_failed",
  "ready_write_failed",
  "internal_error",
] as const;

export type Phase3ApprovalCustodyHelperCode =
  (typeof phase3ApprovalCustodyHelperCodes)[number];

export type Phase3ApprovalCustodyFailure =
  | "startup_failed"
  | "protocol"
  | "signal"
  | "timeout"
  | "stdin"
  | "holder_lost"
  | "cleanup_unproved";

const failureMessages: Readonly<Record<Phase3ApprovalCustodyFailure, string>> =
  Object.freeze({
    startup_failed: "Approval custody helper failed during startup",
    protocol: "Approval custody helper protocol failed",
    signal: "Approval custody helper terminated by signal",
    timeout: "Approval custody helper timed out",
    stdin: "Approval custody helper control failed",
    holder_lost: "Approval custody holder was lost",
    cleanup_unproved: "Approval custody helper cleanup was not proved",
  });

export class Phase3ApprovalCustodyError extends Error {
  constructor(
    public readonly code: Phase3ApprovalCustodyFailure,
    public readonly helperCode?: Phase3ApprovalCustodyHelperCode,
  ) {
    super(failureMessages[code]);
    this.name = "Phase3ApprovalCustodyError";
  }
}

export interface Phase3ApprovalCustodyMetadata {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly ctimeNs: bigint;
  readonly kind: "directory" | "regular" | "other";
}

export interface Phase3ApprovalCustodyChild {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  readonly pid?: number | undefined;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  on(event: "error", listener: (error: NodeJS.ErrnoException) => void): this;
  on(
    event: "exit" | "close",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): this;
  kill(signal?: NodeJS.Signals | number): boolean;
  unref(): void;
}

export interface Phase3ApprovalCustodyRunner {
  spawn(
    helperPath: string,
    root: string,
    parentPid: number,
  ): Phase3ApprovalCustodyChild;
  lstat(path: string): Promise<Phase3ApprovalCustodyMetadata>;
  statfsType(path: string): Promise<bigint>;
  currentUid(): bigint;
}

export interface LinuxPhase3ApprovalCustodyOptions {
  readonly helperPath: string;
  readonly operationTimeoutMs?: number;
  readonly terminationGraceMs?: number;
  readonly platform?: NodeJS.Platform;
  readonly runner?: Phase3ApprovalCustodyRunner;
}

interface ReadyFrame {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly nlink: bigint;
  readonly ctimeSec: bigint;
  readonly ctimeNsec: bigint;
  readonly fsType: bigint;
}

type ParsedFrame =
  | { readonly kind: "ready"; readonly ready: ReadyFrame }
  | {
      readonly kind: "failure";
      readonly helperCode: Phase3ApprovalCustodyHelperCode;
    };

type ChildState = "running" | "exited_waiting_close" | "closed";

const helperExitCodes: Readonly<
  Record<Phase3ApprovalCustodyHelperCode, number>
> = Object.freeze({
  invalid_arguments: 64,
  parent_invalid: 65,
  parent_changed: 65,
  root_open_failed: 66,
  root_unsafe: 66,
  filesystem_unsupported: 67,
  lock_failed: 68,
  ready_write_failed: 69,
  internal_error: 74,
});

const unsignedPattern = /^(?:0|[1-9][0-9]{0,19})$/u;
const readyPattern =
  /^phase3-approval-custody-v1\tready\tdev=([0-9]+)\tino=([0-9]+)\tmode=([0-9]+)\tuid=([0-9]+)\tgid=([0-9]+)\tnlink=([0-9]+)\tctime_sec=([0-9]+)\tctime_nsec=([0-9]+)\tfs_type=([0-9]+)\n$/u;
const failurePattern =
  /^phase3-approval-custody-v1\tfailure\tcode=([a-z_]+)\n$/u;
const validDurationMaximumMs = 60_000;
let moduleLive = 0;

export function createLinuxPhase3ApprovalCustodyProvider(
  options: LinuxPhase3ApprovalCustodyOptions,
): Phase3ApprovalCustodyProvider {
  const helperPath = validatedPath(options.helperPath);
  const operationTimeoutMs = validatedDuration(
    options.operationTimeoutMs ?? 5_000,
  );
  const terminationGraceMs = validatedDuration(
    options.terminationGraceMs ?? 1_000,
  );
  const realRunner = options.runner === undefined;
  if (realRunner && options.platform !== undefined)
    throw custodyError("startup_failed");
  const runner = options.runner ?? new SpawnPhase3ApprovalCustodyRunner();
  const platform = realRunner ? process.platform : options.platform;
  if (platform === undefined) throw custodyError("startup_failed");
  let providerLive = 0;

  return async (root: string): Promise<Phase3ApprovalCustodyLease> => {
    const startedAt = performance.now();
    const deadline = startedAt + operationTimeoutMs;
    if (platform !== "linux") throw custodyError("startup_failed");
    const normalizedRoot = validatedPath(root);
    let preflight: {
      readonly helperBefore: Phase3ApprovalCustodyMetadata;
      readonly rootBefore: Phase3ApprovalCustodyMetadata;
      readonly fsTypeBefore: bigint;
    };
    try {
      preflight = await beforeDeadline(
        (async () => {
          const currentUid = runner.currentUid();
          const helperBefore = await runner.lstat(helperPath);
          validateHelper(helperBefore, currentUid);
          const rootBefore = await runner.lstat(normalizedRoot);
          validateRoot(rootBefore, currentUid);
          const fsTypeBefore = await runner.statfsType(normalizedRoot);
          return { helperBefore, rootBefore, fsTypeBefore };
        })(),
        deadline,
      );
    } catch (error) {
      if (isDeadlineError(error)) throw custodyError("timeout");
      throw custodyError("startup_failed");
    }

    if (performance.now() >= deadline) throw custodyError("timeout");
    if (
      providerLive >= PHASE3_APPROVAL_CUSTODY_LIMITS.providerLive ||
      moduleLive >= PHASE3_APPROVAL_CUSTODY_LIMITS.moduleLive
    )
      throw custodyError("startup_failed");
    providerLive += 1;
    moduleLive += 1;
    let slotReleased = false;
    const releaseSlot = (): void => {
      if (slotReleased) return;
      slotReleased = true;
      providerLive -= 1;
      moduleLive -= 1;
    };

    let child: Phase3ApprovalCustodyChild;
    try {
      child = runner.spawn(helperPath, normalizedRoot, process.pid);
    } catch {
      releaseSlot();
      throw custodyError("startup_failed");
    }
    const controller = new CustodyController({
      child,
      helperPath,
      root: normalizedRoot,
      helperBefore: preflight.helperBefore,
      rootBefore: preflight.rootBefore,
      fsTypeBefore: preflight.fsTypeBefore,
      runner,
      operationTimeoutMs,
      terminationGraceMs,
      deadline,
      releaseSlot,
    });
    return await controller.acquire();
  };
}

class SpawnPhase3ApprovalCustodyRunner implements Phase3ApprovalCustodyRunner {
  spawn(
    helperPath: string,
    root: string,
    parentPid: number,
  ): Phase3ApprovalCustodyChild {
    return spawn(helperPath, [root, String(parentPid)], {
      cwd: "/",
      env: {},
      shell: false,
      detached: false,
      stdio: ["pipe", "pipe", "pipe"],
    });
  }

  async lstat(path: string): Promise<Phase3ApprovalCustodyMetadata> {
    return snapshotMetadata(await lstat(path, { bigint: true }));
  }

  async statfsType(path: string): Promise<bigint> {
    return (await statfs(path, { bigint: true })).type;
  }

  currentUid(): bigint {
    if (process.getuid === undefined) throw custodyError("startup_failed");
    return BigInt(process.getuid());
  }
}

class CustodyController {
  private readonly child: Phase3ApprovalCustodyChild;
  private readonly helperPath: string;
  private readonly root: string;
  private readonly helperBefore: Phase3ApprovalCustodyMetadata;
  private readonly rootBefore: Phase3ApprovalCustodyMetadata;
  private readonly fsTypeBefore: bigint;
  private readonly runner: Phase3ApprovalCustodyRunner;
  private readonly operationTimeoutMs: number;
  private readonly terminationGraceMs: number;
  private readonly deadline: number;
  private readonly releaseSlot: () => void;
  private readonly stdoutChunks: Buffer[] = [];
  private stdoutBytes = 0;
  private stderrBytes = 0;
  private state: ChildState = "running";
  private pidUsable = false;
  private readySeen = false;
  private readyValidated = false;
  private holderLost = false;
  private failureFrame: Phase3ApprovalCustodyHelperCode | undefined;
  private spawnFailed = false;
  private timedOut = false;
  private signalFailure = false;
  private stdinFailure = false;
  private protocolFailure = false;
  private acquired = false;
  private releaseRequested = false;
  private controlSent = false;
  private terminationStarted = false;
  private handlesDetached = false;
  private finalSettled = false;
  private exitCode: number | null = null;
  private exitSignal: NodeJS.Signals | null = null;
  private operationTimer: NodeJS.Timeout | undefined;
  private graceTimer: NodeJS.Timeout | undefined;
  private acquisitionResolve:
    | ((lease: Phase3ApprovalCustodyLease) => void)
    | undefined;
  private acquisitionReject:
    | ((error: Phase3ApprovalCustodyError) => void)
    | undefined;
  private releaseResolve: (() => void) | undefined;
  private releaseReject:
    | ((error: Phase3ApprovalCustodyError) => void)
    | undefined;
  private releasePromise: Promise<void> | undefined;
  private pendingReleaseError: Phase3ApprovalCustodyError | undefined;
  private readonly lease: Phase3ApprovalCustodyLease;

  constructor(input: {
    readonly child: Phase3ApprovalCustodyChild;
    readonly helperPath: string;
    readonly root: string;
    readonly helperBefore: Phase3ApprovalCustodyMetadata;
    readonly rootBefore: Phase3ApprovalCustodyMetadata;
    readonly fsTypeBefore: bigint;
    readonly runner: Phase3ApprovalCustodyRunner;
    readonly operationTimeoutMs: number;
    readonly terminationGraceMs: number;
    readonly deadline: number;
    readonly releaseSlot: () => void;
  }) {
    this.child = input.child;
    this.helperPath = input.helperPath;
    this.root = input.root;
    this.helperBefore = input.helperBefore;
    this.rootBefore = input.rootBefore;
    this.fsTypeBefore = input.fsTypeBefore;
    this.runner = input.runner;
    this.operationTimeoutMs = input.operationTimeoutMs;
    this.terminationGraceMs = input.terminationGraceMs;
    this.deadline = input.deadline;
    this.releaseSlot = input.releaseSlot;
    this.lease = Object.freeze({ release: () => this.release() });

    this.child.on("error", () => this.onError());
    this.child.on("exit", (code, signal) => this.onExit(code, signal));
    this.child.on("close", (code, signal) => this.onClose(code, signal));
    this.child.stdout.on("data", (chunk: Buffer | string) =>
      this.onStdout(chunk),
    );
    this.child.stderr.on("data", (chunk: Buffer | string) =>
      this.onStderr(chunk),
    );
    this.child.stdin.on("error", () => this.onStdinError());

    const pid = this.child.pid;
    this.pidUsable =
      typeof pid === "number" && Number.isSafeInteger(pid) && pid > 0;
    if (!this.pidUsable) {
      this.spawnFailed = true;
      this.beginTermination();
    }
  }

  acquire(): Promise<Phase3ApprovalCustodyLease> {
    const promise = new Promise<Phase3ApprovalCustodyLease>(
      (resolvePromise, rejectPromise) => {
        this.acquisitionResolve = resolvePromise;
        this.acquisitionReject = rejectPromise;
      },
    );
    const delay = Math.max(0, this.deadline - performance.now());
    if (!this.terminationStarted)
      this.operationTimer = setTimeout(() => this.onOperationTimeout(), delay);
    return promise;
  }

  private release(): Promise<void> {
    if (this.releasePromise) return this.releasePromise;
    this.releaseRequested = true;
    this.releasePromise = new Promise<void>((resolvePromise, rejectPromise) => {
      this.releaseResolve = resolvePromise;
      this.releaseReject = rejectPromise;
    });
    if (this.terminationStarted) {
      if (this.state === "closed") this.finishReleaseFromClose();
      else if (this.pendingReleaseError)
        this.rejectRelease(this.pendingReleaseError);
      return this.releasePromise;
    }
    this.clearTimers();
    if (this.state !== "running") {
      if (this.state === "closed") this.finishReleaseFromClose();
      else this.startReleaseTimer();
      return this.releasePromise;
    }
    try {
      this.child.stdin.end(Buffer.from([0x52]));
      this.controlSent = true;
    } catch {
      this.stdinFailure = true;
      this.beginTermination();
    }
    this.startReleaseTimer();
    return this.releasePromise;
  }

  private startReleaseTimer(): void {
    if (this.terminationStarted) return;
    this.operationTimer = setTimeout(
      () => this.onOperationTimeout(),
      this.operationTimeoutMs,
    );
  }

  private onStdout(value: Buffer | string): void {
    if (this.finalSettled) return;
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    this.stdoutBytes += chunk.byteLength;
    if (
      this.stdoutBytes > PHASE3_APPROVAL_CUSTODY_LIMITS.stdoutBytes ||
      this.readySeen ||
      this.failureFrame !== undefined
    ) {
      this.protocolFailure = true;
      this.beginTermination();
      return;
    }
    this.stdoutChunks.push(Buffer.from(chunk));
    const bytes = Buffer.concat(this.stdoutChunks);
    const newline = bytes.indexOf(0x0a);
    if (newline < 0) return;
    if (newline !== bytes.byteLength - 1) {
      this.protocolFailure = true;
      this.beginTermination();
      return;
    }
    const frame = parseFrame(bytes);
    if (!frame) {
      this.protocolFailure = true;
      this.beginTermination();
      return;
    }
    if (frame.kind === "failure") {
      this.failureFrame = frame.helperCode;
      return;
    }
    this.readySeen = true;
    void this.completeReady(frame.ready);
  }

  private onStderr(value: Buffer | string): void {
    if (this.finalSettled) return;
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    this.stderrBytes += chunk.byteLength;
    this.protocolFailure = true;
    if (this.stderrBytes > PHASE3_APPROVAL_CUSTODY_LIMITS.stderrBytes)
      this.stderrBytes = PHASE3_APPROVAL_CUSTODY_LIMITS.stderrBytes + 1;
    this.beginTermination();
  }

  private onError(): void {
    if (this.finalSettled) return;
    this.spawnFailed = true;
    this.beginTermination();
  }

  private onStdinError(): void {
    if (this.finalSettled) return;
    this.stdinFailure = true;
    this.beginTermination();
  }

  private onExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.state !== "running") return;
    this.state = "exited_waiting_close";
    this.exitCode = code;
    this.exitSignal = signal;
  }

  private onClose(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.state === "closed") return;
    this.state = "closed";
    this.exitCode = code;
    this.exitSignal = signal;
    this.releaseSlot();
    if (this.finalSettled) return;
    if (!this.acquired) this.finishAcquisitionFromClose();
    else if (this.releaseRequested) this.finishReleaseFromClose();
    else this.holderLost = true;
  }

  private onOperationTimeout(): void {
    this.startTermination(true);
  }

  private beginTermination(): void {
    this.startTermination(false);
  }

  private startTermination(operationTimedOut: boolean): void {
    if (this.finalSettled || this.state === "closed" || this.terminationStarted)
      return;
    this.terminationStarted = true;
    if (operationTimedOut)
      this.timedOut =
        this.state === "running" &&
        !this.stdinFailure &&
        !this.protocolFailure &&
        !this.spawnFailed;
    if (this.operationTimer) clearTimeout(this.operationTimer);
    this.operationTimer = undefined;
    this.signalRunning("SIGTERM");
    this.graceTimer = setTimeout(() => {
      this.graceTimer = undefined;
      if (this.finalSettled || this.state === "closed") return;
      this.signalRunning("SIGKILL");
      if (this.childClosed()) return;
      if (!this.acquired)
        this.rejectAcquisition(custodyError("cleanup_unproved"));
      else {
        this.pendingReleaseError ??= custodyError("cleanup_unproved");
        this.detachHandles();
        if (this.releaseRequested) this.rejectRelease(this.pendingReleaseError);
      }
    }, this.terminationGraceMs);
  }

  private signalRunning(signal: NodeJS.Signals): void {
    if (this.state !== "running") return;
    if (this.child.exitCode !== null || this.child.signalCode !== null) {
      this.state = "exited_waiting_close";
      this.exitCode = this.child.exitCode;
      this.exitSignal = this.child.signalCode;
      return;
    }
    if (!this.pidUsable) {
      return;
    }
    try {
      if (!this.child.kill(signal)) this.signalFailure = true;
    } catch {
      this.signalFailure = true;
    }
  }

  private finishAcquisitionFromClose(): void {
    let error: Phase3ApprovalCustodyError;
    if (this.signalFailure) error = custodyError("cleanup_unproved");
    else if (this.timedOut) error = custodyError("timeout");
    else if (this.stdinFailure) error = custodyError("stdin");
    else if (this.protocolFailure) error = custodyError("protocol");
    else if (this.exitSignal !== null) error = custodyError("signal");
    else if (
      this.failureFrame !== undefined &&
      this.exitCode === helperExitCodes[this.failureFrame] &&
      !this.stdinFailure
    )
      error = custodyError("startup_failed", this.failureFrame);
    else if (this.readySeen) error = custodyError("holder_lost");
    else if (this.spawnFailed) error = custodyError("startup_failed");
    else error = custodyError("protocol");
    this.rejectAcquisition(error);
  }

  private finishReleaseFromClose(): void {
    let error: Phase3ApprovalCustodyError | undefined;
    if (this.signalFailure) error = custodyError("cleanup_unproved");
    else if (this.timedOut) error = custodyError("timeout");
    else if (this.stdinFailure) error = custodyError("stdin");
    else if (this.protocolFailure) error = custodyError("protocol");
    else if (this.spawnFailed) error = custodyError("holder_lost");
    else if (this.holderLost) error = custodyError("holder_lost");
    else if (this.exitSignal !== null) error = custodyError("signal");
    else if (
      !this.readyValidated ||
      !this.controlSent ||
      this.exitCode !== 0 ||
      this.stderrBytes !== 0
    )
      error = custodyError("holder_lost");
    if (error) this.rejectRelease(error);
    else this.resolveRelease();
  }

  private rejectAcquisition(error: Phase3ApprovalCustodyError): void {
    if (this.finalSettled) return;
    this.finalSettled = true;
    this.clearTimers();
    const rejectPromise = this.acquisitionReject;
    this.acquisitionResolve = undefined;
    this.acquisitionReject = undefined;
    this.detachHandles();
    rejectPromise?.(error);
  }

  private resolveRelease(): void {
    if (this.finalSettled) return;
    this.finalSettled = true;
    this.clearTimers();
    const resolvePromise = this.releaseResolve;
    this.releaseResolve = undefined;
    this.releaseReject = undefined;
    this.detachHandles();
    resolvePromise?.();
  }

  private rejectRelease(error: Phase3ApprovalCustodyError): void {
    if (this.finalSettled) return;
    this.finalSettled = true;
    this.clearTimers();
    const rejectPromise = this.releaseReject;
    this.releaseResolve = undefined;
    this.releaseReject = undefined;
    this.detachHandles();
    rejectPromise?.(error);
  }

  private clearTimers(): void {
    if (this.operationTimer) clearTimeout(this.operationTimer);
    if (this.graceTimer) clearTimeout(this.graceTimer);
    this.operationTimer = undefined;
    this.graceTimer = undefined;
  }

  private childClosed(): boolean {
    return this.state === "closed";
  }

  private detachHandles(): void {
    if (this.handlesDetached) return;
    this.handlesDetached = true;
    try {
      this.child.stdin.destroy();
    } catch {
      // Final cleanup remains best effort after the bounded result is fixed.
    }
    try {
      this.child.stdout.destroy();
    } catch {
      // Final cleanup remains best effort after the bounded result is fixed.
    }
    try {
      this.child.stderr.destroy();
    } catch {
      // Final cleanup remains best effort after the bounded result is fixed.
    }
    unrefHandle(this.child.stdin);
    unrefHandle(this.child.stdout);
    unrefHandle(this.child.stderr);
    try {
      this.child.unref();
    } catch {
      // Unref failure cannot extend or replace the bounded public result.
    }
  }

  private async completeReady(ready: ReadyFrame): Promise<void> {
    try {
      await beforeDeadline(this.validateReady(ready), this.deadline);
    } catch (error) {
      if (this.finalSettled) return;
      if (isDeadlineError(error)) {
        this.onOperationTimeout();
        return;
      }
      this.protocolFailure = true;
      this.beginTermination();
      return;
    }
    if (
      this.finalSettled ||
      this.state !== "running" ||
      this.terminationStarted ||
      this.timedOut ||
      this.protocolFailure ||
      this.stdinFailure ||
      this.spawnFailed ||
      this.signalFailure ||
      performance.now() >= this.deadline
    )
      return;
    this.readyValidated = true;
    this.acquired = true;
    this.clearTimers();
    const resolvePromise = this.acquisitionResolve;
    this.acquisitionResolve = undefined;
    this.acquisitionReject = undefined;
    resolvePromise?.(this.lease);
  }

  private async validateReady(ready: ReadyFrame): Promise<void> {
    const rootAfter = await this.runner.lstat(this.root);
    const helperAfter = await this.runner.lstat(this.helperPath);
    const fsTypeAfter = await this.runner.statfsType(this.root);
    if (
      !sameMetadata(this.rootBefore, rootAfter) ||
      !sameMetadata(this.helperBefore, helperAfter) ||
      this.fsTypeBefore !== fsTypeAfter ||
      rootAfter.dev !== ready.dev ||
      rootAfter.ino !== ready.ino ||
      rootAfter.mode !== ready.mode ||
      rootAfter.uid !== ready.uid ||
      rootAfter.gid !== ready.gid ||
      rootAfter.nlink !== ready.nlink ||
      rootAfter.ctimeNs / 1_000_000_000n !== ready.ctimeSec ||
      rootAfter.ctimeNs % 1_000_000_000n !== ready.ctimeNsec ||
      fsTypeAfter !== ready.fsType
    )
      throw custodyError("protocol");
  }
}

function snapshotMetadata(stats: BigIntStats): Phase3ApprovalCustodyMetadata {
  return Object.freeze({
    dev: stats.dev,
    ino: stats.ino,
    mode: stats.mode,
    uid: stats.uid,
    gid: stats.gid,
    nlink: stats.nlink,
    size: stats.size,
    ctimeNs: stats.ctimeNs,
    kind: stats.isDirectory()
      ? "directory"
      : stats.isFile()
        ? "regular"
        : "other",
  });
}

function validateHelper(
  metadata: Phase3ApprovalCustodyMetadata,
  currentUid: bigint,
): void {
  if (
    metadata.kind !== "regular" ||
    metadata.uid !== currentUid ||
    (metadata.mode & 0o022n) !== 0n ||
    (metadata.mode & 0o100n) === 0n ||
    metadata.nlink !== 1n
  )
    throw custodyError("startup_failed");
}

function validateRoot(
  metadata: Phase3ApprovalCustodyMetadata,
  currentUid: bigint,
): void {
  if (
    metadata.kind !== "directory" ||
    metadata.uid !== currentUid ||
    (metadata.mode & 0o077n) !== 0n ||
    metadata.nlink < 1n ||
    metadata.ctimeNs < 0n
  )
    throw custodyError("startup_failed");
}

function sameMetadata(
  left: Phase3ApprovalCustodyMetadata,
  right: Phase3ApprovalCustodyMetadata,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.ctimeNs === right.ctimeNs &&
    left.kind === right.kind
  );
}

function parseFrame(bytes: Buffer): ParsedFrame | undefined {
  for (const byte of bytes)
    if (byte !== 0x09 && byte !== 0x0a && (byte < 0x20 || byte > 0x7e))
      return undefined;
  const value = bytes.toString("ascii");
  const readyMatch = readyPattern.exec(value);
  if (readyMatch) {
    const values = readyMatch.slice(1);
    if (values.length !== 9 || values.some((item) => !isUnsigned(item)))
      return undefined;
    const [dev, ino, mode, uid, gid, nlink, ctimeSec, ctimeNsec, fsType] =
      values.map((item) => BigInt(item));
    if (
      dev === undefined ||
      ino === undefined ||
      mode === undefined ||
      uid === undefined ||
      gid === undefined ||
      nlink === undefined ||
      ctimeSec === undefined ||
      ctimeNsec === undefined ||
      fsType === undefined ||
      ctimeNsec > 999_999_999n
    )
      return undefined;
    return {
      kind: "ready",
      ready: {
        dev,
        ino,
        mode,
        uid,
        gid,
        nlink,
        ctimeSec,
        ctimeNsec,
        fsType,
      },
    };
  }
  const failureMatch = failurePattern.exec(value);
  const helperCode = failureMatch?.[1];
  if (helperCode && isHelperCode(helperCode))
    return { kind: "failure", helperCode };
  return undefined;
}

function isUnsigned(value: string): boolean {
  return unsignedPattern.test(value);
}

function isHelperCode(value: string): value is Phase3ApprovalCustodyHelperCode {
  return phase3ApprovalCustodyHelperCodes.includes(
    value as Phase3ApprovalCustodyHelperCode,
  );
}

function validatedPath(value: string): string {
  if (
    typeof value !== "string" ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    resolve(value) !== value
  )
    throw custodyError("startup_failed");
  return value;
}

function validatedDuration(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > validDurationMaximumMs
  )
    throw custodyError("startup_failed");
  return value;
}

function custodyError(
  code: Phase3ApprovalCustodyFailure,
  helperCode?: Phase3ApprovalCustodyHelperCode,
): Phase3ApprovalCustodyError {
  return new Phase3ApprovalCustodyError(code, helperCode);
}

function unrefHandle(handle: Readable | Writable): void {
  const candidate = handle as Readable & { unref?: () => void };
  try {
    candidate.unref?.();
  } catch {
    // Unref failure cannot extend or replace the bounded public result.
  }
}

const deadlineMarker = new Error("phase3 approval custody deadline");

async function beforeDeadline<T>(
  operation: Promise<T>,
  deadline: number,
): Promise<T> {
  const remaining = deadline - performance.now();
  if (remaining <= 0) throw deadlineMarker;
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolvePromise, rejectPromise) => {
        timer = setTimeout(() => rejectPromise(deadlineMarker), remaining);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isDeadlineError(error: unknown): boolean {
  return error === deadlineMarker;
}
