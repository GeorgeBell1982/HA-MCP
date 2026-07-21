import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { posix as posixPath } from "node:path";
import { PHASE2_MAX_TEXT_BYTES } from "../phase2Contracts.js";
import type {
  Phase3AtomicApplyPort,
  Phase3OperationContext,
} from "./applyCoordinator.js";
import type { Phase3CommitStatus } from "./contracts.js";
import { canonicalPhase3Path } from "./resourceLocks.js";

export const phase3AtomicApplyFramePrefix = "phase3-atomic-apply-v1";
export const phase3AtomicApplyStdoutLimit = 256;
export const phase3AtomicApplyStderrLimit = 4096;

export const phase3AtomicApplyHelperErrorCodes = [
  "invalid_input",
  "unsupported_platform",
  "open_root_failed",
  "open_parent_failed",
  "open_target_failed",
  "pending_blocked",
  "target_unsafe",
  "target_digest_mismatch",
  "candidate_read_failed",
  "candidate_digest_mismatch",
  "temp_create_failed",
  "temp_write_failed",
  "temp_verify_failed",
  "race_detected",
  "cancelled",
  "exchange_failed",
  "fsync_failed",
  "cleanup_failed",
  "commit_verification_failed",
  "internal_error",
] as const;

export type Phase3AtomicApplyHelperErrorCode =
  (typeof phase3AtomicApplyHelperErrorCodes)[number];

export type Phase3AtomicApplyErrorCode =
  | "invalid_path"
  | "invalid_digest"
  | "content_too_large"
  | "content_digest_mismatch"
  | "operation_cancelled"
  | "deadline_exceeded"
  | "unsupported_platform"
  | "invalid_root"
  | "invalid_helper"
  | "queue_full"
  | "helper_spawn_failed"
  | "helper_protocol"
  | "helper_exit"
  | "helper_signal"
  | "helper_stdin_failed"
  | "helper_timeout"
  | Phase3AtomicApplyHelperErrorCode;

export class Phase3AtomicApplyError extends Error {
  constructor(
    public readonly code: Phase3AtomicApplyErrorCode,
    message: string,
    public readonly commitStatus: Phase3CommitStatus,
  ) {
    super(message);
    this.name = "Phase3AtomicApplyError";
  }
}

export interface Phase3AtomicApplyRunnerRequest {
  readonly helperPath: string;
  readonly root: string;
  readonly path: string;
  readonly expectedSha256: string;
  readonly contentSha256: string;
  readonly byteLength: number;
  readonly stdin: Uint8Array;
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
  readonly stdoutLimit: number;
  readonly stderrLimit: number;
  readonly terminationGraceMs: number;
}

export interface Phase3AtomicApplyRunnerResult {
  readonly started: boolean;
  readonly stdout: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stderrBytes: number;
  readonly stdoutTruncated?: boolean;
  readonly stdinError?: string;
  readonly spawnError?: string;
  readonly timedOut?: boolean;
  readonly forcedKill?: boolean;
}

export interface Phase3AtomicApplyRunner {
  run(
    request: Phase3AtomicApplyRunnerRequest,
  ): Promise<Phase3AtomicApplyRunnerResult>;
}

interface Waiter {
  active: boolean;
  timer: NodeJS.Timeout | undefined;
  readonly context: Phase3OperationContext;
  readonly resolve: (release: () => void) => void;
  readonly reject: (error: Phase3AtomicApplyError) => void;
  readonly abort: () => void;
}

interface ParsedFrame {
  readonly status: Phase3CommitStatus;
  readonly errorCode?: Phase3AtomicApplyHelperErrorCode;
}

export class NativePhase3AtomicApply implements Phase3AtomicApplyPort {
  private readonly root: string;
  private readonly helperPath: string;
  private readonly platform: NodeJS.Platform;
  private readonly runner: Phase3AtomicApplyRunner;
  private readonly maxConcurrent: number;
  private readonly maxWaiters: number;
  private readonly terminationGraceMs: number;
  private active = 0;
  private readonly waiters: Waiter[] = [];

  constructor(
    options: Readonly<{
      root?: string;
      helperPath?: string;
      platform?: NodeJS.Platform;
      runner?: Phase3AtomicApplyRunner;
      maxConcurrent?: number;
      maxWaiters?: number;
      terminationGraceMs?: number;
    }> = {},
  ) {
    this.root = options.root ?? "/homeassistant";
    this.helperPath = options.helperPath ?? "/app/native/openat2-replace";
    this.platform = options.platform ?? process.platform;
    this.runner = options.runner ?? new SpawnPhase3AtomicApplyRunner();
    this.maxConcurrent = positiveInt(options.maxConcurrent ?? 1, 1);
    this.maxWaiters = positiveInt(options.maxWaiters ?? 8, 8);
    this.terminationGraceMs = positiveInt(
      options.terminationGraceMs ?? 1000,
      1000,
    );
  }

  async replace(
    input: Readonly<{
      path: string;
      expectedSha256: string;
      content: Uint8Array;
      contentSha256: string;
    }>,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ status: Phase3CommitStatus }>> {
    const path = validatedPath(input.path);
    const expectedSha256 = validatedDigest(input.expectedSha256);
    const contentSha256 = validatedDigest(input.contentSha256);
    if (input.content.byteLength > PHASE2_MAX_TEXT_BYTES)
      throw fail("content_too_large", "Candidate content is too large");
    if (digest(input.content) !== contentSha256)
      throw fail(
        "content_digest_mismatch",
        "Candidate content digest does not match",
      );
    assertActive(context);
    if (this.platform !== "linux")
      throw fail("unsupported_platform", "Native atomic apply requires Linux");
    const root = validatedAbsolute("invalid_root", this.root);
    const helperPath = validatedAbsolute("invalid_helper", this.helperPath);
    const release = await this.acquire(context);
    let candidate: Uint8Array | undefined;
    try {
      assertActive(context);
      candidate = Uint8Array.from(input.content);
      const result = await this.runner.run({
        helperPath,
        root,
        path,
        expectedSha256,
        contentSha256,
        byteLength: candidate.byteLength,
        stdin: candidate,
        signal: context.signal,
        deadlineAt: context.deadlineAt,
        stdoutLimit: phase3AtomicApplyStdoutLimit,
        stderrLimit: phase3AtomicApplyStderrLimit,
        terminationGraceMs: this.terminationGraceMs,
      });
      return classifyRunnerResult(result);
    } finally {
      candidate?.fill(0);
      release();
    }
  }

  private async acquire(context: Phase3OperationContext): Promise<() => void> {
    assertActive(context);
    if (this.active < this.maxConcurrent) {
      this.active += 1;
      try {
        assertActive(context);
      } catch (error) {
        this.release();
        throw error;
      }
      return () => this.release();
    }
    if (this.waiters.length >= this.maxWaiters)
      throw fail("queue_full", "Atomic apply waiter queue is full");
    return await new Promise<() => void>((resolve, reject) => {
      const waiter: Waiter = {
        active: true,
        timer: undefined,
        context,
        resolve,
        reject,
        abort: () => {
          if (!waiter.active) return;
          waiter.active = false;
          this.removeWaiter(waiter);
          cleanupWaiter(waiter);
          reject(
            fail("operation_cancelled", "Atomic apply wait was cancelled"),
          );
        },
      };
      context.signal.addEventListener("abort", waiter.abort, { once: true });
      const delay = context.deadlineAt - Date.now();
      if (delay <= 0) {
        cleanupWaiter(waiter);
        reject(fail("deadline_exceeded", "Atomic apply wait deadline expired"));
        return;
      }
      waiter.timer = setTimeout(() => {
        if (!waiter.active) return;
        waiter.active = false;
        this.removeWaiter(waiter);
        cleanupWaiter(waiter);
        reject(fail("deadline_exceeded", "Atomic apply wait deadline expired"));
      }, delay);
      this.waiters.push(waiter);
    });
  }

  private release(): void {
    this.active = Math.max(0, this.active - 1);
    for (;;) {
      const waiter = this.waiters.shift();
      if (!waiter) return;
      if (!waiter.active) continue;
      try {
        assertActive(waiter.context);
      } catch (error) {
        waiter.active = false;
        cleanupWaiter(waiter);
        waiter.reject(error as Phase3AtomicApplyError);
        continue;
      }
      waiter.active = false;
      cleanupWaiter(waiter);
      this.active += 1;
      waiter.resolve(() => this.release());
      return;
    }
  }

  private removeWaiter(waiter: Waiter): void {
    const index = this.waiters.indexOf(waiter);
    if (index >= 0) this.waiters.splice(index, 1);
  }
}

export class SpawnPhase3AtomicApplyRunner implements Phase3AtomicApplyRunner {
  async run(
    request: Phase3AtomicApplyRunnerRequest,
  ): Promise<Phase3AtomicApplyRunnerResult> {
    const args = [
      request.root,
      request.path,
      request.expectedSha256,
      request.contentSha256,
      String(request.byteLength),
    ];
    let child;
    try {
      child = spawn(request.helperPath, args, {
        cwd: "/",
        env: {},
        shell: false,
        detached: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      return spawnFailure(error);
    }

    let stdoutBytes = 0;
    let stdoutTruncated = false;
    let stdout = Buffer.alloc(0);
    let stderrBytes = 0;
    let stdinError: string | undefined;
    let spawnError: string | undefined;
    let timedOut = false;
    let forcedKill = false;
    let settled = false;
    let graceTimer: NodeJS.Timeout | undefined;
    let deadlineTimer: NodeJS.Timeout | undefined;
    const stdinCopy = Buffer.from(request.stdin);
    let stdinCopyZeroed = false;
    const zeroStdinCopy = (): void => {
      if (stdinCopyZeroed) return;
      stdinCopy.fill(0);
      stdinCopyZeroed = true;
    };

    const terminate = (timeout: boolean): void => {
      if (settled) return;
      timedOut ||= timeout;
      killProcessGroup(child.pid, "SIGTERM");
      graceTimer ??= setTimeout(() => {
        if (settled) return;
        forcedKill = true;
        killProcessGroup(child.pid, "SIGKILL");
      }, request.terminationGraceMs);
    };

    const abort = (): void => terminate(false);
    request.signal.addEventListener("abort", abort, { once: true });
    const delay = request.deadlineAt - Date.now();
    if (delay <= 0) terminate(true);
    else deadlineTimer = setTimeout(() => terminate(true), delay);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > request.stdoutLimit) {
        stdoutTruncated = true;
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes = Math.min(
        request.stderrLimit + 1,
        stderrBytes + chunk.byteLength,
      );
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnError = error.code ?? "spawn_error";
    });
    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      stdinError = error.code ?? "stdin_error";
      zeroStdinCopy();
    });
    child.stdin.on("close", zeroStdinCopy);
    child.stdin.end(stdinCopy);

    return await new Promise<Phase3AtomicApplyRunnerResult>((resolve) => {
      child.on("close", (exitCode, signal) => {
        settled = true;
        zeroStdinCopy();
        request.signal.removeEventListener("abort", abort);
        if (deadlineTimer) clearTimeout(deadlineTimer);
        if (graceTimer) clearTimeout(graceTimer);
        resolve({
          started: child.pid !== undefined,
          stdout: stdoutTruncated ? "" : stdout.toString("utf8"),
          exitCode,
          signal,
          stderrBytes,
          stdoutTruncated,
          timedOut,
          forcedKill,
          ...(stdinError !== undefined ? { stdinError } : {}),
          ...(spawnError !== undefined ? { spawnError } : {}),
        });
      });
    });
  }
}

function classifyRunnerResult(
  result: Phase3AtomicApplyRunnerResult,
): Readonly<{ status: Phase3CommitStatus }> {
  if (!result.started)
    throw new Phase3AtomicApplyError(
      "helper_spawn_failed",
      "Atomic apply helper did not start",
      "before_commit",
    );
  const frame = parseFrame(result.stdout, result.stdoutTruncated === true);
  if (
    result.stdinError !== undefined ||
    result.forcedKill === true ||
    result.timedOut === true ||
    result.signal !== null ||
    result.exitCode !== 0
  ) {
    if (frame?.status === "before_commit") return frameResult(frame);
    const code =
      result.stdinError !== undefined
        ? "helper_stdin_failed"
        : result.timedOut === true
          ? "helper_timeout"
          : result.signal !== null
            ? "helper_signal"
            : "helper_exit";
    throw new Phase3AtomicApplyError(
      code,
      "Atomic apply helper ended without a trusted precommit frame",
      "commit_unknown",
    );
  }
  if (!frame)
    throw new Phase3AtomicApplyError(
      "helper_protocol",
      "Atomic apply helper returned an invalid protocol frame",
      "commit_unknown",
    );
  return frameResult(frame);
}

function frameResult(
  frame: ParsedFrame,
): Readonly<{ status: Phase3CommitStatus }> {
  if (frame.errorCode)
    throw new Phase3AtomicApplyError(
      frame.errorCode,
      "Atomic apply helper failed",
      frame.status,
    );
  return Object.freeze({ status: frame.status });
}

function parseFrame(stdout: string, truncated: boolean): ParsedFrame | null {
  if (truncated) return null;
  const match =
    /^phase3-atomic-apply-v1 status=(before_commit|committed|commit_unknown)(?: error=([a-z_]+))?\n$/u.exec(
      stdout,
    );
  if (!match) return null;
  const status = match[1] as Phase3CommitStatus;
  const code = match[2];
  if (code === undefined) return { status };
  if (status === "committed" || !isHelperErrorCode(code)) return null;
  return { status, errorCode: code };
}

function validatedPath(path: string): string {
  try {
    return canonicalPhase3Path(path);
  } catch {
    throw fail("invalid_path", "Atomic apply path is invalid");
  }
}

function validatedDigest(value: string): string {
  const normalized = value.toLowerCase();
  if (value !== normalized || !/^[a-f0-9]{64}$/u.test(value))
    throw fail("invalid_digest", "Atomic apply digest is invalid");
  return value;
}

function validatedAbsolute(
  code: "invalid_root" | "invalid_helper",
  value: string,
): string {
  if (
    value.includes("\0") ||
    !value.startsWith("/") ||
    posixPath.normalize(value) !== value
  )
    throw fail(code, "Atomic apply path must be absolute and normalized");
  return value;
}

function assertActive(context: Phase3OperationContext): void {
  if (context.signal.aborted)
    throw fail("operation_cancelled", "Atomic apply operation was cancelled");
  if (Date.now() >= context.deadlineAt)
    throw fail("deadline_exceeded", "Atomic apply deadline expired");
}

function fail(
  code: Phase3AtomicApplyErrorCode,
  message: string,
): Phase3AtomicApplyError {
  return new Phase3AtomicApplyError(code, message, "before_commit");
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function isHelperErrorCode(
  code: string,
): code is Phase3AtomicApplyHelperErrorCode {
  return phase3AtomicApplyHelperErrorCodes.includes(
    code as Phase3AtomicApplyHelperErrorCode,
  );
}

function cleanupWaiter(waiter: Waiter): void {
  waiter.context.signal.removeEventListener("abort", waiter.abort);
  if (waiter.timer) clearTimeout(waiter.timer);
  waiter.timer = undefined;
}

function positiveInt(value: number, fallback: number): number {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function killProcessGroup(
  pid: number | undefined,
  signal: NodeJS.Signals,
): void {
  if (pid === undefined) return;
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      // Process may already be gone.
    }
  }
}

function spawnFailure(error: unknown): Phase3AtomicApplyRunnerResult {
  return {
    started: false,
    stdout: "",
    exitCode: null,
    signal: null,
    stderrBytes: 0,
    spawnError:
      typeof error === "object" && error !== null && "code" in error
        ? String((error as { readonly code: unknown }).code)
        : "spawn_error",
  };
}
