import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PHASE2_MAX_TEXT_BYTES } from "../src/phase2Contracts.js";
import {
  NativePhase3AtomicApply,
  Phase3AtomicApplyError,
  type Phase3AtomicApplyRunner,
  type Phase3AtomicApplyRunnerRequest,
  type Phase3AtomicApplyRunnerResult,
} from "../src/phase3/atomicApply.js";
import type { Phase3OperationContext } from "../src/phase3/applyCoordinator.js";
import { sha256, type Phase3CommitStatus } from "../src/phase3/contracts.js";

const oldBytes = Buffer.from("old: true\n");
const newBytes = Buffer.from("old: false\n");
const oldSha = sha256(oldBytes);
const newSha = sha256(newBytes);

function context(controller = new AbortController()): Phase3OperationContext {
  return { signal: controller.signal, deadlineAt: Date.now() + 10_000 };
}

function input(
  patch: Partial<Parameters<NativePhase3AtomicApply["replace"]>[0]> = {},
) {
  return {
    path: "automations/lights.yaml",
    expectedSha256: oldSha,
    content: Uint8Array.from(newBytes),
    contentSha256: newSha,
    ...patch,
  };
}

function frame(status: Phase3CommitStatus, error?: string): string {
  return `phase3-atomic-apply-v1 status=${status}${error ? ` error=${error}` : ""}\n`;
}

function result(
  stdout: string,
  patch: Partial<Phase3AtomicApplyRunnerResult> = {},
): Phase3AtomicApplyRunnerResult {
  return {
    started: true,
    stdout,
    exitCode: 0,
    signal: null,
    stderrBytes: 0,
    ...patch,
  };
}

class QueueRunner implements Phase3AtomicApplyRunner {
  readonly calls: Phase3AtomicApplyRunnerRequest[] = [];
  private readonly responses: (
    | Phase3AtomicApplyRunnerResult
    | ((
        request: Phase3AtomicApplyRunnerRequest,
      ) => Promise<Phase3AtomicApplyRunnerResult>)
  )[];

  constructor(
    ...responses: (
      | Phase3AtomicApplyRunnerResult
      | ((
          request: Phase3AtomicApplyRunnerRequest,
        ) => Promise<Phase3AtomicApplyRunnerResult>)
    )[]
  ) {
    this.responses = responses;
  }

  async run(
    request: Phase3AtomicApplyRunnerRequest,
  ): Promise<Phase3AtomicApplyRunnerResult> {
    this.calls.push(request);
    const response = this.responses.shift() ?? result(frame("committed"));
    if (typeof response === "function") return await response(request);
    return response;
  }
}

function adapter(runner: Phase3AtomicApplyRunner, extra = {}) {
  return new NativePhase3AtomicApply({
    platform: "linux",
    root: "/homeassistant",
    helperPath: "/app/native/openat2-replace",
    runner,
    ...extra,
  });
}

async function expectAtomicError(
  promise: Promise<unknown>,
  code: string,
  commitStatus: Phase3CommitStatus,
): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code, commitStatus });
}

describe("Phase 3F native atomic apply adapter", () => {
  it("validates inputs before spawning and preserves caller bytes", async () => {
    const cases: readonly [string, Parameters<typeof input>[0], string][] = [
      ["invalid path", { path: "../configuration.yaml" }, "invalid_path"],
      [
        "uppercase expected",
        { expectedSha256: oldSha.toUpperCase() },
        "invalid_digest",
      ],
      [
        "uppercase content",
        { contentSha256: newSha.toUpperCase() },
        "invalid_digest",
      ],
      ["bad digest", { expectedSha256: "abc" }, "invalid_digest"],
      [
        "oversize content",
        {
          content: new Uint8Array(PHASE2_MAX_TEXT_BYTES + 1),
          contentSha256: sha256(new Uint8Array(PHASE2_MAX_TEXT_BYTES + 1)),
        },
        "content_too_large",
      ],
      [
        "digest mismatch",
        { contentSha256: sha256("different") },
        "content_digest_mismatch",
      ],
    ];
    for (const [, patch, code] of cases) {
      const runner = new QueueRunner();
      await expectAtomicError(
        adapter(runner).replace(input(patch), context()),
        code,
        "before_commit",
      );
      expect(runner.calls).toEqual([]);
    }

    const cancelled = new AbortController();
    cancelled.abort();
    const cancelledRunner = new QueueRunner();
    await expectAtomicError(
      adapter(cancelledRunner).replace(input(), context(cancelled)),
      "operation_cancelled",
      "before_commit",
    );
    expect(cancelledRunner.calls).toEqual([]);

    const deadlineRunner = new QueueRunner();
    await expectAtomicError(
      adapter(deadlineRunner).replace(input(), {
        signal: new AbortController().signal,
        deadlineAt: Date.now() - 1,
      }),
      "deadline_exceeded",
      "before_commit",
    );
    expect(deadlineRunner.calls).toEqual([]);

    const platformRunner = new QueueRunner();
    await expectAtomicError(
      new NativePhase3AtomicApply({
        platform: "win32",
        runner: platformRunner,
      }).replace(input(), context()),
      "unsupported_platform",
      "before_commit",
    );
    expect(platformRunner.calls).toEqual([]);
  });

  it("spawns a fixed no-shell helper request with owned stdin and zeroes the owned copy", async () => {
    const runner = new QueueRunner(result(frame("committed")));
    const candidate = Uint8Array.from(newBytes);
    const output = await adapter(runner).replace(
      input({ content: candidate }),
      context(),
    );
    expect(output.status).toBe("committed");
    expect(Buffer.from(candidate).equals(newBytes)).toBe(true);
    expect(runner.calls).toHaveLength(1);
    const call = runner.calls[0]!;
    expect(call).toMatchObject({
      helperPath: "/app/native/openat2-replace",
      root: "/homeassistant",
      path: "automations/lights.yaml",
      expectedSha256: oldSha,
      contentSha256: newSha,
      byteLength: newBytes.byteLength,
      stdoutLimit: 256,
      stderrLimit: 4096,
    });
    expect(call.stdin).not.toBe(candidate);
    expect([...call.stdin]).toEqual([...new Uint8Array(newBytes.byteLength)]);
  });

  it.each([
    ["committed", "committed"],
    ["before_commit", "before_commit"],
    ["commit_unknown", "commit_unknown"],
  ] as const)("accepts exact %s protocol frames", async (status, expected) => {
    const runner = new QueueRunner(result(frame(status)));
    await expect(adapter(runner).replace(input(), context())).resolves.toEqual({
      status: expected,
    });
  });

  it("turns helper error frames into stable classified errors", async () => {
    const before = new QueueRunner(
      result(frame("before_commit", "race_detected")),
    );
    await expectAtomicError(
      adapter(before).replace(input(), context()),
      "race_detected",
      "before_commit",
    );
    const pending = new QueueRunner(
      result(frame("before_commit", "pending_blocked")),
    );
    await expectAtomicError(
      adapter(pending).replace(input(), context()),
      "pending_blocked",
      "before_commit",
    );

    const unknown = new QueueRunner(
      result(frame("commit_unknown", "commit_verification_failed")),
    );
    await expectAtomicError(
      adapter(unknown).replace(input(), context()),
      "commit_verification_failed",
      "commit_unknown",
    );
  });

  it.each([
    ["missing", ""],
    ["malformed", "not a frame\n"],
    ["trailing", `${frame("committed")}extra`],
    ["unknown error", frame("before_commit", "surprise")],
    ["committed with error", frame("committed", "internal_error")],
  ])(
    "treats %s stdout as commit_unknown protocol failure",
    async (_name, stdout) => {
      await expectAtomicError(
        adapter(new QueueRunner(result(stdout))).replace(input(), context()),
        "helper_protocol",
        "commit_unknown",
      );
    },
  );

  it.each([
    [
      "spawn",
      {
        started: false,
        spawnError: "ENOENT",
        stdout: "",
        exitCode: null,
        signal: null,
        stderrBytes: 0,
      },
      "helper_spawn_failed",
      "before_commit",
    ],
    ["exit", result("", { exitCode: 7 }), "helper_exit", "commit_unknown"],
    [
      "signal",
      result("", { signal: "SIGKILL" }),
      "helper_signal",
      "commit_unknown",
    ],
    [
      "stdin",
      result(frame("committed"), { stdinError: "EPIPE" }),
      "helper_stdin_failed",
      "commit_unknown",
    ],
    [
      "timeout",
      result(frame("committed"), { timedOut: true }),
      "helper_timeout",
      "commit_unknown",
    ],
    [
      "forced kill",
      result(frame("committed"), { forcedKill: true }),
      "helper_exit",
      "commit_unknown",
    ],
  ] as const)(
    "classifies %s after process start conservatively",
    async (_name, runnerResult, code, status) => {
      await expectAtomicError(
        adapter(new QueueRunner(runnerResult)).replace(input(), context()),
        code,
        status,
      );
    },
  );

  it("trusts an exact before_commit frame despite abnormal process completion", async () => {
    const runner = new QueueRunner(
      result(frame("before_commit"), { signal: "SIGTERM" }),
    );
    await expect(adapter(runner).replace(input(), context())).resolves.toEqual({
      status: "before_commit",
    });
  });

  it("zeros owned stdin after helper failures", async () => {
    const runner = new QueueRunner(result("bad\n"));
    await expectAtomicError(
      adapter(runner).replace(input(), context()),
      "helper_protocol",
      "commit_unknown",
    );
    expect(runner.calls[0]!.stdin.every((byte) => byte === 0)).toBe(true);
  });

  it("bounds concurrency and waiter queue before spawning fixed helpers", async () => {
    let releaseFirst!: (value: Phase3AtomicApplyRunnerResult) => void;
    const runner = new QueueRunner(
      () =>
        new Promise<Phase3AtomicApplyRunnerResult>((resolve) => {
          releaseFirst = resolve;
        }),
      result(frame("committed")),
    );
    const port = adapter(runner, { maxConcurrent: 1, maxWaiters: 1 });
    const first = port.replace(input(), context());
    const second = port.replace(input(), context());
    await new Promise((resolve) => setTimeout(resolve, 0));
    await expectAtomicError(
      port.replace(input(), context()),
      "queue_full",
      "before_commit",
    );
    expect(runner.calls).toHaveLength(1);
    releaseFirst(result(frame("committed")));
    await expect(first).resolves.toEqual({ status: "committed" });
    await expect(second).resolves.toEqual({ status: "committed" });
    expect(runner.calls).toHaveLength(2);
  });

  it("cancels queued work before helper spawn and lets post-exchange completion return", async () => {
    let releaseFirst!: (value: Phase3AtomicApplyRunnerResult) => void;
    const controller = new AbortController();
    const runner = new QueueRunner(
      () =>
        new Promise<Phase3AtomicApplyRunnerResult>((resolve) => {
          releaseFirst = resolve;
        }),
      result(frame("committed")),
    );
    const port = adapter(runner, { maxConcurrent: 1, maxWaiters: 2 });
    const first = port.replace(input(), context());
    const queued = port.replace(input(), context(controller));
    controller.abort();
    await expectAtomicError(queued, "operation_cancelled", "before_commit");
    releaseFirst(result(frame("committed")));
    await expect(first).resolves.toEqual({ status: "committed" });
    expect(runner.calls).toHaveLength(1);

    const postExchange = new QueueRunner(result(frame("committed")));
    const postController = new AbortController();
    const completed = await adapter(postExchange).replace(
      input(),
      context(postController),
    );
    postController.abort();
    expect(completed.status).toBe("committed");
  });
});

describe("Phase 3F native helper source contract", () => {
  const source = readFileSync("src/phase3/native/openat2-replace.c", "utf8");

  it("declares Linux openat2, OpenSSL SHA256, O_TMPFILE, linkat, and exchange-only replacement", () => {
    expect(source).toContain("#include <linux/openat2.h>");
    expect(source).toContain("extern unsigned char *SHA256");
    expect(source).toContain("O_TMPFILE");
    expect(source).toContain('linkat(tmp, "", parent, pending, AT_EMPTY_PATH)');
    expect(source).toContain("SYS_renameat2");
    expect(source).toContain("RENAME_EXCHANGE");
    expect(source).toContain("rename_exchange(parent, pending, base)");
    expect(source).not.toContain("rename_exchange(parent, base, pending)");
    expect(source).not.toContain("RENAME_NOREPLACE");
    expect(source).not.toContain("O_CREAT");
  });

  it("contains fail-closed safety checks for target identity, xattrs, races, and staged cleanup", () => {
    expect(source).toContain("RESOLVE_BENEATH");
    expect(source).toContain("RESOLVE_NO_SYMLINKS");
    expect(source).toContain("RESOLVE_NO_MAGICLINKS");
    expect(source).toContain("RESOLVE_NO_XDEV");
    expect(source).toContain("flistxattr");
    expect(source).toContain("scan_pending_blockers(parent)");
    expect(source).toContain("errno = 0;");
    expect(source).toContain(
      "return same_file_identity_metadata(&st, expected) ? 0 : -1;",
    );
    expect(source).toContain("O_RDONLY | O_DIRECTORY | O_CLOEXEC");
    expect(source).toContain(
      "same_file_identity_metadata(&current_st, &staged_link)",
    );
    expect(source).toContain(
      "validate_staged_file(displaced, &target_preexchange)",
    );
    expect(source).toContain("secure_bzero");
    expect(source).toContain("fsync(parent)");
    expect(source).toContain('fail_before("race_detected")');
    expect(source).toContain("unlinkat(parent, pending, 0)");
    expect(source).toContain('fail_unknown("commit_verification_failed")');
    expect(source).toContain('test_fail_stage("pre_exchange")');
    expect(source).toContain('test_fail_stage("exchange")');
    expect(source).toContain('test_fail_stage("post_exchange")');
  });
});
