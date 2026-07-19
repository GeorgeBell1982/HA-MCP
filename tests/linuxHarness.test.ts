import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("Slice G2 repository-owned Linux harnesses", () => {
  it("makes every Git candidate matrix family mandatory and machine-readable", async () => {
    const source = await readFile(
      new URL("../scripts/linux/git-candidate-harness.mjs", import.meta.url),
      "utf8",
    );
    for (const token of [
      '"clean"',
      '"staged"',
      '"unstaged"',
      '"staged+unstaged"',
      '"untracked"',
      '"born"',
      '"unborn"',
      '"detached"',
      '"sha1"',
      '"sha256"',
      "status: 1",
      '"object-format": 2',
      "index: 3",
      "tree: 4",
      "objects: 5",
      '"filter.process"',
      '"filter.clean"',
      '"filter.smudge"',
      '"diff.external"',
      '"lazy-fetch-promisor"',
      '"alternates"',
      '"linked"',
      '"bare"',
      '"common-dir"',
      '"worktree"',
      '"submodule"',
      '"rlimits:all"',
      '"missing-loader"',
      '"nonregular"',
      '"over-limit"',
      'type: "manifest"',
      'type: "row"',
      'type: "summary"',
      "mandatory row registry mismatch",
      "assertNoProcessGroup",
      "treeDigest(root) === before",
      'canary: "absent"',
      "mkdirSync(parent, { recursive: true, mode: 0o700 })",
      'error.code === "EPIPE"',
      'error.code === "ERR_STREAM_DESTROYED"',
      "peerCloseErrors.length <= 1",
      'peerClose: peerCloseErrors[0] ?? "clean-close"',
      'child.once("close", resolvePromise)',
    ])
      expect(source).toContain(token);
    expect(source).not.toContain("shell: true");
  });

  it("makes every persistence reliability row mandatory and Linux-only", async () => {
    const [harness, worker, shim, probe, addon] = await Promise.all([
      readFile(
        new URL("../scripts/linux/persistence-harness.mjs", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL("../scripts/linux/persistence-worker.mjs", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL("../scripts/linux/persistence-fault-shim.c", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL(
          "../scripts/linux/persistence-syscall-probe.c",
          import.meta.url,
        ),
        "utf8",
      ),
      readFile(new URL("../addon/Dockerfile", import.meta.url), "utf8"),
    ]);
    for (const token of [
      "proposal",
      "journal",
      "audit",
      "rotation",
      "quarantine",
      "journal_prepared",
      "effect_committed",
      "outcome_committed",
      "identity-race",
      "tmpfs-enospc",
      "assertScopedProof",
      "HA_FAULT_ROOT",
      "mandatory persistence row registry mismatch",
      "assertNoProcessGroup",
      '"UNVERIFIED"',
      '"BLOCKED"',
      '"-Wall"',
      '"-Wextra"',
      '"-Werror"',
      'type: "manifest"',
      'type: "row"',
      'type: "summary"',
    ])
      expect(harness).toContain(token);
    for (const token of [
      "ProposalService",
      "ProposalCursorCodec",
      "inspectSubsystem",
      "proposal-paused",
      "recover-transaction",
    ])
      expect(worker).toContain(token);
    for (const token of [
      "HA_FAULT_ARM",
      "HA_FAULT_ROOT",
      "SYS_getcwd",
      "SYS_readlinkat",
      "scoped_path",
      "target",
      "SYS_newfstatat",
      "open64",
      "pwrite",
      "writev",
      "fdatasync",
      "renameat2",
    ])
      expect(shim).toContain(token);
    for (const token of [
      "openat64",
      "writev",
      "renameat2",
      "dlsym",
      "RTLD_DEFAULT",
    ])
      expect(probe).toContain(token);
    expect(probe.indexOf("#define _GNU_SOURCE")).toBe(0);
    expect(probe.indexOf("#include <errno.h>")).toBeGreaterThan(
      probe.indexOf("#define _GNU_SOURCE"),
    );
    expect(shim.indexOf("#define _GNU_SOURCE")).toBe(0);
    expect(shim.indexOf("#include <dlfcn.h>")).toBeGreaterThan(
      shim.indexOf("#define _GNU_SOURCE"),
    );
    expect(addon).not.toContain("persistence-harness");
    expect(addon).not.toContain("persistence-fault-shim");
  });
});
