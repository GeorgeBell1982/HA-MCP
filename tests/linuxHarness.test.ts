import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("Slice G2 repository-owned Linux harnesses", () => {
  it("makes candidate-image validation mandatory and machine-readable", async () => {
    const source = await readFile(
      new URL("../scripts/linux/candidate-image-harness.mjs", import.meta.url),
      "utf8",
    );
    for (const token of [
      '"image:metadata"',
      '"image:native-paths"',
      '"image:native-artifacts"',
      '"image:linkage"',
      '"image:git-protocol-matrix"',
      '"image:setuid-setgid"',
      '"image:writable-dirs"',
      '"image:offline-startup"',
      "mandatory candidate-image row registry mismatch",
      'type: "manifest"',
      'type: "row"',
      'type: "summary"',
      '["/run.sh"]',
      "/app/native/openat2-read",
      "/app/native/openat2-list",
      "/app/native/git-broker",
      "root:root 555 regular file",
      "git-candidate-harness.mjs",
      "--network",
      "none",
      "apk add|fetch",
      "/var/tmp",
    ])
      expect(source).toContain(token);
    expect(source).not.toContain("shell: true");
  });

  it("fails candidate-image validation when frozen evidence mismatches", async () => {
    const base = await mkdtemp(join(tmpdir(), "candidate-image-harness-"));
    const fakeDocker = join(
      base,
      process.platform === "win32" ? "docker.cmd" : "docker",
    );
    const fakeDockerScript = join(base, "fake-docker.mjs");
    await writeFile(
      fakeDockerScript,
      `#!/usr/bin/env node
const args = process.argv.slice(2);
const mode = process.env.FAKE_DOCKER_MODE ?? "ok";
const hashes = new Map([
  ["/app/native/git-broker", "01823637f02c49e685f84a2b371870945299e772b6dc37dbf9194b2f34f051f8"],
  ["/app/native/openat2-list", "6fe9587146b927b6f84c53a3d61efd87e6143c9ee95268b9c997d464260bab51"],
  ["/app/native/openat2-read", "59faab9a79575409e59b3672cb1ecb50a9f3b3a7d0db85f1065d499a3c7c425f"],
  ["/usr/bin/git", "5b5cbd6facf5d86226063d69fe57064bc5ad79bdccee2af0ac787646c564a880"],
  ["/lib/ld-musl-x86_64.so.1", "7d221f4e17e8f7ebfc208d6e621bb7fc71bc99081bed47409d77048d9a69dbd5"],
  ["/usr/lib/libpcre2-8.so.0.14.0", "0eae946d1f2746b6c64cc8beb9230360dc935e8552f89b765c7e697bff232345"],
  ["/usr/lib/libz.so.1.3.1", "09b1bbd6ffe274039cefaca595f55cec0af65fe90d9e285e5d57ff7ed96948d2"],
]);
function out(value) { process.stdout.write(value); }
if (args[0] === "image" && args[1] === "inspect") {
  const labels = mode === "labels" ? { bad: "label" } : mode === "ha-labels" ? { "io.hass.arch": "aarch64" } : null;
  out(JSON.stringify([{ Id: mode === "bad-id" ? "sha256:bad" : "sha256:60d3d5d8fda4f2bee464e02cf99b6394cd787f62572a9a01934f100864c68cb1", RepoDigests: [], Architecture: "amd64", Os: "linux", Config: { Cmd: ["/run.sh"], Labels: labels } }]));
  process.exit(0);
}
if (args[0] === "run" && (!args.includes("--platform") || !args.includes("linux/amd64"))) {
  process.stderr.write("missing expected platform\\n");
  process.exit(1);
}
if (args[0] === "run" && args.includes("--entrypoint") && args.includes("node")) {
  if (!args.includes(process.cwd() + ":/work:ro")) {
    process.stderr.write("missing readonly work bind\\n");
    process.exit(1);
  }
  out('{"type":"summary","status":"PASSED","required":74,"executed":74,"passed":74,"failed":[]}\\n');
  process.exit(0);
}
if (args[0] === "run" && args.includes("-lc")) {
  const command = args.at(-1);
  if (command.includes("/app/native/*")) {
    out("file /app/native/git-broker\\nfile /app/native/openat2-list\\nfile /app/native/openat2-read\\n");
    if (mode === "extra-native-entry") out("dir /app/native/debug\\n");
  } else if (command.includes("readlink -f")) {
    const zlibTarget = mode === "bad-link-target" ? "/usr/lib/libz.so.1.2.13" : "/usr/lib/libz.so.1.3.1";
    out("/lib/ld-musl-x86_64.so.1 -> /lib/ld-musl-x86_64.so.1\\n" + hashes.get("/lib/ld-musl-x86_64.so.1") + "  /lib/ld-musl-x86_64.so.1\\n");
    out("/usr/lib/libpcre2-8.so.0 -> /usr/lib/libpcre2-8.so.0.14.0\\n" + hashes.get("/usr/lib/libpcre2-8.so.0.14.0") + "  /usr/lib/libpcre2-8.so.0.14.0\\n");
    out("/usr/lib/libz.so.1 -> " + zlibTarget + "\\n" + hashes.get("/usr/lib/libz.so.1.3.1") + "  " + zlibTarget + "\\n");
  } else if (command.includes("sha256sum")) {
    out("root:root 555 regular file /app/native/git-broker\\nroot:root 555 regular file /app/native/openat2-list\\nroot:root 555 regular file /app/native/openat2-read\\n");
    for (const [path, digest] of hashes) out((mode === "bad-hash" && path === "/app/native/git-broker" ? "0".repeat(64) : digest) + "  " + path + "\\n");
  } else if (command.includes("ldd")) {
    out("/lib/ld-musl-x86_64.so.1 (0x1)\\nlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x1)\\nlibpcre2-8.so.0 => /usr/lib/libpcre2-8.so.0 (0x1)\\nlibz.so.1 => /usr/lib/libz.so.1 (0x1)\\n");
    if (mode === "extra-link") out("libextra.so.1 => /usr/lib/libextra.so.1 (0x1)\\n");
  } else if (command.includes("-perm -4000"))
    out(mode === "ha-setid" ? "/package/admin/s6-overlay-helpers/command/s6-overlay-suexec\\n" : "");
  else if (command.includes("-perm -0002")) out("/tmp\\n/var/tmp\\n");
  process.exit(0);
}
if (args[0] === "run") process.exit(mode === "startup-success" ? 0 : 127);
process.exit(99);
`,
    );
    if (process.platform === "win32")
      await writeFile(
        fakeDocker,
        `@echo off\r\n"${process.execPath}" "${fakeDockerScript}" %*\r\n`,
      );
    else {
      await writeFile(
        fakeDocker,
        `#!/bin/sh\n"${process.execPath}" "${fakeDockerScript}" "$@"\n`,
      );
      await chmod(fakeDocker, 0o700);
    }

    const script = new URL(
      "../scripts/linux/candidate-image-harness.mjs",
      import.meta.url,
    );
    const baseArgs = [
      fileURLToPath(script),
      "--image",
      "candidate:test",
      "--expected-image-id",
      "sha256:60d3d5d8fda4f2bee464e02cf99b6394cd787f62572a9a01934f100864c68cb1",
      "--expected-architecture",
      "amd64",
      "--expect-no-labels",
      "true",
      "--runtime-loader",
      "/lib/ld-musl-x86_64.so.1",
      "--runtime-input",
      "/usr/lib/libpcre2-8.so.0.14.0",
      "--runtime-input",
      "/usr/lib/libz.so.1.3.1",
      "--expected-startup-status",
      "null",
      "--expected-startup-signal",
      "SIGTERM",
      "--expected-startup-timed-out",
      "true",
      "--startup-timeout-ms",
      "10",
      "--expected-sha256",
      "/app/native/git-broker=sha256:01823637f02c49e685f84a2b371870945299e772b6dc37dbf9194b2f34f051f8",
      "--expected-sha256",
      "/app/native/openat2-list=sha256:6fe9587146b927b6f84c53a3d61efd87e6143c9ee95268b9c997d464260bab51",
      "--expected-sha256",
      "/app/native/openat2-read=sha256:59faab9a79575409e59b3672cb1ecb50a9f3b3a7d0db85f1065d499a3c7c425f",
      "--expected-sha256",
      "/usr/bin/git=sha256:5b5cbd6facf5d86226063d69fe57064bc5ad79bdccee2af0ac787646c564a880",
      "--expected-sha256",
      "/lib/ld-musl-x86_64.so.1=sha256:7d221f4e17e8f7ebfc208d6e621bb7fc71bc99081bed47409d77048d9a69dbd5",
      "--expected-sha256",
      "/usr/lib/libpcre2-8.so.0.14.0=sha256:0eae946d1f2746b6c64cc8beb9230360dc935e8552f89b765c7e697bff232345",
      "--expected-sha256",
      "/usr/lib/libz.so.1.3.1=sha256:09b1bbd6ffe274039cefaca595f55cec0af65fe90d9e285e5d57ff7ed96948d2",
    ];
    async function expectHarnessFailure(
      args: string[],
      environment: NodeJS.ProcessEnv,
      expected: string,
    ) {
      try {
        await execFileAsync(process.execPath, args, { env: environment });
      } catch (error) {
        const stdout =
          typeof (error as { stdout?: unknown }).stdout === "string"
            ? (error as { stdout: string }).stdout
            : "";
        expect(stdout).toContain(expected);
        return;
      }
      throw new Error("expected candidate-image harness failure");
    }

    const env = {
      ...process.env,
      HA_CANDIDATE_IMAGE_HARNESS_DOCKER: process.execPath,
      HA_CANDIDATE_IMAGE_HARNESS_DOCKER_ARGV: JSON.stringify([
        fakeDockerScript,
      ]),
    };
    await expect(
      execFileAsync(process.execPath, baseArgs, {
        env: {
          ...env,
          HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:metadata",
        },
      }),
    ).resolves.toBeDefined();
    await expect(
      execFileAsync(
        process.execPath,
        baseArgs
          .filter(
            (arg, index) =>
              arg !== "--expect-no-labels" &&
              baseArgs[index - 1] !== "--expect-no-labels",
          )
          .concat(
            "--expected-labels-base64",
            Buffer.from(JSON.stringify({ "io.hass.arch": "aarch64" })).toString(
              "base64",
            ),
          ),
        {
          env: {
            ...env,
            FAKE_DOCKER_MODE: "ha-labels",
            HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:metadata",
          },
        },
      ),
    ).resolves.toBeDefined();
    await expect(
      execFileAsync(
        process.execPath,
        baseArgs.concat(
          "--expected-setid-path",
          "/package/admin/s6-overlay-helpers/command/s6-overlay-suexec",
        ),
        {
          env: {
            ...env,
            FAKE_DOCKER_MODE: "ha-setid",
            HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:setuid-setgid",
          },
        },
      ),
    ).resolves.toBeDefined();
    await expect(
      execFileAsync(process.execPath, baseArgs, {
        env: {
          ...env,
          HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:git-protocol-matrix",
        },
      }),
    ).resolves.toBeDefined();
    for (const [mode, row, expected] of [
      ["bad-id", "image:metadata", "image ID mismatch"],
      ["labels", "image:metadata", "image labels are not empty"],
      [
        "extra-native-entry",
        "image:native-paths",
        "unexpected native helper entries",
      ],
      ["bad-hash", "image:native-artifacts", "SHA-256 mismatch"],
      ["extra-link", "image:linkage", "unexpected linkage targets"],
      ["bad-link-target", "image:linkage", "linkage realpath mismatch"],
    ] as const) {
      await expectHarnessFailure(
        baseArgs,
        {
          ...env,
          FAKE_DOCKER_MODE: mode,
          HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: row,
        },
        expected,
      );
    }
    const startupArgs = baseArgs.map((arg, index) => {
      if (baseArgs[index - 1] === "--expected-startup-status") return "0";
      if (baseArgs[index - 1] === "--expected-startup-signal") return "null";
      if (baseArgs[index - 1] === "--expected-startup-timed-out")
        return "false";
      if (baseArgs[index - 1] === "--startup-timeout-ms") return "5000";
      return arg;
    });
    await expect(
      execFileAsync(process.execPath, startupArgs, {
        env: {
          ...env,
          FAKE_DOCKER_MODE: "startup-success",
          HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:offline-startup",
        },
      }),
    ).resolves.toBeDefined();
    await expectHarnessFailure(
      baseArgs.map((arg, index) =>
        baseArgs[index - 1] === "--expected-startup-status" ? "0" : arg,
      ),
      { ...env, HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS: "image:offline-startup" },
      "startup status mismatch",
    );
  }, 60_000);

  it("makes native aarch64 provenance mandatory without overstating trust", async () => {
    const source = await readFile(
      new URL(
        "../scripts/linux/native-aarch64-provenance-harness.mjs",
        import.meta.url,
      ),
      "utf8",
    );
    for (const token of [
      '"host:os-architecture"',
      '"host:cpu-provenance"',
      '"host:binfmt"',
      '"docker:server"',
      '"host:runner-provenance"',
      "mandatory native-aarch64 row registry mismatch",
      "HA_NATIVE_AARCH64_PROVENANCE_FIXTURE",
      "selfAttested: true",
      "external immutable runner provenance is still required",
      'type: "manifest"',
      'type: "row"',
      'type: "summary"',
    ])
      expect(source).toContain(token);
    expect(source).toContain("shell: false");
    expect(source).not.toContain("shell: true");
  });

  it("fails native aarch64 provenance on ambiguous or emulated evidence", async () => {
    const script = fileURLToPath(
      new URL(
        "../scripts/linux/native-aarch64-provenance-harness.mjs",
        import.meta.url,
      ),
    );
    const fixture = {
      platform: "linux",
      arch: "arm64",
      commands: {
        unameSystem: { status: 0, stdout: "Linux\n", stderr: "" },
        unameMachine: { status: 0, stdout: "aarch64\n", stderr: "" },
        lscpu: {
          status: 0,
          stdout: JSON.stringify({
            lscpu: [{ field: "Architecture:", data: "aarch64" }],
          }),
          stderr: "",
        },
        dockerServer: {
          status: 0,
          stdout: JSON.stringify({
            Server: { OSType: "linux", Architecture: "arm64" },
          }),
          stderr: "",
        },
      },
      files: {
        "/proc/cpuinfo":
          "processor : 0\nCPU architecture : 8\nHardware : Raspberry Pi 5 Model B Rev 1.0\n",
        "/proc/sys/fs/binfmt_misc/status": "enabled\n",
      },
      directories: {
        "/proc/sys/fs/binfmt_misc": ["register", "status"],
      },
    };
    const identity = "runner-attestation:sha256:" + "a".repeat(64);
    const environment = (value: typeof fixture, nodeEnv = "test") => ({
      ...process.env,
      NODE_ENV: nodeEnv,
      HA_NATIVE_AARCH64_PROVENANCE_FIXTURE: JSON.stringify(value),
    });
    async function run(
      value: typeof fixture,
      args = ["--runner-identity", identity],
    ) {
      return execFileAsync(process.execPath, [script, ...args], {
        env: environment(value),
      });
    }
    async function expectFailure(
      value: typeof fixture,
      expected: string,
      args = ["--runner-identity", identity],
    ) {
      try {
        await run(value, args);
      } catch (error) {
        const stdout =
          typeof (error as { stdout?: unknown }).stdout === "string"
            ? (error as { stdout: string }).stdout
            : "";
        const stderr =
          typeof (error as { stderr?: unknown }).stderr === "string"
            ? (error as { stderr: string }).stderr
            : "";
        expect(stdout + "\n" + stderr).toContain(expected);
        return;
      }
      throw new Error("expected native aarch64 provenance harness failure");
    }

    const success = await run(fixture);
    const records = success.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.at(-1)).toMatchObject({
      type: "summary",
      status: "PASSED",
      required: 5,
      executed: 5,
    });
    const runnerRecord = records.find(
      (record) => record.id === "host:runner-provenance",
    );
    expect(runnerRecord).toBeDefined();
    expect(runnerRecord?.evidence).toEqual({
      identity,
      bytes: Buffer.byteLength(identity),
      sha256: createHash("sha256").update(identity).digest("hex"),
      selfAttested: true,
      claimLimit:
        "This self-attested value does not establish runner provenance; external immutable runner provenance is still required.",
    });

    for (const [mutate, expected] of [
      [
        (value: typeof fixture) => Object.assign(value, { platform: "win32" }),
        "process.platform is not linux",
      ],
      [
        (value: typeof fixture) => Object.assign(value, { arch: "x64" }),
        "process.arch is not arm64",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.commands.unameSystem, { stdout: "Darwin\n" }),
        "uname -s is not Linux",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.commands.unameMachine, { stdout: "x86_64\n" }),
        "uname -m is not aarch64",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.files, {
            "/proc/cpuinfo": "processor : 0\nHardware : QEMU Virtual CPU\n",
          }),
        "CPU provenance contains emulation indicators",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.files, {
            "/proc/cpuinfo": "processor : 0\nHardware : TCG\n",
          }),
        "CPU provenance contains emulation indicators",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.files, {
            "/proc/cpuinfo": "processor : 0\n",
          }),
        "cpuinfo identity evidence is missing",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.files, {
            "/proc/cpuinfo": "processor : 0\nHardware :   \n",
          }),
        "cpuinfo identity evidence is missing",
      ],
      [
        (value: typeof fixture) => {
          value.directories["/proc/sys/fs/binfmt_misc"].push("qemu-aarch64");
          Object.assign(value.files, {
            "/proc/sys/fs/binfmt_misc/qemu-aarch64":
              "enabled\ninterpreter /usr/bin/qemu-aarch64-static\n",
          });
        },
        "enabled arm64/aarch64 binfmt translation handler detected",
      ],
      [
        (value: typeof fixture) =>
          Object.assign(value.commands.dockerServer, {
            stdout: JSON.stringify({
              Server: { OSType: "linux", Architecture: "amd64" },
            }),
          }),
        "Docker Server architecture is not arm64/aarch64",
      ],
    ] as const) {
      const changed = structuredClone(fixture);
      mutate(changed);
      await expectFailure(changed, expected);
    }

    await expectFailure(fixture, "missing --runner-identity", []);
    await expectFailure(fixture, "runner identity is empty or whitespace", [
      "--runner-identity",
      "   ",
    ]);
    await expectFailure(fixture, "runner identity has controls", [
      "--runner-identity",
      "runner\u0001identity",
    ]);
    await expectFailure(fixture, "runner identity exceeds 512 UTF-8 bytes", [
      "--runner-identity",
      "x".repeat(513),
    ]);

    let productionSeamRejected = false;
    try {
      await execFileAsync(
        process.execPath,
        [script, "--runner-identity", identity],
        { env: environment(fixture, "production") },
      );
    } catch (error) {
      productionSeamRejected = true;
      const stderr =
        typeof (error as { stderr?: unknown }).stderr === "string"
          ? (error as { stderr: string }).stderr
          : "";
      expect(stderr).toContain(
        "HA_NATIVE_AARCH64_PROVENANCE_FIXTURE is test-only",
      );
    }
    expect(productionSeamRejected).toBe(true);
  }, 60_000);
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

const phase3ApprovalRows = [
  "env:linux",
  "env:native-fs",
  "env:root-private",
  "init:same-key-race",
  "init:different-key-race",
  "init:wrong-key-restart",
  "cross:issue-consume-replay",
  "race:issue-colliding-uuid",
  "race:consume",
  "tamper:header",
  "tamper:grant",
  "tamper:receipt",
  "exhaustion:header-same-instance-retry",
  "exhaustion:grant-same-instance-retry",
  "exhaustion:receipt-same-instance-retry",
  "topology:root-mode",
  "topology:root-owner",
  "topology:header-symlink",
  "topology:header-hardlink",
  "topology:header-nonregular",
  "topology:root-unknown-entry",
  "topology:root-entry-overflow",
  "topology:slot-entry-overflow",
  "kill:header:precommit",
  "kill:header:postcommit",
  "kill:header:parent-synced",
  "kill:grant:precommit",
  "kill:grant:postcommit",
  "kill:grant:parent-synced",
  "kill:receipt:precommit",
  "kill:receipt:postcommit",
  "kill:receipt:parent-synced",
  "fault:header:open",
  "fault:header:pwrite-fail",
  "fault:header:pwrite-short",
  "fault:header:pwrite-enospc",
  "fault:header:file-fsync",
  "fault:header:link-family",
  "fault:header:parent-fsync",
  "fault:grant:open",
  "fault:grant:pwrite-fail",
  "fault:grant:pwrite-short",
  "fault:grant:pwrite-enospc",
  "fault:grant:file-fsync",
  "fault:grant:stage-fsync",
  "fault:grant:rename",
  "fault:grant:parent-fsync",
  "fault:receipt:open",
  "fault:receipt:pwrite-fail",
  "fault:receipt:pwrite-short",
  "fault:receipt:pwrite-enospc",
  "fault:receipt:file-fsync",
  "fault:receipt:link-family",
  "fault:receipt:parent-fsync",
  "shim:link:fail",
  "shim:linkat:fail",
] as const;

type ApprovalEvidenceStatus = "PASSED" | "FAILED" | "BLOCKED" | "UNVERIFIED";

interface ApprovalWorkerClient {
  readonly pid?: number;
  readonly processGroupAbsent: boolean;
  ready(): Promise<void>;
}

interface ApprovalWorkerState {
  clients: Set<ApprovalWorkerClient>;
}

interface ApprovalHarnessLifecycle {
  WorkerClient: new (
    config: { node: string; worker: string },
    root: string,
    options?: { env?: NodeJS.ProcessEnv; timeoutMs?: number },
  ) => ApprovalWorkerClient;
  closeWorker(
    state: ApprovalWorkerState,
    client: ApprovalWorkerClient,
  ): Promise<void>;
  terminateWorkers(state: ApprovalWorkerState): Promise<void>;
  settleProcessGroupProbe(
    probe: {
      pid?: number;
      lifecycle: Promise<
        | { kind: "error"; error: Error }
        | { kind: "close"; code: number | null; signal: NodeJS.Signals | null }
      >;
      closed: Promise<{
        kind: "close";
        code: number | null;
        signal: NodeJS.Signals | null;
      }>;
    },
    controls?: {
      assertAbsent?: (pid: number) => Promise<void>;
      terminate?: (pid: number) => void;
      probeTimeoutMs?: number;
      cleanupTimeoutMs?: number;
    },
  ): Promise<void>;
  buildDiagnosticReport(
    error: unknown,
    state?: { base?: string },
  ): {
    total: number;
    details: ReadonlyArray<string>;
    truncated: boolean;
  };
  buildNonPassingEvidence(
    error: unknown,
    state?: { base?: string },
  ): {
    reason: string;
    diagnostic: {
      total: number;
      details: ReadonlyArray<string>;
      truncated: boolean;
    };
  };
  parseApprovalEvidence(output: string): {
    rows: ReadonlyArray<{ status: ApprovalEvidenceStatus }>;
    summary: {
      status: ApprovalEvidenceStatus;
      nonPassed: ReadonlyArray<string>;
    };
  };
}

const controlledApprovalWorker = `
import { spawn } from "node:child_process";

const behavior = process.env.HA_PHASE3M_WORKER_FIXTURE;
const send = (message) => new Promise((resolve, reject) => {
  process.send(message, (error) => error ? reject(error) : resolve());
});

if (behavior === "malformed") {
  await send({ type: "malformed" });
  setInterval(() => undefined, 1_000);
} else if (behavior === "overflow") {
  await send({ type: "ready", protocol: 1, padding: "x".repeat(300_000) });
  setInterval(() => undefined, 1_000);
} else if (behavior === "timeout") {
  setInterval(() => undefined, 1_000);
} else if (behavior === "survivor") {
  const survivor = spawn(process.execPath, ["-e", "setInterval(() => undefined, 1000)"], {
    stdio: "ignore",
  });
  survivor.unref();
  await send({ type: "ready", protocol: 1 });
  process.on("message", async (message) => {
    if (message?.type !== "request" || message.command !== "close") return;
    await send({
      type: "result",
      requestId: message.requestId,
      command: "close",
      ok: true,
      evidence: { closed: true },
    });
    process.disconnect();
  });
} else {
  process.exit(64);
}
`;

function phase3ApprovalEvidence(
  statuses: Readonly<Record<string, ApprovalEvidenceStatus>> = {},
): string {
  const rows = phase3ApprovalRows.map((id) => ({
    type: "row",
    id,
    status: statuses[id] ?? "PASSED",
    evidence: { fixture: true },
  }));
  const nonPassed = rows
    .filter((row) => row.status !== "PASSED")
    .map((row) => row.id);
  const status = rows.some((row) => row.status === "FAILED")
    ? "FAILED"
    : rows.some((row) => row.status === "BLOCKED")
      ? "BLOCKED"
      : rows.some((row) => row.status !== "PASSED")
        ? "UNVERIFIED"
        : "PASSED";
  return [
    {
      type: "manifest",
      version: 1,
      requiredRows: phase3ApprovalRows,
      adapters: { filesystem: "default", durability: "default" },
      prerequisites: ["linux", "uid0", "compiler", "process-groups"],
      limitations: [
        "actual-power-cut-unverified",
        "grant-native-topology-unverified",
        "receipt-native-topology-unverified",
      ],
    },
    ...rows,
    {
      type: "summary",
      status,
      required: phase3ApprovalRows.length,
      executed: rows.length,
      passed: rows.length - nonPassed.length,
      nonPassed,
    },
  ]
    .map((record) => JSON.stringify(record))
    .join("\n")
    .concat("\n");
}

describe("Phase 3M native approval evidence harness", () => {
  const harnessUrl = new URL(
    "../scripts/linux/phase3-approval-harness.mjs",
    import.meta.url,
  );

  async function loadApprovalLifecycle(): Promise<ApprovalHarnessLifecycle> {
    return (await import(
      harnessUrl.href
    )) as unknown as ApprovalHarnessLifecycle;
  }

  async function withControlledApprovalWorker(
    operation: (worker: string, root: string) => Promise<void>,
  ): Promise<void> {
    const root = await mkdtemp(join(tmpdir(), "ha-phase3m-worker-"));
    const worker = join(root, "controlled-worker.mjs");
    try {
      await writeFile(worker, controlledApprovalWorker, { mode: 0o600 });
      await operation(worker, root);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  function expectNoProcessGroup(pid: number | undefined): void {
    if (!Number.isSafeInteger(pid) || (pid ?? 0) <= 0)
      throw new Error("controlled worker PID is unavailable");
    try {
      process.kill(-(pid ?? 0), 0);
    } catch (error) {
      expect((error as NodeJS.ErrnoException).code).toBe("ESRCH");
      return;
    }
    throw new Error(`controlled worker process group ${pid} survived cleanup`);
  }

  async function ensureControlledWorkersStopped(
    harness: ApprovalHarnessLifecycle,
    state: ApprovalWorkerState,
  ): Promise<void> {
    if (state.clients.size === 0) return;
    try {
      await harness.terminateWorkers(state);
    } catch (error) {
      if (state.clients.size > 0) throw error;
    }
  }

  async function runFake(output: string, allow = true, nodeEnv = "test") {
    return await execFileAsync(
      process.execPath,
      [fileURLToPath(harnessUrl), ...(allow ? ["--allow-test-fake"] : [])],
      {
        env: {
          ...process.env,
          NODE_ENV: nodeEnv,
          HA_PHASE3_APPROVAL_HARNESS_FAKE_OUTPUT_BASE64:
            Buffer.from(output).toString("base64"),
        },
      },
    );
  }

  async function expectFakeFailure(
    output: string,
    allow = true,
    nodeEnv = "test",
  ) {
    try {
      await runFake(output, allow, nodeEnv);
    } catch (error) {
      return error as { stdout?: string; stderr?: string; code?: number };
    }
    throw new Error("expected Phase 3M fake evidence failure");
  }

  it("freezes all 56 rows and keeps the harness inert and mirrored", async () => {
    const [harness, worker, shim, rootPackage, addonPackage, dockerfile] =
      await Promise.all([
        readFile(harnessUrl, "utf8"),
        readFile(
          new URL(
            "../scripts/linux/phase3-approval-worker.mjs",
            import.meta.url,
          ),
          "utf8",
        ),
        readFile(
          new URL("../scripts/linux/persistence-fault-shim.c", import.meta.url),
          "utf8",
        ),
        readFile(new URL("../package.json", import.meta.url), "utf8"),
        readFile(new URL("../addon/app/package.json", import.meta.url), "utf8"),
        readFile(new URL("../addon/Dockerfile", import.meta.url), "utf8"),
      ]);
    expect(phase3ApprovalRows).toHaveLength(56);
    for (const id of phase3ApprovalRows) expect(harness).toContain(`"${id}"`);
    for (const token of [
      "mandatory Phase 3M row registry mismatch",
      "parseApprovalEvidence",
      "appendBounded",
      "validateWorkerMessage",
      "MAX_STDIO_BYTES",
      "MAX_IPC_BYTES",
      "MAX_IPC_MESSAGES",
      "WORKER_TIMEOUT_MS",
      "detached: true",
      "assertNoProcessGroup",
      "actual-power-cut-unverified",
      "grant-native-topology-unverified",
      "receipt-native-topology-unverified",
      "NODE_ENV",
      "--allow-test-fake",
      '"-Wall"',
      '"-Wextra"',
      '"-Werror"',
    ])
      expect(harness).toContain(token);
    for (const token of [
      "DurablePhase3ApprovalGrants",
      'filesystem: "default"',
      'durability: "default"',
      "RELATIVE_ARTIFACT_PATTERN",
      'message.command === "initialize" ? "header_" : "grant_"',
    ])
      expect(worker).toContain(token);
    for (const token of [
      "target_matches",
      '"open-family"',
      '"link-family"',
      "int link(",
      "int linkat(",
    ])
      expect(shim).toContain(token);
    const rootScript = (
      JSON.parse(rootPackage) as { scripts: Record<string, string> }
    ).scripts["validate:linux:approval"];
    const addonScript = (
      JSON.parse(addonPackage) as { scripts: Record<string, string> }
    ).scripts["validate:linux:approval"];
    expect(rootScript).toBe(
      "pnpm build && node scripts/linux/phase3-approval-harness.mjs",
    );
    expect(addonScript).toBe(rootScript);
    expect(dockerfile).not.toContain("phase3-approval-harness");
    expect(dockerfile).not.toContain("phase3-approval-worker");
    expect(harness).not.toContain("createHmac");
    expect(harness).not.toContain("shell: true");
  });

  it("strictly parses manifest, ordered rows, and summary through the dual-gated fake seam", async () => {
    const valid = phase3ApprovalEvidence();
    const result = await runFake(valid);
    expect(result.stdout).toBe(valid);
    expect(result.stderr).toBe("");

    const duplicateRecords = valid.trimEnd().split("\n");
    duplicateRecords[2] = duplicateRecords[1]!;
    const duplicate = `${duplicateRecords.join("\n")}\n`;
    expect((await expectFakeFailure(duplicate)).stderr).toContain(
      "evidence row order mismatch",
    );

    const missingRecords = valid.trimEnd().split("\n");
    missingRecords.splice(2, 1);
    expect(
      (await expectFakeFailure(`${missingRecords.join("\n")}\n`)).stderr,
    ).toContain("expected 56 evidence rows");

    const malformedRecords = valid.trimEnd().split("\n");
    malformedRecords[2] = "{";
    expect(
      (await expectFakeFailure(`${malformedRecords.join("\n")}\n`)).stderr,
    ).toContain("malformed JSON");

    const badSummaryRecords = valid.trimEnd().split("\n");
    const summary = JSON.parse(badSummaryRecords.at(-1) ?? "null") as {
      passed: number;
    };
    summary.passed -= 1;
    badSummaryRecords[badSummaryRecords.length - 1] = JSON.stringify(summary);
    expect(
      (await expectFakeFailure(`${badSummaryRecords.join("\n")}\n`)).stderr,
    ).toContain("summary does not match evidence rows");

    expect((await expectFakeFailure(`${valid}{`)).stderr).toContain(
      "approval evidence must end with one JSONL newline",
    );
    expect((await expectFakeFailure(valid, false)).stderr).toContain(
      "requires NODE_ENV=test and --allow-test-fake",
    );
    expect(
      (await expectFakeFailure(valid, true, "production")).stderr,
    ).toContain("requires NODE_ENV=test and --allow-test-fake");
  });

  it("returns nonzero for failed, blocked, and unverified evidence", async () => {
    for (const status of ["FAILED", "BLOCKED", "UNVERIFIED"] as const) {
      const output = phase3ApprovalEvidence({ "env:linux": status });
      const failure = await expectFakeFailure(output);
      expect(failure.stdout).toBe(output);
      expect(failure.stderr ?? "").toBe("");
    }
  });

  it("enforces exported output and IPC controls without native execution", async () => {
    const moduleUrl = harnessUrl.href;
    const program = `
const harness = await import(${JSON.stringify(moduleUrl)});
let overflow = false;
try { harness.appendBounded([], Buffer.alloc(5), 4, "fixture"); } catch { overflow = true; }
if (!overflow) process.exit(2);
if (harness.validateWorkerMessage({ type: "ready", protocol: 1 }).kind !== "ready") process.exit(3);
let malformed = false;
try { harness.validateWorkerMessage({ type: "hook", requestId: 1, hook: { stage: "header_pre_commit", commitState: "not_committed", relativePending: "/escape", relativeFinal: "header.json" } }); } catch { malformed = true; }
if (!malformed) process.exit(4);
if (harness.fakeEvidenceAllowed({ NODE_ENV: "test" }, true) !== true) process.exit(5);
if (harness.fakeEvidenceAllowed({ NODE_ENV: "test" }, false) !== false) process.exit(6);
`;
    await expect(
      execFileAsync(process.execPath, ["--input-type=module", "-e", program]),
    ).resolves.toMatchObject({ stdout: "", stderr: "" });
  });

  it("contains missing-executable spawn failure and still emits a complete contract", async () => {
    const harness = await loadApprovalLifecycle();
    const root = await mkdtemp(join(tmpdir(), "ha-phase3m-missing-"));
    const missingNode = join(root, "missing-node-executable");
    const state: ApprovalWorkerState = { clients: new Set() };
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    const startedAt = Date.now();
    try {
      const client = new harness.WorkerClient(
        { node: missingNode, worker: fileURLToPath(harnessUrl) },
        root,
      );
      state.clients.add(client);
      await expect(client.ready()).rejects.toThrow("worker PID is unavailable");
      await expect(harness.terminateWorkers(state)).rejects.toThrow(
        "worker cleanup failed",
      );
      await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
      expect(Date.now() - startedAt).toBeLessThan(5_000);
      expect(state.clients.size).toBe(0);
      expect(client.processGroupAbsent).toBe(true);
      expect(unhandled).toEqual([]);

      let failure:
        | { code?: number; stdout?: string; stderr?: string }
        | undefined;
      try {
        await execFileAsync(process.execPath, [
          fileURLToPath(harnessUrl),
          "--node",
          missingNode,
        ]);
      } catch (error) {
        failure = error as {
          code?: number;
          stdout?: string;
          stderr?: string;
        };
      }
      expect(failure?.code).toBe(1);
      expect(failure?.stderr ?? "").toBe("");
      const parsed = harness.parseApprovalEvidence(failure?.stdout ?? "");
      expect(parsed.rows).toHaveLength(56);
      expect(parsed.summary.status).not.toBe("PASSED");
      expect(parsed.summary.nonPassed.length).toBeGreaterThan(0);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      await ensureControlledWorkersStopped(harness, state);
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it.runIf(process.platform === "linux")(
    "fails closed and removes a same-group process-group probe survivor",
    async () => {
      const harness = await loadApprovalLifecycle();
      const root = await mkdtemp(join(tmpdir(), "ha-phase3m-probe-"));
      const launcher = join(root, "probe-launcher.mjs");
      const groupPath = join(root, "probe-group");
      const launcherSource = `#!${process.execPath}
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

if (process.argv[2] !== "-e" || process.argv[3] !== "process.exit(0)") process.exit(64);
const survivor = spawn(process.execPath, ["-e", "setInterval(() => undefined, 1_000)"], {
  stdio: "ignore",
});
writeFileSync(process.env.HA_PHASE3M_PROBE_GROUP_PATH, String(process.pid), {
  flag: "wx",
  mode: 0o600,
});
survivor.unref();
`;
      let groupId: number | undefined;
      let cleanupFailure: unknown;
      try {
        await writeFile(launcher, launcherSource, { mode: 0o700 });
        await chmod(launcher, 0o700);
        let failure:
          | { code?: number; stdout?: string; stderr?: string }
          | undefined;
        try {
          await execFileAsync(
            process.execPath,
            [fileURLToPath(harnessUrl), "--node", launcher],
            {
              env: {
                ...process.env,
                HA_PHASE3M_PROBE_GROUP_PATH: groupPath,
              },
              timeout: 20_000,
              killSignal: "SIGKILL",
              maxBuffer: 2 * 1_048_576,
            },
          );
        } catch (error) {
          failure = error as {
            code?: number;
            stdout?: string;
            stderr?: string;
          };
        }

        groupId = Number((await readFile(groupPath, "utf8")).trim());
        expect(failure?.code).toBe(1);
        expect(failure?.stderr ?? "").toBe("");
        const parsed = harness.parseApprovalEvidence(failure?.stdout ?? "");
        expect(parsed.rows).toHaveLength(56);
        expect(parsed.summary.status).not.toBe("PASSED");
        expect(parsed.summary.nonPassed.length).toBeGreaterThan(0);
        expectNoProcessGroup(groupId);
      } finally {
        if (Number.isSafeInteger(groupId) && (groupId ?? 0) > 0) {
          try {
            process.kill(-(groupId ?? 0), "SIGKILL");
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ESRCH")
              cleanupFailure = error;
          }
        }
        await rm(root, { recursive: true, force: true });
      }
      if (cleanupFailure) throw cleanupFailure;
    },
    30_000,
  );

  async function expectProbeSettlementRegressions(): Promise<void> {
    const harness = await loadApprovalLifecycle();
    const rawCanary = `${tmpdir()}/private-preflight/SECRET_ENV_VALUE`;

    const delayedEvents: string[] = [];
    let terminated = false;
    const delayedClose = new Promise<{
      kind: "close";
      code: 0;
      signal: null;
    }>((resolvePromise) => {
      setTimeout(() => {
        delayedEvents.push("close");
        resolvePromise({ kind: "close", code: 0, signal: null });
      }, 25);
    });
    let delayedFailure: unknown;
    try {
      await harness.settleProcessGroupProbe(
        {
          pid: 41_001,
          lifecycle: Promise.resolve({
            kind: "error",
            error: new Error(rawCanary),
          }),
          closed: delayedClose,
        },
        {
          assertAbsent: async () => {
            delayedEvents.push(terminated ? "absence-after" : "absence-before");
            if (!terminated) throw new Error(rawCanary);
          },
          terminate: () => {
            delayedEvents.push("terminate");
            terminated = true;
          },
          probeTimeoutMs: 100,
          cleanupTimeoutMs: 100,
        },
      );
    } catch (error) {
      delayedFailure = error;
    }
    expect(delayedFailure).toBeInstanceOf(AggregateError);
    expect(
      (delayedFailure as AggregateError).errors.map(
        (error) => (error as Error).message,
      ),
    ).toEqual([
      "process-group probe failed to start",
      "process-group probe absence was not proven before cleanup",
    ]);
    expect(delayedEvents).toEqual([
      "absence-before",
      "terminate",
      "close",
      "absence-after",
    ]);

    const noPidEvents: string[] = [];
    let noPidFailure: unknown;
    try {
      await harness.settleProcessGroupProbe(
        {
          lifecycle: Promise.resolve({
            kind: "error",
            error: new Error(rawCanary),
          }),
          closed: new Promise((resolvePromise) => {
            setTimeout(() => {
              noPidEvents.push("close");
              resolvePromise({ kind: "close", code: 0, signal: null });
            }, 10);
          }),
        },
        { probeTimeoutMs: 100, cleanupTimeoutMs: 100 },
      );
    } catch (error) {
      noPidFailure = error;
    }
    expect(noPidFailure).toBeInstanceOf(AggregateError);
    expect(
      (noPidFailure as AggregateError).errors.map(
        (error) => (error as Error).message,
      ),
    ).toEqual([
      "process-group probe failed to start",
      "process-group probe has no PID",
      "process-group probe cleanup has no PID; group absence was not claimed",
    ]);
    expect(noPidEvents).toEqual(["close"]);

    const missingEvents: string[] = [];
    let missingFailure: unknown;
    const startedAt = Date.now();
    try {
      await harness.settleProcessGroupProbe(
        {
          pid: 41_002,
          lifecycle: Promise.resolve({
            kind: "error",
            error: new Error(rawCanary),
          }),
          closed: new Promise(() => undefined),
        },
        {
          assertAbsent: async () => {
            missingEvents.push("absence");
            throw new Error(rawCanary);
          },
          terminate: () => {
            missingEvents.push("terminate");
            throw new Error(rawCanary);
          },
          probeTimeoutMs: 20,
          cleanupTimeoutMs: 20,
        },
      );
    } catch (error) {
      missingFailure = error;
    }
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(missingFailure).toBeInstanceOf(AggregateError);
    expect(
      (missingFailure as AggregateError).errors.map(
        (error) => (error as Error).message,
      ),
    ).toEqual([
      "process-group probe failed to start",
      "process-group probe absence was not proven before cleanup",
      "process-group probe termination failed",
      "process-group probe close was not observed during cleanup",
      "process-group probe absence was not proven after cleanup",
    ]);
    expect(missingEvents).toEqual(["absence", "terminate", "absence"]);

    const diagnostic = harness.buildDiagnosticReport(missingFailure, {
      base: tmpdir(),
    });
    expect(diagnostic).toEqual({
      total: 5,
      details: [
        "process-group probe failed to start",
        "process-group probe absence was not proven before cleanup",
        "process-group probe termination failed",
        "process-group probe close was not observed during cleanup",
        "process-group probe absence was not proven after cleanup",
      ],
      truncated: false,
    });
    const nonPassing = harness.buildNonPassingEvidence(missingFailure, {
      base: tmpdir(),
    });
    expect(nonPassing.reason).toBe("process-group probe failed to start");
    expect(nonPassing.diagnostic).toEqual(diagnostic);
    expect(JSON.stringify(nonPassing)).not.toContain(rawCanary);
    expect(JSON.stringify(nonPassing)).not.toContain("SECRET_ENV_VALUE");
  }

  it.runIf(process.platform === "linux")(
    "bounds probe/IPC failure ordering and proves cleanup",
    async () => {
      await expectProbeSettlementRegressions();
      const harness = await loadApprovalLifecycle();
      await withControlledApprovalWorker(async (worker, root) => {
        for (const fixture of [
          {
            behavior: "malformed",
            expected: "worker IPC message is malformed",
            timeoutMs: 2_000,
            cleanupFails: false,
          },
          {
            behavior: "overflow",
            expected: "worker IPC exceeded its bound",
            timeoutMs: 2_000,
            cleanupFails: false,
          },
          {
            behavior: "timeout",
            expected: "worker exceeded 100 ms",
            timeoutMs: 100,
            cleanupFails: true,
          },
        ] as const) {
          const state: ApprovalWorkerState = { clients: new Set() };
          const client = new harness.WorkerClient(
            { node: process.execPath, worker },
            root,
            {
              env: {
                ...process.env,
                HA_PHASE3M_WORKER_FIXTURE: fixture.behavior,
              },
              timeoutMs: fixture.timeoutMs,
            },
          );
          state.clients.add(client);
          try {
            await expect(client.ready()).rejects.toThrow(fixture.expected);
            if (fixture.cleanupFails)
              await expect(harness.terminateWorkers(state)).rejects.toThrow(
                "worker cleanup failed",
              );
            else
              await expect(
                harness.terminateWorkers(state),
              ).resolves.toBeUndefined();
            expect(state.clients.size).toBe(0);
            expect(client.processGroupAbsent).toBe(true);
            expectNoProcessGroup(client.pid);
          } finally {
            await ensureControlledWorkersStopped(harness, state);
          }
        }
      });
    },
    30_000,
  );

  it.runIf(process.platform === "linux")(
    "surfaces a close survivor, retains tracking, and enforces group disappearance",
    async () => {
      const harness = await loadApprovalLifecycle();
      await withControlledApprovalWorker(async (worker, root) => {
        const state: ApprovalWorkerState = { clients: new Set() };
        const client = new harness.WorkerClient(
          { node: process.execPath, worker },
          root,
          {
            env: {
              ...process.env,
              HA_PHASE3M_WORKER_FIXTURE: "survivor",
            },
            timeoutMs: 5_000,
          },
        );
        state.clients.add(client);
        try {
          await client.ready();
          await expect(harness.closeWorker(state, client)).rejects.toThrow(
            "survived completion",
          );
          expect(state.clients.has(client)).toBe(true);
          expect(client.processGroupAbsent).toBe(false);

          await expect(
            harness.terminateWorkers(state),
          ).resolves.toBeUndefined();
          expect(state.clients.size).toBe(0);
          expect(client.processGroupAbsent).toBe(true);
          expectNoProcessGroup(client.pid);
        } finally {
          await ensureControlledWorkersStopped(harness, state);
        }
      });
    },
    30_000,
  );
});
