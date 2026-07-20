import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, writeFile, readFile } from "node:fs/promises";
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
