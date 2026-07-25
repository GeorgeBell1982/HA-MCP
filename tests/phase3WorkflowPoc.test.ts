import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

type Status = "PASSED" | "FAILED" | "SKIPPED" | "BLOCKED";

interface PocHarness {
  AppendOnlyTopologyRegistry: new (input: {
    ancestor: { path: string; metadata: unknown };
    root: { path: string; metadata: unknown };
    nonce: {
      path: string;
      metadata: unknown;
      value: Buffer;
      sha256: string;
    };
  }) => {
    captureStage(allowNew: boolean): void;
    registerHelpers(native: unknown): void;
  };
  PHASE3_WORKFLOW_POC_ACK: string;
  PHASE3_WORKFLOW_POC_ROWS: readonly string[];
  PHASE3_WORKFLOW_POC_MANIFEST: Readonly<Record<string, unknown>>;
  allowedTopology(relativePath: string, type: string): boolean;
  authorizeWorkerRun(client: unknown, message: unknown): boolean;
  assertNoMountAtOrBelow(workspace: string, mountInfo: string): void;
  assertPinnedIdentity(path: string, expected: unknown): void;
  assertWorkspacePathAllowed(path: string): string;
  captureProcessOwnership(pid: number): unknown;
  capturePinnedIdentity(path: string): unknown;
  cleanupTopology(registry: unknown): unknown;
  parseMountInfo(value: string): readonly string[];
  parseWorkflowEvidence(output: string): {
    readonly rows: ReadonlyArray<{ readonly status: Status }>;
    readonly summary: {
      readonly status: Status;
      readonly nonPassed: readonly string[];
    };
  };
  sanitizeEvidence(value: unknown): unknown;
  settleWorkerProcess(client: unknown, helperProofs: unknown): Promise<void>;
  signalLiveOwnedProcessGroup(
    client: unknown,
    signalProcess?: (pid: number, signal: NodeJS.Signals) => void,
  ): boolean;
  proveHelpersAbsent(
    helperProofs: unknown,
    options?: Readonly<Record<string, number>>,
  ): Promise<void>;
  procHelperPids(
    helperProofs: unknown,
    options?: Readonly<Record<string, number>>,
  ): number[];
  validateEnvironmentBoundary(value: {
    readonly platform: string;
    readonly uid: number;
    readonly euid: number;
    readonly nodeVersion: string;
    readonly environment: Readonly<Record<string, string | undefined>>;
  }): unknown;
  validateWorkerMessage(
    message: unknown,
    nonce: string,
    scenario: string,
  ): { readonly kind: string };
}

const controllerUrl = new URL(
  "../scripts/linux/phase3-workflow-poc.mjs",
  import.meta.url,
);
const workerUrl = new URL(
  "../scripts/linux/phase3-workflow-poc-worker.mjs",
  import.meta.url,
);

async function harness(): Promise<PocHarness> {
  return (await import(controllerUrl.href)) as unknown as PocHarness;
}

function runNode(
  args: readonly string[],
  options: {
    readonly env?: NodeJS.ProcessEnv;
    readonly ipc?: boolean;
  } = {},
): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [...args], {
      env: options.env ?? process.env,
      stdio: options.ipc
        ? ["ignore", "pipe", "pipe", "ipc"]
        : ["ignore", "pipe", "pipe"],
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("error", rejectPromise);
    child.once("close", (code, signal) =>
      resolvePromise({ code, signal, stdout, stderr }),
    );
  });
}

function evidenceOutput(
  module: PocHarness,
  statuses: Readonly<Record<string, Status>> = {},
): string {
  const rows = module.PHASE3_WORKFLOW_POC_ROWS.map((id) => ({
    type: "row",
    id,
    status: statuses[id] ?? "PASSED",
    evidence: { fixture: true },
  }));
  const nonPassed = rows
    .filter((row) => row.status !== "PASSED")
    .map((row) => row.id);
  return [
    module.PHASE3_WORKFLOW_POC_MANIFEST,
    ...rows,
    {
      type: "summary",
      status: nonPassed.length === 0 ? "PASSED" : "FAILED",
      required: rows.length,
      executed: rows.length,
      passed: rows.length - nonPassed.length,
      nonPassed,
    },
  ]
    .map((record) => JSON.stringify(record))
    .join("\n")
    .concat("\n");
}

interface FileProof {
  readonly metadata: unknown;
  readonly sha256: string;
}

async function fileProof(module: PocHarness, path: string): Promise<FileProof> {
  return {
    metadata: module.capturePinnedIdentity(path),
    sha256: createHash("sha256")
      .update(await readFile(path))
      .digest("hex"),
  };
}

async function removeIfPresent(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function createLinuxRegistryFixture(module: PocHarness): Promise<{
  readonly root: string;
  readonly noncePath: string;
  readonly helperPaths: readonly string[];
  readonly artifactPath: string;
  readonly registry: InstanceType<PocHarness["AppendOnlyTopologyRegistry"]>;
  cleanup(): Promise<void>;
}> {
  const ancestorPath = tmpdir();
  const root = await mkdtemp(join(ancestorPath, "phase3-poc-registry-"));
  await chmod(root, 0o700);
  const noncePath = join(root, ".phase3-poc-nonce");
  const nonceValue = Buffer.from(`${"a".repeat(64)}\n`, "ascii");
  await writeFile(noncePath, nonceValue, { mode: 0o600, flag: "wx" });
  const registry = new module.AppendOnlyTopologyRegistry({
    ancestor: {
      path: ancestorPath,
      metadata: module.capturePinnedIdentity(ancestorPath),
    },
    root: { path: root, metadata: module.capturePinnedIdentity(root) },
    nonce: {
      path: noncePath,
      metadata: module.capturePinnedIdentity(noncePath),
      value: nonceValue,
      sha256: createHash("sha256").update(nonceValue).digest("hex"),
    },
  });
  registry.captureStage(true);
  const native = join(root, "native");
  await mkdir(native, { mode: 0o700 });
  const helperPaths = [
    join(native, "openat2-list"),
    join(native, "openat2-read"),
    join(native, "openat2-replace"),
  ];
  for (const path of helperPaths) {
    await writeFile(path, Buffer.from(`fixture:${path.split("-").at(-1)}\n`), {
      mode: 0o600,
      flag: "wx",
    });
    await chmod(path, 0o555);
  }
  const helperProofs = {
    list: await fileProof(module, helperPaths[0]!),
    read: await fileProof(module, helperPaths[1]!),
    replace: await fileProof(module, helperPaths[2]!),
  };
  registry.registerHelpers({
    outputs: helperProofs,
    sourcePins: {
      list: { path: helperPaths[0], ...helperProofs.list },
      read: { path: helperPaths[1], ...helperProofs.read },
      replace: { path: helperPaths[2], ...helperProofs.replace },
    },
  });
  const success = join(root, "success");
  const repository = join(success, "repo");
  const automations = join(repository, "automations");
  await mkdir(success, { mode: 0o700 });
  await mkdir(repository, { mode: 0o700 });
  await mkdir(automations, { mode: 0o700 });
  const artifactPath = join(automations, "poc.yaml");
  await writeFile(artifactPath, "- alias: registered\n", {
    mode: 0o600,
    flag: "wx",
  });
  registry.captureStage(true);
  return {
    root,
    noncePath,
    helperPaths,
    artifactPath,
    registry,
    async cleanup() {
      await removeIfPresent(artifactPath);
      for (const path of helperPaths) await removeIfPresent(path);
      await removeIfPresent(noncePath);
      for (const path of [automations, repository, success, native, root]) {
        try {
          await rmdir(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      }
    },
  };
}

function trackedProcess(
  module: PocHarness,
  child: ReturnType<typeof spawn>,
): {
  readonly pid: number;
  live: boolean;
  readonly ownership: unknown;
  closed: Promise<{
    readonly code: number | null;
    readonly signal: string | null;
  }>;
  terminate(): boolean;
} {
  if (!child.pid) throw new Error("spawned process has no PID");
  const client: {
    readonly pid: number;
    live: boolean;
    readonly ownership: unknown;
    closed: Promise<{
      readonly code: number | null;
      readonly signal: string | null;
    }>;
    terminate(): boolean;
  } = {
    pid: child.pid,
    live: true,
    ownership: module.captureProcessOwnership(child.pid),
    closed: Promise.resolve({ code: null, signal: null }),
    terminate: () => false,
  };
  client.closed = new Promise((resolvePromise) => {
    child.once("close", (code, signal) => {
      client.live = false;
      resolvePromise({ code, signal: signal ?? null });
    });
  });
  client.terminate = () => module.signalLiveOwnedProcessGroup(client);
  return client;
}

describe("isolated Phase 3 workflow POC", () => {
  it("freezes the six-file inert scope, exact package mirror, and public command", async () => {
    const [controller, worker, rootPackageText, addonPackageText, readme] =
      await Promise.all([
        readFile(controllerUrl, "utf8"),
        readFile(workerUrl, "utf8"),
        readFile(new URL("../package.json", import.meta.url), "utf8"),
        readFile(new URL("../addon/app/package.json", import.meta.url), "utf8"),
        readFile(
          new URL("../scripts/linux/README.md", import.meta.url),
          "utf8",
        ),
      ]);
    const rootPackage = JSON.parse(rootPackageText) as {
      scripts: Record<string, string>;
    };
    const addonPackage = JSON.parse(addonPackageText) as {
      scripts: Record<string, string>;
    };
    const expected = "pnpm build && node scripts/linux/phase3-workflow-poc.mjs";
    expect(rootPackage.scripts["validate:linux:phase3-poc"]).toBe(expected);
    expect(addonPackage.scripts["validate:linux:phase3-poc"]).toBe(expected);
    expect(addonPackage).toEqual(rootPackage);
    expect(readme).toContain(
      "pnpm validate:linux:phase3-poc -- --ack-disposable-phase3-poc",
    );
    for (const token of [
      "PHASE3_WORKFLOW_POC_ROWS",
      "parseWorkflowEvidence",
      "sanitizeEvidence",
      "assertNoMountAtOrBelow",
      "cleanupTopology",
      "detached: true",
      "SIGKILL",
      "cleanup_unproved",
      "libcrypto.so.3",
      '"-Wl,-z,noexecstack"',
      '"GNU_STACK"',
      "same_uid_transient_swap_restore_not_defeated_by_path_cleanup",
    ])
      expect(controller).toContain(token);
    for (const token of [
      "NativeOpenat2Catalog",
      "NativeOpenat2Reader",
      "ProtectedIdentityRegistry",
      "ProductionSecretValueProvider",
      "ProtectedPhase3SourceAdapter",
      "ProtectedProposalStore",
      "storageEnvelope",
      "ProtectedPhase3ProposalAdapter",
      "DurablePhase3Journal",
      "DurablePhase3Checkpoints",
      "DurablePhase3ApprovalGrants",
      "NativePhase3AtomicApply",
      "StrictYamlPhase3Validation",
      "NarrowPhase3ReloadAdapter",
      "NarrowPhase3VerificationAdapter",
      "Phase3ApplyCoordinator",
      'Object.freeze(["secrets.yaml"])',
      'process.kill(process.pid, "SIGKILL")',
    ])
      expect(worker).toContain(token);
    expect(controller).not.toMatch(/\brmSync\s*\(/u);
    expect(worker).not.toMatch(/\brmSync\s*\(/u);
    expect(controller).not.toContain("shell: true");
    expect(worker).not.toContain("shell: true");
  });

  it("keeps the worker import graph on exact dist modules and away from runtime and network paths", async () => {
    const source = await readFile(workerUrl, "utf8");
    const imports = [
      ...source.matchAll(/import\((["'])(.*?)\1\)/gu),
      ...source.matchAll(/from\s+(["'])(.*?)\1/gu),
    ].map((match) => match[2]);
    const allowed = new Set([
      "node:crypto",
      "node:fs",
      "node:path",
      "node:url",
      "../../dist/repository/repositoryReads.js",
      "../../dist/security/repositoryBoundary.js",
      "../../dist/phase2Activation.js",
      "../../dist/phase2Contracts.js",
      "../../dist/proposals/storage.js",
      "../../dist/phase3/proposalAdapter.js",
      "../../dist/phase3/approvalKey.js",
      "../../dist/phase3/durableApproval.js",
      "../../dist/phase3/journal.js",
      "../../dist/phase3/checkpoints.js",
      "../../dist/phase3/sourceAdapter.js",
      "../../dist/phase3/atomicApply.js",
      "../../dist/phase3/validationAdapter.js",
      "../../dist/phase3/reloadAdapter.js",
      "../../dist/phase3/verificationAdapter.js",
      "../../dist/phase3/applyCoordinator.js",
      "../../dist/phase3/resourceLocks.js",
    ]);
    expect(imports.length).toBeGreaterThan(10);
    expect(imports.every((specifier) => allowed.has(specifier ?? ""))).toBe(
      true,
    );
    expect(
      imports.filter(
        (specifier) => specifier === "../../dist/phase2Activation.js",
      ),
    ).toHaveLength(1);
    for (const forbidden of [
      "buildPhase2Registry(",
      "dist/index.js",
      "dist/cli.js",
      "dist/application.js",
      "dist/toolRegistry.js",
      "dist/config.js",
      "../ha/",
      "fetch(",
      "axios",
      "http.request",
      "https.request",
    ])
      expect(source).not.toContain(forbidden);
  });

  it("applies the protected fixture unified diff deterministically to the candidate digest", async () => {
    const worker = (await import(workerUrl.href)) as {
      fixtureDigests(): {
        readonly candidateMatches: boolean;
        readonly candidateSha256: string;
        readonly appliedSha256: string;
        readonly diffSha256: string;
      };
    };
    const first = worker.fixtureDigests();
    const second = worker.fixtureDigests();
    expect(first.candidateMatches).toBe(true);
    expect(first.appliedSha256).toBe(first.candidateSha256);
    expect(first).toEqual(second);
    expect(first.diffSha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("rejects missing, extra, and incorrect public arguments with exit 64", async () => {
    const script = fileURLToPath(controllerUrl);
    for (const args of [
      [script],
      [script, "--ack-disposable-phase3-poc", "--retain"],
      [script, "--ack-disposable-phase3-poc", "/tmp/caller-path"],
      [script, "--", "--ack-disposable-phase3-poc", "--retain"],
      [script, "--wrong"],
    ]) {
      const result = await runNode(args);
      expect(result.code).toBe(64);
      expect(result.signal).toBeNull();
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("exact disposable");
    }
  });

  it("enforces Linux, equal non-root UID, Node range, and present-even-empty credential denial", async () => {
    const module = await harness();
    const good = {
      platform: "linux",
      uid: 1000,
      euid: 1000,
      nodeVersion: "22.19.0",
      environment: {},
    };
    expect(() => module.validateEnvironmentBoundary(good)).not.toThrow();
    for (const override of [
      { platform: "win32" },
      { uid: 0, euid: 0 },
      { uid: 1000, euid: 1001 },
      { nodeVersion: "21.9.0" },
      { nodeVersion: "25.0.0" },
      { environment: { SUPERVISOR_TOKEN: "" } },
      { environment: { LONG_LIVED_ACCESS_TOKEN: "present" } },
    ])
      expect(() =>
        module.validateEnvironmentBoundary({ ...good, ...override }),
      ).toThrow();
  });

  it("fails the standalone and malformed-IPC worker before supplied workspace access", async () => {
    const standalone = await runNode([fileURLToPath(workerUrl)], {
      env: { PATH: process.env.PATH },
    });
    expect(standalone.code).toBe(64);
    expect(standalone.stdout).toBe("");
    expect(standalone.stderr).toBe("");

    const result = await new Promise<{
      readonly code: number | null;
      readonly messages: unknown[];
    }>((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, [fileURLToPath(workerUrl)], {
        env: { PATH: process.env.PATH },
        stdio: ["ignore", "ignore", "ignore", "ipc"],
        shell: false,
      });
      const messages: unknown[] = [];
      child.once("error", rejectPromise);
      child.on("message", (message) => {
        messages.push(message);
        if (
          typeof message === "object" &&
          message !== null &&
          "type" in message &&
          message.type === "boot"
        )
          child.send({
            type: "run",
            protocol: 1,
            nonce: "a".repeat(64),
            workspace: join(tmpdir(), "must-not-be-accessed"),
            scenario: "success",
            deadlineAt: Date.now() + 10_000,
            artifacts: { list: "native/openat2-list" },
          });
      });
      child.once("close", (code) => resolvePromise({ code, messages }));
    });
    expect(result.code).toBe(1);
    expect(result.messages).toHaveLength(2);
    expect(result.messages[1]).toMatchObject({
      type: "result",
      ok: false,
      code: "invalid_request",
    });
  });

  it("rejects denied-root intersections, workspace mounts, unknown topology, and substitutions", async () => {
    const module = await harness();
    for (const path of [
      "/data",
      "/data/child",
      "/",
      "/mnt",
      "/mnt/data/supervisor/homeassistant/child",
    ])
      expect(() => module.assertWorkspacePathAllowed(path)).toThrow();
    expect(module.assertWorkspacePathAllowed("/tmp/phase3-safe")).toBe(
      "/tmp/phase3-safe",
    );
    const mountInfo =
      "36 25 0:31 / / rw,relatime - overlay overlay rw\n" +
      "37 36 0:32 / /tmp/phase3-safe/bind rw - tmpfs tmpfs rw\n";
    expect(module.parseMountInfo(mountInfo)).toContain("/tmp/phase3-safe/bind");
    expect(() =>
      module.assertNoMountAtOrBelow("/tmp/phase3-safe", mountInfo),
    ).toThrow();
    expect(module.allowedTopology("success/repo", "directory")).toBe(true);
    expect(module.allowedTopology("success/unknown", "file")).toBe(false);
    expect(
      module.allowedTopology(
        "success/journal/.pending-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "directory",
      ),
    ).toBe(false);

    const root = await mkdtemp(join(tmpdir(), "phase3-poc-substitution-"));
    const path = join(root, "pinned");
    try {
      await writeFile(path, "first");
      const pinned = module.capturePinnedIdentity(path);
      await unlink(path);
      await writeFile(path, "second");
      expect(() => module.assertPinnedIdentity(path, pinned)).toThrow();
    } finally {
      await unlink(path);
      await rmdir(root);
    }
  });

  it("never signals an already-closed worker client", async () => {
    const module = await harness();
    let signals = 0;
    expect(
      module.signalLiveOwnedProcessGroup({ live: false }, () => {
        signals += 1;
      }),
    ).toBe(false);
    expect(signals).toBe(0);
  });

  it("does not authorize run IPC or effects without valid live ownership", async () => {
    const module = await harness();
    let runMessages = 0;
    let effects = 0;
    for (const ownership of [
      undefined,
      {
        pid: 1,
        pgrp: 1,
        session: 1,
        startTime: "invalid",
        executable: { type: "file", dev: 0n, ino: 0n, size: 0n },
      },
    ]) {
      const client = {
        pid: 1,
        live: true,
        ownership,
        send() {
          runMessages += 1;
          effects += 1;
        },
      };
      expect(
        module.authorizeWorkerRun(client, {
          type: "run",
          workspace: "/tmp/must-not-be-accessed",
        }),
      ).toBe(false);
    }
    expect(runMessages).toBe(0);
    expect(effects).toBe(0);
  });

  it.skipIf(process.platform !== "linux")(
    "bounds proc scans and settles live and already-closed owned process groups without post-close signals",
    async () => {
      const module = await harness();
      const root = await mkdtemp(join(tmpdir(), "phase3-poc-process-proof-"));
      const sleeperSource = join(root, "bounded-sleeper.c");
      const helperPaths = [
        join(root, "helper-list"),
        join(root, "helper-read"),
        join(root, "helper-replace"),
      ];
      let matching: ReturnType<typeof spawn> | undefined;
      let hanging: ReturnType<typeof spawn> | undefined;
      let matchingClient: ReturnType<typeof trackedProcess> | undefined;
      let hangingClient: ReturnType<typeof trackedProcess> | undefined;
      try {
        await writeFile(
          sleeperSource,
          [
            "#define _POSIX_C_SOURCE 200809L",
            "#include <errno.h>",
            "#include <time.h>",
            "int main(void) {",
            "  struct timespec remaining = {30, 0};",
            "  while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {}",
            "  return 0;",
            "}",
            "",
          ].join("\n"),
          { mode: 0o600, flag: "wx" },
        );
        await new Promise<void>((resolvePromise, rejectPromise) => {
          const compiler = spawn(
            "cc",
            [
              "-std=c11",
              "-O2",
              "-Wall",
              "-Wextra",
              "-Werror",
              sleeperSource,
              "-o",
              helperPaths[0]!,
            ],
            { cwd: root, stdio: "ignore" },
          );
          compiler.once("error", rejectPromise);
          compiler.once("close", (code, signal) => {
            if (code === 0 && signal === null) resolvePromise();
            else rejectPromise(new Error("bounded sleeper compilation failed"));
          });
        });
        for (const path of helperPaths.slice(1))
          await copyFile(helperPaths[0]!, path);
        for (const path of helperPaths) await chmod(path, 0o555);
        const proofs = {
          list: await fileProof(module, helperPaths[0]!),
          read: await fileProof(module, helperPaths[1]!),
          replace: await fileProof(module, helperPaths[2]!),
        };
        matching = spawn(helperPaths[0]!, ["30"], {
          detached: true,
          stdio: "ignore",
        });
        await new Promise<void>((resolvePromise, rejectPromise) => {
          matching!.once("spawn", resolvePromise);
          matching!.once("error", rejectPromise);
        });
        matchingClient = trackedProcess(module, matching);
        expect(module.procHelperPids(proofs)).toContain(matching.pid);
        expect(() =>
          module.procHelperPids(proofs, { maxPidEntries: 0 }),
        ).toThrow();
        expect(() => module.procHelperPids(proofs, { maxScanMs: 0 })).toThrow();
        expect(() =>
          module.procHelperPids(proofs, { maxExecutableBytes: 0 }),
        ).toThrow();
        await expect(
          module.proveHelpersAbsent(proofs, {
            deadlineAt: performance.now() - 1,
          }),
        ).rejects.toThrow();
        matchingClient.terminate();
        expect((await matchingClient.closed).signal).toBe("SIGKILL");
        await module.proveHelpersAbsent(proofs);
        expect(module.procHelperPids(proofs)).toEqual([]);

        hanging = spawn(
          process.execPath,
          ["-e", "setInterval(() => {}, 1000)"],
          { detached: true, stdio: "ignore" },
        );
        await new Promise<void>((resolvePromise, rejectPromise) => {
          hanging!.once("spawn", resolvePromise);
          hanging!.once("error", rejectPromise);
        });
        hangingClient = trackedProcess(module, hanging);
        await module.settleWorkerProcess(hangingClient, proofs);
        expect((await hangingClient.closed).signal).toBe("SIGKILL");

        const early = spawn(
          process.execPath,
          ["-e", "setTimeout(() => process.exit(7), 50)"],
          {
            detached: true,
            stdio: "ignore",
          },
        );
        await new Promise<void>((resolvePromise, rejectPromise) => {
          early.once("spawn", resolvePromise);
          early.once("error", rejectPromise);
        });
        const earlyClient = trackedProcess(module, early);
        await earlyClient.closed;
        let closedSignals = 0;
        expect(
          module.signalLiveOwnedProcessGroup(earlyClient, () => {
            closedSignals += 1;
          }),
        ).toBe(false);
        await module.settleWorkerProcess(earlyClient, proofs);
        expect(closedSignals).toBe(0);
        await expect(module.proveHelpersAbsent(undefined)).rejects.toThrow();
      } finally {
        if (matchingClient?.live)
          try {
            matchingClient.terminate();
          } catch {
            // The test will retain the primary proof failure.
          }
        if (hangingClient?.live)
          try {
            hangingClient.terminate();
          } catch {
            // The test will retain the primary proof failure.
          }
        await removeIfPresent(sleeperSource);
        for (const path of helperPaths) await removeIfPresent(path);
        await rmdir(root);
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "linux")(
    "preserves an immutable cleanup registry on root, nonce, helper, and scenario-artifact substitution or removal",
    async () => {
      const module = await harness();
      for (const mutation of [
        "root_replace",
        "nonce_replace",
        "helper_replace",
        "helper_remove",
        "artifact_replace",
      ] as const) {
        const fixture = await createLinuxRegistryFixture(module);
        let movedRoot: string | undefined;
        try {
          if (mutation === "root_replace") {
            movedRoot = `${fixture.root}-original`;
            await rename(fixture.root, movedRoot);
            await mkdir(fixture.root, { mode: 0o700 });
          } else {
            const path =
              mutation === "nonce_replace"
                ? fixture.noncePath
                : mutation.startsWith("helper")
                  ? fixture.helperPaths[1]!
                  : fixture.artifactPath;
            await unlink(path);
            if (mutation !== "helper_remove") {
              await writeFile(path, `replacement:${mutation}\n`, {
                mode: 0o600,
                flag: "wx",
              });
              if (mutation === "helper_replace") await chmod(path, 0o555);
            }
          }
          expect(() => module.cleanupTopology(fixture.registry)).toThrow();
          expect(
            await lstat(movedRoot ?? fixture.root).then((value) =>
              value.isDirectory(),
            ),
          ).toBe(true);
        } finally {
          if (movedRoot) {
            await rmdir(fixture.root);
            await rename(movedRoot, fixture.root);
          }
          await fixture.cleanup();
        }
      }
    },
    30_000,
  );

  it("strictly parses ordered JSONL and recursively rejects unsafe evidence", async () => {
    const module = await harness();
    const valid = evidenceOutput(module);
    expect(module.parseWorkflowEvidence(valid).summary.status).toBe("PASSED");
    const records = valid.trimEnd().split("\n");
    records[2] = records[1]!;
    expect(() =>
      module.parseWorkflowEvidence(`${records.join("\n")}\n`),
    ).toThrow();
    expect(() => module.parseWorkflowEvidence(valid.trimEnd())).toThrow();
    expect(
      module.parseWorkflowEvidence(
        evidenceOutput(module, {
          "scenario:rollback": "BLOCKED",
        }),
      ).summary,
    ).toMatchObject({
      status: "FAILED",
      nonPassed: ["scenario:rollback"],
    });
    for (const unsafe of [
      { path: "/tmp/private" },
      { path: "C:\\private\\file" },
      { nested: { SUPERVISOR_TOKEN: "credential" } },
      { candidateBytes: "fixture" },
      { value: Buffer.from("bytes") },
      { value: "x".repeat(513) },
    ])
      expect(() => module.sanitizeEvidence(unsafe)).toThrow();
    expect(
      module.validateWorkerMessage(
        { type: "boot", protocol: 1 },
        "a".repeat(64),
        "success",
      ).kind,
    ).toBe("boot");
    expect(() =>
      module.validateWorkerMessage(
        {
          type: "result",
          protocol: 1,
          nonce: "a".repeat(64),
          scenario: "success",
          ok: true,
          evidence: { path: "/tmp/private" },
        },
        "a".repeat(64),
        "success",
      ),
    ).toThrow();
  });

  it("emits only sanitized bounded JSONL on a public precondition failure", async () => {
    const module = await harness();
    const result = await runNode(
      [fileURLToPath(controllerUrl), module.PHASE3_WORKFLOW_POC_ACK],
      {
        env: { ...process.env, SUPERVISOR_TOKEN: "" },
      },
    );
    expect(result.code).toBe(1);
    expect(result.signal).toBeNull();
    expect(result.stderr).toBe("");
    expect(module.parseWorkflowEvidence(result.stdout).summary.status).toBe(
      "FAILED",
    );
    expect(result.stdout).not.toMatch(/\bat .+:\d+:\d+/u);
    expect(result.stdout).not.toMatch(/[A-Za-z]:[\\/]/u);
    expect(result.stdout).not.toMatch(/"(?:\/[^"]*)"/u);
    expect(result.stdout).not.toContain("Phase 3 disposable POC candidate");
    expect(result.stdout).not.toMatch(
      /SUPERVISOR_TOKEN|BEGIN [A-Z ]*PRIVATE KEY|bearer\s+[A-Za-z0-9._~-]+/iu,
    );
  });
});
