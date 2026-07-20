import { Buffer } from "node:buffer";
import { constants } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  PHASE2_FIXED_ADDON_PATHS,
  PHASE2_FIXED_ARTIFACT_PATHS,
  ProductionSecretValueProvider,
  buildPhase2Registry,
  derivePhase2Keys,
  type Phase2ActivationConstructors,
  type Phase2ActivationDependencies,
  type Phase2ActivationDiagnostic,
  type Phase2ActivationFs,
  type Phase2FileHandle,
  type Phase2Stat,
} from "../src/phase2Activation.js";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";

const paths = PHASE2_FIXED_ADDON_PATHS;
const artifacts = PHASE2_FIXED_ARTIFACT_PATHS;

describe("Phase 2 activation boundary", () => {
  it("does not touch injected dependencies when disabled or local", async () => {
    const fs = fakeFs();
    const deps = depsWith({ fs });
    await expect(
      buildPhase2Registry({
        enabled: false,
        mode: "addon",
        dependencies: deps,
      }),
    ).resolves.toBeUndefined();
    await expect(
      buildPhase2Registry({
        enabled: true,
        mode: "local",
        dependencies: deps,
      }),
    ).resolves.toBeUndefined();
    expect(fs.events).toEqual([]);
  });

  it("runs the healthy gates in order and returns the injected registry", async () => {
    const events: string[] = [];
    const registry = Object.freeze({ names: () => [] });
    const fs = fakeFs(undefined, events);
    const deps = depsWith({ fs }, constructors(events, registry));
    const result = await buildPhase2Registry({
      enabled: true,
      mode: "addon",
      dependencies: deps,
    });
    expect(result).toBe(registry);
    expect(events).toEqual([
      "lstat:/homeassistant",
      "lstat:/app/native/openat2-read",
      "lstat:/app/native/openat2-list",
      "lstat:/app/native/git-broker",
      "lstat:/usr/bin/git",
      "lstat:/lib/ld-musl-aarch64.so.1",
      "lstat:/usr/lib/libpcre2-8.so.0.14.0",
      "lstat:/usr/lib/libz.so.1.3.2",
      "lstat:/data",
      "mkdir:/data/phase2",
      "lstat:/data/phase2",
      "lstat:/data/phase2/master.key",
      "open:/data/phase2/master.key",
      "read:/data/phase2/master.key",
      "lstat:/data/phase2/master.key",
      "close:/data/phase2/master.key",
      "reader",
      "catalog",
      "registry",
      "repoCursor",
      "proposalCursor",
      "store",
      "audit",
      "proposalService",
      "proposalInitialize",
      "secretProvider",
      "registryInitialize",
      "catalogProof",
      "repoRead",
      "resource",
      "broker",
      "gitRead",
      "tools",
    ]);
  });

  it("reports closed diagnostics without leaking causes for gate failures", async () => {
    for (const [path, stage, code] of [
      ["/app/native/openat2-list", "artifacts", "unsafe_artifact"],
      ["/data/phase2/master.key", "master_key", "unsafe_state"],
    ] as const) {
      const diagnostics: Phase2ActivationDiagnostic[] = [];
      const fs = fakeFs({
        [path]: stat({ file: true, mode: 0o666n, size: 32n }),
      });
      const result = await buildPhase2Registry({
        enabled: true,
        mode: "addon",
        diagnostics: (diagnostic) => diagnostics.push(diagnostic),
        dependencies: depsWith({ fs }),
      });
      expect(result).toBeUndefined();
      expect(diagnostics).toEqual([{ stage, code }]);
      expect(Object.keys(diagnostics[0]!)).toEqual(["stage", "code"]);
      expect(JSON.stringify(diagnostics)).not.toContain("secret");
      expect(JSON.stringify(diagnostics)).not.toContain("cause");
    }
  });

  it("creates, reuses, and rejects unsafe master keys", async () => {
    const freshFs = fakeFs({ [paths.masterKeyPath]: undefined });
    const fresh = await buildPhase2Registry({
      enabled: true,
      mode: "addon",
      dependencies: depsWith({
        fs: freshFs,
        randomBytes: () => Buffer.alloc(32, 7),
      }),
    });
    expect(fresh).toBeDefined();
    expect(
      freshFs.files.get(paths.masterKeyPath)?.equals(Buffer.alloc(32, 7)),
    ).toBe(true);
    expect(
      freshFs.events.some(
        (event) =>
          event.startsWith("rename:/data/phase2/.master-key-") &&
          event.endsWith(`.tmp:${paths.masterKeyPath}`),
      ),
    ).toBe(true);

    const restartFs = fakeFs();
    await buildPhase2Registry({
      enabled: true,
      mode: "addon",
      dependencies: depsWith({ fs: restartFs }),
    });
    expect(restartFs.events.some((event) => event.startsWith("rename:"))).toBe(
      false,
    );

    for (const bad of [
      { name: "corrupt", stat: stat({ file: true, mode: 0o600n, size: 31n }) },
      { name: "mode", stat: stat({ file: true, mode: 0o644n, size: 32n }) },
      {
        name: "symlink",
        stat: stat({ file: true, mode: 0o600n, size: 32n, symlink: true }),
      },
    ]) {
      const diagnostics: Phase2ActivationDiagnostic[] = [];
      await expect(
        buildPhase2Registry({
          enabled: true,
          mode: "addon",
          diagnostics: (diagnostic) => diagnostics.push(diagnostic),
          dependencies: depsWith({
            fs: fakeFs({ [paths.masterKeyPath]: bad.stat }),
          }),
        }),
      ).resolves.toBeUndefined();
      expect(diagnostics[0]?.stage, bad.name).toBe("master_key");
    }
  });

  it("derives domain-separated cursor keys", () => {
    const master = Buffer.alloc(32, 9);
    const first = derivePhase2Keys(master);
    const second = derivePhase2Keys(master);
    expect(first.repositoryCursorKey).toEqual(second.repositoryCursorKey);
    expect(first.proposalCursorKey).toEqual(second.proposalCursorKey);
    expect(first.repositoryCursorKey.equals(first.proposalCursorKey)).toBe(
      false,
    );
  });

  it("strictly extracts secret scalar values only and wipes source buffers", async () => {
    const provider = new ProductionSecretValueProvider();
    const source = Buffer.from(
      "api_password: s3cr3t\nnumeric: 42\nflag: true\n",
      "utf8",
    );
    const values = await provider.loadExactValues(
      [{ path: "secrets.yaml", bytes: source }],
      context(),
    );
    expect(values).toEqual(["s3cr3t", "42", "true"]);
    expect(source.every((byte) => byte === 0)).toBe(true);
    expect(values).not.toContain("api_password");
  });

  it("rejects malformed, nested, and out-of-bounds secrets", async () => {
    const cases = [
      "bad: [unterminated",
      "nested:\n  child: value\n",
      `huge: ${"x".repeat(16 * 1024 + 1)}\n`,
    ];
    for (const body of cases) {
      await expect(
        new ProductionSecretValueProvider().loadExactValues(
          [{ path: "secrets.yaml", bytes: Buffer.from(body, "utf8") }],
          context(),
        ),
      ).rejects.toThrow();
    }
  });

  it("maps secret startup failures to closed diagnostics without causes", async () => {
    const diagnostics: Phase2ActivationDiagnostic[] = [];
    const result = await buildPhase2Registry({
      enabled: true,
      mode: "addon",
      diagnostics: (diagnostic) => diagnostics.push(diagnostic),
      dependencies: depsWith(
        { fs: fakeFs() },
        constructors([], Object.freeze({ names: () => [] }), {
          registryInitialize: async () => {
            throw new Error("the real secret value is hunter2");
          },
        }),
      ),
    });
    expect(result).toBeUndefined();
    expect(diagnostics).toEqual([
      { stage: "identity_registry", code: "secrets_invalid" },
    ]);
    expect(JSON.stringify(diagnostics)).not.toContain("hunter2");
  });
});

function context(): Phase2OperationContext {
  return {
    requestId: "11111111-1111-4111-8111-111111111111",
    operationId: "22222222-2222-4222-8222-222222222222",
    deadlineAt: Date.now() + 30_000,
    signal: new AbortController().signal,
  };
}

function depsWith(
  partial: Partial<Phase2ActivationDependencies>,
  ctor = constructors(),
): Partial<Phase2ActivationDependencies> {
  return {
    constructors: ctor,
    createUuid: () => "11111111-1111-4111-8111-111111111111",
    now: () => 1_000,
    platform: "linux",
    ...partial,
  };
}

function constructors(
  events: string[] = [],
  registry: object = Object.freeze({ names: () => [] }),
  overrides: { readonly registryInitialize?: () => Promise<void> } = {},
): Phase2ActivationConstructors {
  const reader = {};
  const catalog = {
    catalog: vi.fn(async () => {
      events.push("catalogProof");
      return {
        rootIdentity: { device: "1", inode: "2" },
        directories: [],
        files: [],
      };
    }),
  };
  const protectedRegistry = {
    initialize: vi.fn(async () => {
      events.push("registryInitialize");
      await overrides.registryInitialize?.();
    }),
  };
  const proposalService = {
    initialize: vi.fn(async () => events.push("proposalInitialize")),
  };
  return {
    nativeReader: () => (events.push("reader"), reader as never),
    nativeCatalog: () => (events.push("catalog"), catalog as never),
    identityRegistry: () => (
      events.push("registry"),
      protectedRegistry as never
    ),
    repositoryCursorCodec: () => (events.push("repoCursor"), {} as never),
    proposalCursorCodec: () => (events.push("proposalCursor"), {} as never),
    proposalStore: () => (events.push("store"), {} as never),
    auditAdapter: () => (events.push("audit"), {} as never),
    proposalService: () => (
      events.push("proposalService"),
      proposalService as never
    ),
    secretProvider: () => (events.push("secretProvider"), {} as never),
    repositoryReadService: () => (events.push("repoRead"), {} as never),
    repositoryResourceService: () => (events.push("resource"), {} as never),
    gitBroker: () => (events.push("broker"), {} as never),
    gitReadService: () => (events.push("gitRead"), {} as never),
    phase2Tools: () => (events.push("tools"), registry as never),
  };
}

function fakeFs(
  stats: Record<string, Phase2Stat | undefined> = {},
  externalEvents?: string[],
): Phase2ActivationFs & {
  readonly events: string[];
  readonly files: Map<string, Buffer>;
} {
  const events = externalEvents ?? [];
  const files = new Map<string, Buffer>([
    [paths.masterKeyPath, Buffer.alloc(32, 5)],
  ]);
  const statMap = new Map<string, Phase2Stat>();
  for (const path of [
    paths.repositoryRoot,
    artifacts.readHelperPath,
    artifacts.catalogHelperPath,
    artifacts.gitBrokerPath,
    artifacts.gitPath,
    artifacts.runtimeLoaderPath,
    ...artifacts.runtimeInputPaths,
  ])
    statMap.set(
      path,
      stat({
        file: path !== paths.repositoryRoot,
        directory: path === paths.repositoryRoot,
        mode: 0o555n,
      }),
    );
  statMap.set(paths.dataRoot, stat({ directory: true, mode: 0o700n }));
  statMap.set(paths.stateRoot, stat({ directory: true, mode: 0o700n }));
  statMap.set(
    paths.masterKeyPath,
    stat({ file: true, mode: 0o600n, size: 32n }),
  );
  for (const [path, value] of Object.entries(stats)) {
    if (value === undefined) statMap.delete(path);
    else statMap.set(path, value);
  }
  return {
    events,
    files,
    async lstat(path) {
      events.push(`lstat:${path}`);
      const value = statMap.get(path);
      if (!value) {
        const error = new Error("missing") as NodeJS.ErrnoException;
        error.code = "ENOENT";
        throw error;
      }
      return value;
    },
    async mkdir(path) {
      events.push(`mkdir:${path}`);
      statMap.set(path, stat({ directory: true, mode: 0o700n }));
    },
    async open(path, flags) {
      events.push(`open:${path}`);
      if ((flags & constants.O_CREAT) !== 0) {
        files.set(path, Buffer.alloc(0));
        statMap.set(path, stat({ file: true, mode: 0o600n, size: 0n }));
      }
      if (
        !files.has(path) &&
        path !== paths.stateRoot &&
        path !== paths.dataRoot
      ) {
        const error = new Error("missing") as NodeJS.ErrnoException;
        error.code = "ENOENT";
        throw error;
      }
      return handle(path, events, files, statMap);
    },
    async rename(from, to) {
      events.push(`rename:${from}:${to}`);
      const content = files.get(from) ?? Buffer.alloc(0);
      files.set(to, Buffer.from(content));
      files.delete(from);
      statMap.set(
        to,
        stat({ file: true, mode: 0o600n, size: BigInt(content.length) }),
      );
      statMap.delete(from);
    },
    async unlink(path) {
      events.push(`unlink:${path}`);
      files.delete(path);
      statMap.delete(path);
    },
  };
}

function handle(
  path: string,
  events: string[],
  files: Map<string, Buffer>,
  stats: Map<string, Phase2Stat>,
): Phase2FileHandle {
  return {
    async read(buffer, offset, length, position) {
      events.push(`read:${path}`);
      const source = files.get(path) ?? Buffer.alloc(0);
      const chunk = source.subarray(position, position + length);
      buffer.set(chunk, offset);
      return { bytesRead: chunk.length };
    },
    async write(buffer, offset, length, position) {
      events.push(`write:${path}`);
      const previous = files.get(path) ?? Buffer.alloc(0);
      const next = Buffer.alloc(Math.max(previous.length, position + length));
      previous.copy(next);
      Buffer.from(buffer.subarray(offset, offset + length)).copy(
        next,
        position,
      );
      files.set(path, next);
      stats.set(
        path,
        stat({ file: true, mode: 0o600n, size: BigInt(next.length) }),
      );
      return { bytesWritten: length };
    },
    async stat() {
      return stats.get(path) ?? stat({ directory: true, mode: 0o700n });
    },
    async sync() {
      events.push(`sync:${path}`);
    },
    async close() {
      events.push(`close:${path}`);
    },
  };
}

function stat(options: {
  readonly file?: boolean;
  readonly directory?: boolean;
  readonly symlink?: boolean;
  readonly mode: bigint;
  readonly size?: bigint;
  readonly uid?: bigint;
}): Phase2Stat {
  return {
    mode: options.mode,
    uid: options.uid ?? 0n,
    size: options.size ?? 0n,
    nlink: 1n,
    isFile: () => Boolean(options.file),
    isDirectory: () => Boolean(options.directory),
    isSymbolicLink: () => Boolean(options.symlink),
  };
}
