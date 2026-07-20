import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat as nodeLstat,
  mkdir as nodeMkdir,
  open as nodeOpen,
  rename as nodeRename,
  unlink as nodeUnlink,
} from "node:fs/promises";
import { posix } from "node:path";
import { isMap, isScalar, parseDocument } from "yaml";
import { NativeGitBroker, GitReadService } from "./git/gitReads.js";
import { Phase2Tools } from "./phase2Tools.js";
import type { Phase2OperationContext } from "./phase2Contracts.js";
import { Phase2AuditAdapter } from "./proposals/phase2Audit.js";
import { ProposalCursorCodec } from "./proposals/cursor.js";
import { ProposalService } from "./proposals/proposalService.js";
import { ProtectedProposalStore } from "./proposals/storage.js";
import {
  NativeOpenat2Catalog,
  RepositoryCursorCodec,
  RepositoryReadService,
} from "./repository/repositoryReads.js";
import { RepositoryResourceService } from "./repository/resourceProjection.js";
import {
  NativeOpenat2Reader,
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  assertOperationActive,
  type SecretValueProvider,
  type SecureFileReader,
} from "./security/repositoryBoundary.js";
import type { RepositoryCatalogProvider } from "./repository/repositoryReads.js";
import type { GitBroker } from "./git/gitReads.js";
import type { ToolRegistry } from "./toolRegistry.js";
import { validateAndProjectYaml } from "./yaml/strictYamlGate.js";

const MASTER_KEY_BYTES = 32;
const OWNER_ROOT = 0n;
const MAX_SECRET_VALUES = 256;
const MAX_SECRET_VALUE_BYTES = 16 * 1024;
const MAX_SECRET_TOTAL_BYTES = 128 * 1024;

export const PHASE2_FIXED_ADDON_PATHS = Object.freeze({
  repositoryRoot: "/homeassistant",
  dataRoot: "/data",
  stateRoot: "/data/phase2",
  masterKeyPath: "/data/phase2/master.key",
  auditPath: "/data/phase2/audit/phase2.jsonl",
  proposalRoot: "/data/phase2/proposals",
  protectedSourcePaths: Object.freeze(["secrets.yaml"] as const),
});

export const PHASE2_FIXED_ARTIFACT_PATHS = Object.freeze({
  readHelperPath: "/app/native/openat2-read",
  catalogHelperPath: "/app/native/openat2-list",
  gitBrokerPath: "/app/native/git-broker",
  gitPath: "/usr/bin/git",
  runtimeLoaderPath: "/lib/ld-musl-aarch64.so.1",
  runtimeInputPaths: Object.freeze([
    "/usr/lib/libpcre2-8.so.0.14.0",
    "/usr/lib/libz.so.1.3.2",
  ] as readonly string[]),
});

export type Phase2ActivationStage =
  | "options"
  | "artifacts"
  | "master_key"
  | "repository_boundary"
  | "proposal_recovery"
  | "secrets"
  | "identity_registry"
  | "catalog_proof"
  | "tools";

export type Phase2ActivationCode =
  | "invalid_options"
  | "unsafe_artifact"
  | "unsafe_state"
  | "key_unavailable"
  | "key_corrupt"
  | "dependency_unavailable"
  | "secrets_invalid"
  | "service_unhealthy";

export interface Phase2ActivationDiagnostic {
  readonly stage: Phase2ActivationStage;
  readonly code: Phase2ActivationCode;
}

export type Phase2ActivationResult =
  | Readonly<{ status: "activated"; registry: ToolRegistry }>
  | Readonly<{ status: "inactive" }>;

export interface Phase2AddonPaths {
  readonly repositoryRoot: string;
  readonly dataRoot: string;
  readonly stateRoot: string;
  readonly masterKeyPath: string;
  readonly auditPath: string;
  readonly proposalRoot: string;
  readonly protectedSourcePaths: readonly string[];
}

export interface Phase2ActivationArtifacts {
  readonly readHelperPath: string;
  readonly catalogHelperPath: string;
  readonly gitBrokerPath: string;
  readonly gitPath: string;
  readonly runtimeLoaderPath: string;
  readonly runtimeInputPaths: readonly string[];
}

export interface Phase2ActivationOptions {
  readonly enabled: boolean;
  readonly mode: "addon" | "local";
  readonly paths?: Phase2AddonPaths;
  readonly artifacts?: Phase2ActivationArtifacts;
  readonly diagnostics?: (diagnostic: Phase2ActivationDiagnostic) => void;
  readonly dependencies?: Partial<Phase2ActivationDependencies>;
}

export const PHASE2_DEFAULT_ACTIVATION_OPTIONS = Object.freeze({
  enabled: false,
  mode: "local" as const,
  paths: PHASE2_FIXED_ADDON_PATHS,
  artifacts: PHASE2_FIXED_ARTIFACT_PATHS,
});

export interface Phase2Stat {
  readonly mode: bigint;
  readonly uid: bigint;
  readonly size: bigint;
  readonly nlink: bigint;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}

export interface Phase2FileHandle {
  read(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ readonly bytesRead: number }>;
  write(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ readonly bytesWritten: number }>;
  stat(options?: { readonly bigint: true }): Promise<Phase2Stat>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

export interface Phase2ActivationFs {
  lstat(path: string): Promise<Phase2Stat>;
  mkdir(path: string, options: { readonly mode: number }): Promise<void>;
  open(path: string, flags: number, mode?: number): Promise<Phase2FileHandle>;
  rename(from: string, to: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

export interface Phase2ActivationConstructors {
  readonly nativeReader: (options: {
    readonly helperPath: string;
    readonly root: string;
    readonly platform: NodeJS.Platform;
  }) => SecureFileReader;
  readonly nativeCatalog: (options: {
    readonly helperPath: string;
    readonly root: string;
    readonly platform: NodeJS.Platform;
  }) => RepositoryCatalogProvider;
  readonly proposalStore: (root: string) => ProtectedProposalStore;
  readonly auditAdapter: (path: string) => Phase2AuditAdapter;
  readonly identityRegistry: (
    reader: SecureFileReader,
  ) => ProtectedIdentityRegistry;
  readonly repositoryCursorCodec: (key: Uint8Array) => RepositoryCursorCodec;
  readonly proposalCursorCodec: (key: Uint8Array) => ProposalCursorCodec;
  readonly proposalService: (
    store: ProtectedProposalStore,
    audit: Phase2AuditAdapter,
    registry: ProtectedIdentityRegistry,
    catalog: RepositoryCatalogProvider,
    cursors: ProposalCursorCodec,
  ) => ProposalService;
  readonly repositoryReadService: (
    catalog: RepositoryCatalogProvider,
    reader: SecureFileReader,
    registry: ProtectedIdentityRegistry,
    cursors: RepositoryCursorCodec,
  ) => RepositoryReadService;
  readonly repositoryResourceService: (
    catalog: RepositoryCatalogProvider,
    reader: SecureFileReader,
    registry: ProtectedIdentityRegistry,
    cursors: RepositoryCursorCodec,
  ) => RepositoryResourceService;
  readonly gitBroker: (options: {
    readonly brokerPath: string;
    readonly gitPath: string;
    readonly runtimeLoader: string;
    readonly root: string;
    readonly runtimeInputs: readonly string[];
    readonly platform: NodeJS.Platform;
  }) => GitBroker;
  readonly gitReadService: (
    catalog: RepositoryCatalogProvider,
    reader: SecureFileReader,
    registry: ProtectedIdentityRegistry,
    broker: GitBroker,
  ) => GitReadService;
  readonly secretProvider: () => SecretValueProvider;
  readonly phase2Tools: (services: {
    readonly repositoryReadService: RepositoryReadService;
    readonly repositoryResourceService: RepositoryResourceService;
    readonly gitReadService: GitReadService;
    readonly proposalService: ProposalService;
  }) => ToolRegistry;
}

export interface Phase2ActivationDependencies {
  readonly fs: Phase2ActivationFs;
  readonly constructors: Phase2ActivationConstructors;
  readonly randomBytes: (size: number) => Buffer;
  readonly createUuid: () => string;
  readonly now: () => number;
  readonly platform: NodeJS.Platform;
}

const nodeFs: Phase2ActivationFs = {
  async lstat(path) {
    return (await nodeLstat(path, { bigint: true })) as Phase2Stat;
  },
  async mkdir(path, options) {
    await nodeMkdir(path, { mode: options.mode });
  },
  async open(path, flags, mode) {
    return (await nodeOpen(path, flags, mode)) as Phase2FileHandle;
  },
  rename: nodeRename,
  unlink: nodeUnlink,
};

const defaultConstructors: Phase2ActivationConstructors = {
  nativeReader: (options) => new NativeOpenat2Reader(options),
  nativeCatalog: (options) => new NativeOpenat2Catalog(options),
  proposalStore: (root) => new ProtectedProposalStore(root),
  auditAdapter: (path) => new Phase2AuditAdapter(path),
  identityRegistry: (reader) => new ProtectedIdentityRegistry(reader),
  repositoryCursorCodec: (key) => new RepositoryCursorCodec(key),
  proposalCursorCodec: (key) => new ProposalCursorCodec(key),
  proposalService: (store, audit, registry, catalog, cursors) =>
    new ProposalService(store, audit, registry, catalog, cursors),
  repositoryReadService: (catalog, reader, registry, cursors) =>
    new RepositoryReadService(catalog, reader, registry, cursors),
  repositoryResourceService: (catalog, reader, registry, cursors) =>
    new RepositoryResourceService(catalog, reader, registry, cursors),
  gitBroker: (options) => new NativeGitBroker(options),
  gitReadService: (catalog, reader, registry, broker) =>
    new GitReadService(catalog, reader, registry, broker),
  secretProvider: () => new ProductionSecretValueProvider(),
  phase2Tools: (services) => new Phase2Tools(services),
};

export async function buildPhase2Registry(
  options: Phase2ActivationOptions,
): Promise<ToolRegistry | undefined> {
  if (!options.enabled || options.mode === "local") return undefined;

  const paths = options.paths ?? PHASE2_FIXED_ADDON_PATHS;
  const artifacts = options.artifacts ?? PHASE2_FIXED_ARTIFACT_PATHS;
  const deps = activationDependencies(options.dependencies);
  let stage: Phase2ActivationStage = "options";
  try {
    assertActivationOptions(paths, artifacts);
    stage = "artifacts";
    await validateArtifacts(deps.fs, paths, artifacts);
    stage = "master_key";
    const masterKey = await loadOrCreateMasterKey(
      deps.fs,
      paths,
      deps.randomBytes,
      deps.createUuid,
    );
    let keys: Phase2DerivedKeys | undefined;
    try {
      keys = derivePhase2Keys(masterKey);
    } finally {
      masterKey.fill(0);
    }

    stage = "repository_boundary";
    const reader = deps.constructors.nativeReader({
      helperPath: artifacts.readHelperPath,
      root: paths.repositoryRoot,
      platform: deps.platform,
    });
    const catalog = deps.constructors.nativeCatalog({
      helperPath: artifacts.catalogHelperPath,
      root: paths.repositoryRoot,
      platform: deps.platform,
    });
    const registry = deps.constructors.identityRegistry(reader);
    const repositoryCursors = deps.constructors.repositoryCursorCodec(
      keys.repositoryCursorKey,
    );
    const proposalCursors = deps.constructors.proposalCursorCodec(
      keys.proposalCursorKey,
    );
    keys.repositoryCursorKey.fill(0);
    keys.proposalCursorKey.fill(0);

    stage = "proposal_recovery";
    const store = deps.constructors.proposalStore(paths.proposalRoot);
    const audit = deps.constructors.auditAdapter(paths.auditPath);
    const proposalService = deps.constructors.proposalService(
      store,
      audit,
      registry,
      catalog,
      proposalCursors,
    );
    await proposalService.initialize();

    stage = "secrets";
    const secretProvider = deps.constructors.secretProvider();
    stage = "identity_registry";
    await registry.initialize(
      Object.freeze([...paths.protectedSourcePaths]),
      secretProvider,
      activationContext(deps),
    );

    stage = "catalog_proof";
    await catalog.catalog(activationContext(deps));

    stage = "tools";
    const repositoryReadService = deps.constructors.repositoryReadService(
      catalog,
      reader,
      registry,
      repositoryCursors,
    );
    const repositoryResourceService =
      deps.constructors.repositoryResourceService(
        catalog,
        reader,
        registry,
        repositoryCursors,
      );
    const gitBroker = deps.constructors.gitBroker({
      brokerPath: artifacts.gitBrokerPath,
      gitPath: artifacts.gitPath,
      runtimeLoader: artifacts.runtimeLoaderPath,
      root: paths.repositoryRoot,
      runtimeInputs: artifacts.runtimeInputPaths,
      platform: deps.platform,
    });
    const gitReadService = deps.constructors.gitReadService(
      catalog,
      reader,
      registry,
      gitBroker,
    );
    return deps.constructors.phase2Tools({
      repositoryReadService,
      repositoryResourceService,
      gitReadService,
      proposalService,
    });
  } catch (error) {
    options.diagnostics?.({ stage, code: activationCode(stage, error) });
    return undefined;
  }
}

export interface Phase2DerivedKeys {
  readonly repositoryCursorKey: Buffer;
  readonly proposalCursorKey: Buffer;
}

export function derivePhase2Keys(masterKey: Uint8Array): Phase2DerivedKeys {
  if (masterKey.byteLength !== MASTER_KEY_BYTES)
    throw new RepositoryBoundaryError("service_unhealthy", "Invalid key");
  return Object.freeze({
    repositoryCursorKey: domainKey(
      masterKey,
      "HA_PHASE2_REPOSITORY_CURSOR_KEY_V1\0",
    ),
    proposalCursorKey: domainKey(
      masterKey,
      "HA_PHASE2_PROPOSAL_CURSOR_KEY_V1\0",
    ),
  });
}

export class ProductionSecretValueProvider implements SecretValueProvider {
  async loadExactValues(
    sources: readonly { readonly path: string; readonly bytes: Uint8Array }[],
    context: Phase2OperationContext,
  ): Promise<readonly string[]> {
    const values: string[] = [];
    let total = 0;
    try {
      for (const source of sources) {
        assertOperationActive(context);
        if (source.path !== "secrets.yaml")
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected source is invalid",
          );
        await validateAndProjectYaml(source.bytes, context);
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          source.bytes,
        );
        const document = parseDocument(text, {
          version: "1.2",
          schema: "core",
          strict: true,
          uniqueKeys: true,
          merge: false,
          prettyErrors: false,
          logLevel: "warn",
        });
        if (document.errors.length > 0 || document.warnings.length > 0)
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Secrets YAML failed strict parsing",
          );
        if (document.contents === null) continue;
        if (!isMap(document.contents))
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Secrets YAML must be a map",
          );
        for (const item of document.contents.items) {
          assertOperationActive(context);
          if (!isScalar(item.value))
            throw new RepositoryBoundaryError(
              "service_unhealthy",
              "Secrets YAML values must be scalars",
            );
          const raw = item.value.value;
          if (raw === null || typeof raw === "undefined") continue;
          if (
            typeof raw !== "string" &&
            typeof raw !== "number" &&
            typeof raw !== "boolean"
          )
            throw new RepositoryBoundaryError(
              "service_unhealthy",
              "Secrets YAML value is invalid",
            );
          const value = String(raw);
          const bytes = Buffer.byteLength(value, "utf8");
          if (bytes === 0 || bytes > MAX_SECRET_VALUE_BYTES)
            throw new RepositoryBoundaryError(
              "service_unhealthy",
              "Secrets YAML value is outside bounds",
            );
          values.push(value);
          total += bytes;
          if (
            values.length > MAX_SECRET_VALUES ||
            total > MAX_SECRET_TOTAL_BYTES
          )
            throw new RepositoryBoundaryError(
              "service_unhealthy",
              "Secrets YAML values exceed bounds",
            );
        }
      }
      return Object.freeze([...new Set(values)]);
    } catch (error) {
      throw error instanceof RepositoryBoundaryError
        ? error
        : new RepositoryBoundaryError(
            "service_unhealthy",
            "Secrets YAML failed safely",
          );
    } finally {
      for (const source of sources) source.bytes.fill(0);
    }
  }
}

function activationDependencies(
  overrides: Partial<Phase2ActivationDependencies> | undefined,
): Phase2ActivationDependencies {
  return {
    fs: overrides?.fs ?? nodeFs,
    constructors: {
      ...defaultConstructors,
      ...overrides?.constructors,
    },
    randomBytes: overrides?.randomBytes ?? randomBytes,
    createUuid: overrides?.createUuid ?? randomUUID,
    now: overrides?.now ?? Date.now,
    platform: overrides?.platform ?? process.platform,
  };
}

function assertActivationOptions(
  paths: Phase2AddonPaths,
  artifacts: Phase2ActivationArtifacts,
): void {
  const allPaths = [
    paths.repositoryRoot,
    paths.dataRoot,
    paths.stateRoot,
    paths.masterKeyPath,
    paths.auditPath,
    paths.proposalRoot,
    artifacts.readHelperPath,
    artifacts.catalogHelperPath,
    artifacts.gitBrokerPath,
    artifacts.gitPath,
    artifacts.runtimeLoaderPath,
    ...artifacts.runtimeInputPaths,
  ];
  if (
    allPaths.some((path) => !isPosixAbsoluteNormalized(path)) ||
    !paths.masterKeyPath.startsWith(`${paths.stateRoot}/`) ||
    !paths.auditPath.startsWith(`${paths.stateRoot}/`) ||
    !paths.proposalRoot.startsWith(`${paths.stateRoot}/`) ||
    artifacts.runtimeInputPaths.length > 16 ||
    new Set(artifacts.runtimeInputPaths).size !==
      artifacts.runtimeInputPaths.length ||
    paths.protectedSourcePaths.length < 1 ||
    !paths.protectedSourcePaths.includes("secrets.yaml")
  )
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Phase 2 activation options are invalid",
    );
}

async function validateArtifacts(
  fs: Phase2ActivationFs,
  paths: Phase2AddonPaths,
  artifacts: Phase2ActivationArtifacts,
): Promise<void> {
  await assertAbsoluteDirectory(fs, paths.repositoryRoot);
  for (const path of [
    artifacts.readHelperPath,
    artifacts.catalogHelperPath,
    artifacts.gitBrokerPath,
    artifacts.gitPath,
    artifacts.runtimeLoaderPath,
    ...artifacts.runtimeInputPaths,
  ])
    await assertRootRegularArtifact(fs, path);
}

async function loadOrCreateMasterKey(
  fs: Phase2ActivationFs,
  paths: Phase2AddonPaths,
  createRandom: (size: number) => Buffer,
  createUuid: () => string,
): Promise<Buffer> {
  await ensureTrustedParentDirectory(fs, paths.dataRoot);
  await mkdirIfMissing(fs, paths.stateRoot);
  await ensureProtectedDirectory(fs, paths.stateRoot);
  try {
    return await readExistingMasterKey(fs, paths.masterKeyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const fresh = createRandom(MASTER_KEY_BYTES);
  try {
    await atomicCreateMasterKey(fs, paths.masterKeyPath, fresh, createUuid);
    return Buffer.from(fresh);
  } finally {
    fresh.fill(0);
  }
}

async function readExistingMasterKey(
  fs: Phase2ActivationFs,
  path: string,
): Promise<Buffer> {
  const before = await fs.lstat(path);
  assertProtectedFile(before, MASTER_KEY_BYTES);
  const handle = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    assertProtectedFile(opened, MASTER_KEY_BYTES);
    const key = Buffer.alloc(MASTER_KEY_BYTES);
    try {
      await readExactly(handle, key);
      const after = await handle.stat({ bigint: true });
      const linked = await fs.lstat(path);
      assertProtectedFile(after, MASTER_KEY_BYTES);
      assertProtectedFile(linked, MASTER_KEY_BYTES);
      if (key.every((byte) => byte === 0))
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Master key is corrupt",
        );
      return key;
    } catch (error) {
      key.fill(0);
      throw error;
    }
  } finally {
    await handle.close();
  }
}

async function atomicCreateMasterKey(
  fs: Phase2ActivationFs,
  path: string,
  key: Uint8Array,
  createUuid: () => string,
): Promise<void> {
  const directory = posix.dirname(path);
  const temporary = posix.join(directory, `.master-key-${createUuid()}.tmp`);
  let reserved = false;
  let committed = false;
  const temp = await fs.open(
    temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
    0o600,
  );
  try {
    try {
      await writeAll(temp, key);
      await temp.sync();
    } finally {
      await temp.close();
    }
    assertProtectedFile(await fs.lstat(temporary), MASTER_KEY_BYTES);
    const reservation = await fs.open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    try {
      await reservation.sync();
    } finally {
      await reservation.close();
    }
    reserved = true;
    await fs.rename(temporary, path);
    committed = true;
    await syncDirectory(fs, directory);
    assertProtectedFile(await fs.lstat(path), MASTER_KEY_BYTES);
  } catch (error) {
    if (!committed) await unlinkIfExists(fs, temporary);
    if (reserved && !committed) await unlinkIfExists(fs, path);
    throw error;
  }
}

async function readExactly(
  handle: Phase2FileHandle,
  output: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < output.byteLength) {
    try {
      const { bytesRead } = await handle.read(
        output,
        offset,
        output.byteLength - offset,
        offset,
      );
      if (bytesRead <= 0 || bytesRead > output.byteLength - offset)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Master key read was incomplete",
        );
      offset += bytesRead;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}

async function writeAll(
  handle: Phase2FileHandle,
  input: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < input.byteLength) {
    try {
      const { bytesWritten } = await handle.write(
        input,
        offset,
        input.byteLength - offset,
        offset,
      );
      if (bytesWritten <= 0 || bytesWritten > input.byteLength - offset)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Master key write made no progress",
        );
      offset += bytesWritten;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}

async function syncDirectory(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  const handle = await fs.open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function mkdirIfMissing(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  try {
    await fs.mkdir(path, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}

async function unlinkIfExists(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  try {
    await fs.unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function assertAbsoluteDirectory(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  if (!isPosixAbsoluteNormalized(path) || path === "/")
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Root directory is invalid",
    );
  const metadata = await fs.lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink())
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Root directory is unsafe",
    );
}

async function ensureTrustedParentDirectory(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  const metadata = await fs.lstat(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== OWNER_ROOT ||
    (metadata.mode & 0o022n) !== 0n
  )
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Protected state parent is unsafe",
    );
}

async function ensureProtectedDirectory(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  const metadata = await fs.lstat(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== OWNER_ROOT ||
    (metadata.mode & 0o077n) !== 0n
  )
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Protected directory is unsafe",
    );
}

async function assertRootRegularArtifact(
  fs: Phase2ActivationFs,
  path: string,
): Promise<void> {
  if (!isPosixAbsoluteNormalized(path))
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Artifact path is invalid",
    );
  const metadata = await fs.lstat(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== OWNER_ROOT ||
    (metadata.mode & 0o022n) !== 0n
  )
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Artifact is unsafe",
    );
}

function assertProtectedFile(metadata: Phase2Stat, size: number): void {
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1n ||
    metadata.uid !== OWNER_ROOT ||
    metadata.size !== BigInt(size) ||
    (metadata.mode & 0o777n) !== 0o600n
  )
    throw new RepositoryBoundaryError(
      "service_unhealthy",
      "Protected master key is unsafe",
    );
}

function domainKey(masterKey: Uint8Array, domain: string): Buffer {
  return createHmac("sha256", masterKey).update(domain, "ascii").digest();
}

function isPosixAbsoluteNormalized(path: string): boolean {
  return (
    path.startsWith("/") &&
    !path.includes("\\") &&
    posix.normalize(path) === path
  );
}

function activationContext(
  deps: Phase2ActivationDependencies,
): Phase2OperationContext {
  return Object.freeze({
    requestId: deps.createUuid(),
    operationId: deps.createUuid(),
    deadlineAt: deps.now() + 30_000,
    signal: new AbortController().signal,
  });
}

function activationCode(
  stage: Phase2ActivationStage,
  error: unknown,
): Phase2ActivationCode {
  if (stage === "options") return "invalid_options";
  if (stage === "artifacts") return "unsafe_artifact";
  if (stage === "master_key") {
    if (error instanceof RepositoryBoundaryError) {
      if (error.message.includes("corrupt")) return "key_corrupt";
      if (error.message.includes("unsafe")) return "unsafe_state";
    }
    return "key_unavailable";
  }
  if (stage === "secrets" || stage === "identity_registry")
    return "secrets_invalid";
  if (stage === "repository_boundary" || stage === "catalog_proof")
    return "dependency_unavailable";
  return "service_unhealthy";
}

function isEintr(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === "EINTR"
  );
}
