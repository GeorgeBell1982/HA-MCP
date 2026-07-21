import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { link, lstat, mkdir, open, readdir, rm } from "node:fs/promises";
import { basename, isAbsolute, join, parse, resolve } from "node:path";
import { z } from "zod";
import { PHASE2_MAX_TEXT_BYTES } from "../phase2Contracts.js";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "../proposals/durability.js";
import type {
  Phase3CheckpointPort,
  Phase3OperationContext,
} from "./applyCoordinator.js";
import { canonicalJson, sha256, sha256Schema } from "./contracts.js";
import { canonicalPhase3Path } from "./resourceLocks.js";

export const PHASE3_CHECKPOINT_LIMITS = Object.freeze({
  checkpoints: 128,
  pendingEntries: 64,
  contentBytes: PHASE2_MAX_TEXT_BYTES,
  recordBytes: 1024 * 1024,
  aggregateBytes: 64 * 1024 * 1024,
  scanEntries: 256,
});

export type Phase3CheckpointHookStage =
  | "file_synced"
  | "file_closed"
  | "entry_synced"
  | "pre_link"
  | "post_link"
  | "parent_synced";

export type Phase3CheckpointErrorCode =
  | "checkpoint_unhealthy"
  | "checkpoint_missing"
  | "checkpoint_conflict"
  | "checkpoint_illegal"
  | "checkpoint_commit_unknown";

export class Phase3CheckpointError extends Error {
  constructor(
    public readonly code: Phase3CheckpointErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Phase3CheckpointError";
  }
}

export class Phase3CheckpointSimulatedCrash extends Error {
  readonly retainPhase3Pending = true;

  constructor(
    public readonly stage: Phase3CheckpointHookStage,
    message = `Simulated Phase 3 checkpoint crash at ${stage}`,
  ) {
    super(message);
    this.name = "Phase3CheckpointSimulatedCrash";
  }
}

export interface Phase3CheckpointRecord {
  readonly schemaVersion: 1;
  readonly nonce: string;
  readonly checkpointId: string;
  readonly path: string;
  readonly expectedSha256: string;
  readonly sourceSha256: string;
  readonly contentSha256: string;
  readonly contentBase64: string;
  readonly storageSha256: string;
}

export interface Phase3CheckpointHookContext {
  readonly stage: Phase3CheckpointHookStage;
  readonly root: string;
  readonly pendingPath: string;
  readonly finalPath: string;
  readonly recordPath: string;
  readonly record: Phase3CheckpointRecord;
}

export interface Phase3CheckpointHooks {
  readonly afterStage?: (context: Phase3CheckpointHookContext) => Promise<void>;
}

export interface Phase3CheckpointFileHandle {
  write(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ bytesWritten: number }>;
  sync(): Promise<void>;
  close(): Promise<void>;
  stat(options: { bigint: true }): Promise<BigIntStats>;
  readFile(): Promise<Buffer>;
}

export interface Phase3CheckpointFilesystem {
  readonly lstat: typeof lstat;
  readonly mkdir: typeof mkdir;
  readonly open: (
    path: string,
    flags: number,
    mode?: number,
  ) => Promise<Phase3CheckpointFileHandle>;
  readonly readdir: typeof readdir;
  readonly link: typeof link;
  readonly rm: typeof rm;
}

export interface DurablePhase3CheckpointOptions {
  readonly durability?: Phase2DurabilityPort;
  readonly filesystem?: Phase3CheckpointFilesystem;
  readonly hooks?: Phase3CheckpointHooks;
}

const lowercaseUuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const pendingNamePattern =
  /^\.pending-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const canonicalCheckpointBase64Schema = z.string().refine((value) => {
  if (
    value !== "" &&
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      value,
    )
  )
    return false;
  const decoded = Buffer.from(value, "base64");
  try {
    return (
      decoded.byteLength <= PHASE3_CHECKPOINT_LIMITS.contentBytes &&
      decoded.toString("base64") === value
    );
  } finally {
    decoded.fill(0);
  }
}, "Checkpoint content must be canonical bounded base64");

const checkpointRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    nonce: z.string().regex(lowercaseUuid),
    checkpointId: z.string().regex(lowercaseUuid),
    path: z.string(),
    expectedSha256: sha256Schema,
    sourceSha256: sha256Schema,
    contentSha256: sha256Schema,
    contentBase64: canonicalCheckpointBase64Schema,
    storageSha256: sha256Schema,
  })
  .strict();

const defaultFilesystem: Phase3CheckpointFilesystem = Object.freeze({
  link,
  lstat,
  mkdir,
  open: async (path: string, flags: number, mode?: number) =>
    await open(path, flags, mode),
  readdir,
  rm,
});

export class DurablePhase3Checkpoints implements Phase3CheckpointPort {
  private readonly durability: Phase2DurabilityPort;
  private readonly filesystem: Phase3CheckpointFilesystem;
  private readonly hooks: Phase3CheckpointHooks;
  private readonly nativeDurability: boolean;
  private unhealthy = true;
  private initialized = false;
  private checkpointIdentities = new Map<string, BigIntStats>();
  private aggregateBytes = 0;

  constructor(
    private readonly root: string,
    options: DurablePhase3CheckpointOptions = {},
  ) {
    this.nativeDurability = options.durability === undefined;
    this.durability = options.durability ?? strictPhase2Durability;
    this.filesystem = options.filesystem ?? defaultFilesystem;
    this.hooks = options.hooks ?? {};
  }

  async initialize(): Promise<void> {
    this.unhealthy = true;
    try {
      if (this.nativeDurability && process.platform !== "linux")
        throw unhealthy("Native Phase 3 checkpoint durability requires Linux");
      await this.ensureRoot();
      this.replaceScanned(await this.scan());
      this.initialized = true;
      this.unhealthy = false;
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Phase 3 checkpoint initialization failed");
    }
  }

  async create(
    path: string,
    bytes: Uint8Array,
    expectedSha256: string,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ checkpointId: string; checkpointSha256: string }>> {
    this.assertHealthy();
    await this.refresh();
    assertActive(context);
    const canonicalPath = this.validatedPath(path);
    if (!sha256Schema.safeParse(expectedSha256).success)
      throw illegal("Phase 3 checkpoint expected digest is invalid");
    if (bytes.byteLength > PHASE3_CHECKPOINT_LIMITS.contentBytes)
      throw illegal("Phase 3 checkpoint content exceeds size limit");
    const contentSha256 = sha256(bytes);
    if (contentSha256 !== expectedSha256)
      throw illegal("Phase 3 checkpoint content digest mismatch");
    await this.assertCapacity();

    const record = checkpointEnvelope(
      randomUUID(),
      canonicalPath,
      expectedSha256,
      bytes,
    );
    const recordBytes = Buffer.from(canonicalJson(record), "utf8");
    try {
      if (recordBytes.byteLength > PHASE3_CHECKPOINT_LIMITS.recordBytes)
        throw unhealthy("Phase 3 checkpoint record exceeds size limit");
      if (
        this.aggregateBytes + recordBytes.byteLength >
        PHASE3_CHECKPOINT_LIMITS.aggregateBytes
      )
        throw unhealthy("Phase 3 checkpoint aggregate byte limit exceeded");
      await this.append(record, recordBytes, context);
      try {
        this.replaceScanned(await this.scan());
      } catch {
        this.unhealthy = true;
        throw new Phase3CheckpointError(
          "checkpoint_commit_unknown",
          "Phase 3 checkpoint committed but final state confirmation failed",
        );
      }
      return Object.freeze({
        checkpointId: record.checkpointId,
        checkpointSha256: contentSha256,
      });
    } finally {
      recordBytes.fill(0);
    }
  }

  async load(checkpointId: string): Promise<Uint8Array> {
    this.assertHealthy();
    await this.refresh();
    if (!lowercaseUuid.test(checkpointId))
      throw new Phase3CheckpointError(
        "checkpoint_missing",
        "Phase 3 checkpoint is missing",
      );
    const scannedIdentity = this.checkpointIdentities.get(checkpointId);
    if (!scannedIdentity)
      throw new Phase3CheckpointError(
        "checkpoint_missing",
        "Phase 3 checkpoint is missing",
      );
    const path = this.finalPath(checkpointId);
    try {
      const metadata = await this.assertFile(path, true);
      if (!sameIdentity(scannedIdentity, metadata, this.durability))
        throw unhealthy("Phase 3 checkpoint identity changed after refresh");
      if (metadata.size > BigInt(PHASE3_CHECKPOINT_LIMITS.recordBytes))
        throw unhealthy("Phase 3 checkpoint record exceeds size limit");
      const { record, content } = await this.readRecord(path, metadata);
      try {
        if (record.checkpointId !== checkpointId)
          throw unhealthy("Phase 3 checkpoint filename identity mismatch");
        return Buffer.from(content);
      } finally {
        content.fill(0);
      }
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Phase 3 checkpoint load failed");
    }
  }

  private async append(
    record: Phase3CheckpointRecord,
    recordBytes: Uint8Array,
    context: Phase3OperationContext,
  ): Promise<void> {
    const finalPath = this.finalPath(record.checkpointId);
    await this.assertFinalAbsent(finalPath);
    assertActive(context);
    const pendingPath = await this.reservePendingDirectory();
    const recordPath = join(pendingPath, "record.json");
    let opened: BigIntStats | undefined;
    let linked = false;
    try {
      assertActive(context);
      const handle = await this.filesystem.open(
        recordPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      try {
        await writeAll(handle, recordBytes, context);
        await handle.sync();
        opened = await handle.stat({ bigint: true });
        await this.afterStage(
          "file_synced",
          pendingPath,
          finalPath,
          recordPath,
          record,
        );
      } finally {
        await handle.close();
      }
      assertActive(context);
      await this.afterStage(
        "file_closed",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      await this.durability.syncDirectory(pendingPath);
      assertActive(context);
      await this.afterStage(
        "entry_synced",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      if (!opened)
        throw unhealthy("Phase 3 checkpoint record identity is absent");
      await this.assertRecordIdentity(recordPath, opened, recordBytes);
      assertActive(context);
      await this.afterStage(
        "pre_link",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      assertActive(context);
      await this.assertFinalAbsent(finalPath);
      await this.filesystem.link(recordPath, finalPath);
      linked = true;
      await this.afterStage(
        "post_link",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      await this.durability.syncDirectory(this.root);
      await this.afterStage(
        "parent_synced",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      await this.removeOwnPending(pendingPath);
      await this.durability.syncDirectory(this.root);
    } catch (error) {
      if (linked)
        throw new Phase3CheckpointError(
          "checkpoint_commit_unknown",
          "Phase 3 checkpoint link commit point was crossed but durability confirmation failed",
        );
      if (retainPending(error)) throw error;
      try {
        await this.removeOwnPending(pendingPath);
        await this.durability.syncDirectory(this.root);
      } catch (cleanupError) {
        throw normalize(
          cleanupError,
          "Phase 3 checkpoint pending cleanup failed",
        );
      }
      if (error instanceof Phase3CheckpointError) throw error;
      if (await this.finalPathExists(finalPath))
        await this.classifyFinalConflict(finalPath);
      throw normalize(error, "Phase 3 checkpoint append failed");
    }
  }

  private async refresh(): Promise<void> {
    try {
      this.replaceScanned(await this.scan());
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Phase 3 checkpoint refresh failed");
    }
  }

  private async scan(): Promise<{
    readonly checkpointIdentities: Map<string, BigIntStats>;
    readonly aggregateBytes: number;
  }> {
    const names = (await this.filesystem.readdir(this.root)).sort();
    if (names.length > PHASE3_CHECKPOINT_LIMITS.scanEntries)
      throw unhealthy("Phase 3 checkpoint scan limit exceeded");

    const pendingNames = names.filter((name) => pendingNamePattern.test(name));
    if (pendingNames.length > PHASE3_CHECKPOINT_LIMITS.pendingEntries)
      throw unhealthy("Phase 3 checkpoint pending entry limit exceeded");
    const pendingRecords: BigIntStats[] = [];
    for (const name of pendingNames) {
      const metadata = await this.validatePending(join(this.root, name));
      if (metadata) pendingRecords.push(metadata);
    }

    const checkpointIdentities = new Map<string, BigIntStats>();
    let aggregateBytes = 0;
    for (const name of names) {
      if (pendingNamePattern.test(name)) continue;
      if (!lowercaseUuid.test(name))
        throw unhealthy("Phase 3 checkpoint contains unknown artifact");
      if (checkpointIdentities.size >= PHASE3_CHECKPOINT_LIMITS.checkpoints)
        throw unhealthy("Phase 3 checkpoint count limit exceeded");
      const { record, bytes, content, metadata } = await this.readFinal(
        join(this.root, name),
        pendingRecords,
      );
      try {
        aggregateBytes += bytes;
        if (aggregateBytes > PHASE3_CHECKPOINT_LIMITS.aggregateBytes)
          throw unhealthy("Phase 3 checkpoint aggregate byte limit exceeded");
        if (record.checkpointId !== name)
          throw unhealthy("Phase 3 checkpoint filename identity mismatch");
        checkpointIdentities.set(record.checkpointId, metadata);
      } finally {
        content.fill(0);
      }
    }
    return { checkpointIdentities, aggregateBytes };
  }

  private replaceScanned(scanned: {
    readonly checkpointIdentities: Map<string, BigIntStats>;
    readonly aggregateBytes: number;
  }): void {
    this.checkpointIdentities = scanned.checkpointIdentities;
    this.aggregateBytes = scanned.aggregateBytes;
  }

  private async readFinal(
    path: string,
    pendingRecords: readonly BigIntStats[],
  ): Promise<{
    readonly record: Phase3CheckpointRecord;
    readonly bytes: number;
    readonly content: Buffer;
    readonly metadata: BigIntStats;
  }> {
    const metadata = await this.assertFile(path, true);
    if (metadata.nlink === 2n) {
      const matches = pendingRecords.filter(
        (pending) =>
          pending.dev === metadata.dev && pending.ino === metadata.ino,
      );
      if (matches.length !== 1)
        throw unhealthy("Phase 3 checkpoint final hard link is unsafe");
    }
    if (metadata.size > BigInt(PHASE3_CHECKPOINT_LIMITS.recordBytes))
      throw unhealthy("Phase 3 checkpoint record exceeds size limit");
    return {
      ...(await this.readRecord(path, metadata)),
      bytes: Number(metadata.size),
      metadata,
    };
  }

  private async validatePending(path: string): Promise<BigIntStats | null> {
    try {
      await this.assertDirectory(path);
      const children = (await this.filesystem.readdir(path)).sort();
      if (children.length === 0) return null;
      if (children.length !== 1 || children[0] !== "record.json")
        throw unhealthy("Phase 3 checkpoint pending entry is malformed");
      const metadata = await this.assertFile(join(path, "record.json"), true);
      if (metadata.size > BigInt(PHASE3_CHECKPOINT_LIMITS.recordBytes))
        throw unhealthy("Phase 3 checkpoint pending record exceeds size limit");
      return metadata;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  private async readRecord(
    path: string,
    before: BigIntStats,
  ): Promise<{
    readonly record: Phase3CheckpointRecord;
    readonly content: Buffer;
  }> {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    const handle = await this.filesystem.open(path, flags);
    let bytes: Buffer | undefined;
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameIdentity(before, opened, this.durability))
        throw unhealthy("Phase 3 checkpoint record identity changed");
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const linked = await this.filesystem.lstat(path, { bigint: true });
      if (
        !sameIdentity(opened, after, this.durability) ||
        !sameIdentity(opened, linked, this.durability)
      )
        throw unhealthy("Phase 3 checkpoint record identity changed");
      return parseEnvelope(bytes);
    } finally {
      bytes?.fill(0);
      await handle.close();
    }
  }

  private async assertRecordIdentity(
    path: string,
    opened: BigIntStats,
    expectedBytes: Uint8Array,
  ): Promise<void> {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    const handle = await this.filesystem.open(path, flags);
    let bytes: Buffer | undefined;
    try {
      const before = await handle.stat({ bigint: true });
      if (!sameIdentity(opened, before, this.durability))
        throw unhealthy(
          "Phase 3 checkpoint record identity changed after close",
        );
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const linked = await this.filesystem.lstat(path, { bigint: true });
      if (
        !sameIdentity(before, after, this.durability) ||
        !sameIdentity(before, linked, this.durability)
      )
        throw unhealthy(
          "Phase 3 checkpoint record identity changed after close",
        );
      if (bytes.byteLength !== expectedBytes.byteLength)
        throw unhealthy("Phase 3 checkpoint record size changed after close");
      if (Buffer.compare(bytes, expectedBytes) !== 0)
        throw unhealthy("Phase 3 checkpoint record changed after close");
    } finally {
      bytes?.fill(0);
      await handle.close();
    }
  }

  private async assertFinalAbsent(path: string): Promise<void> {
    if (!(await this.finalPathExists(path))) return;
    await this.classifyFinalConflict(path);
  }

  private async finalPathExists(path: string): Promise<boolean> {
    try {
      await this.filesystem.lstat(path, { bigint: true });
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  private async classifyFinalConflict(path: string): Promise<never> {
    await this.refresh();
    const checkpointId = basename(path);
    if (
      lowercaseUuid.test(checkpointId) &&
      this.checkpointIdentities.has(checkpointId)
    )
      throw new Phase3CheckpointError(
        "checkpoint_conflict",
        "Phase 3 checkpoint already exists",
      );
    throw unhealthy("Phase 3 checkpoint final entry is unsafe");
  }

  private async assertCapacity(): Promise<void> {
    if (this.checkpointIdentities.size >= PHASE3_CHECKPOINT_LIMITS.checkpoints)
      throw unhealthy("Phase 3 checkpoint count limit exceeded");
    const pendingEntries = (await this.filesystem.readdir(this.root)).filter(
      (name) => pendingNamePattern.test(name),
    ).length;
    if (pendingEntries >= PHASE3_CHECKPOINT_LIMITS.pendingEntries)
      throw unhealthy("Phase 3 checkpoint pending entry limit exceeded");
  }

  private async reservePendingDirectory(): Promise<string> {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const path = join(this.root, `.pending-${randomUUID()}`);
      try {
        await this.filesystem.mkdir(path, { mode: 0o700 });
        return path;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    }
    throw unhealthy("Phase 3 checkpoint pending reservation failed");
  }

  private async ensureRoot(): Promise<void> {
    if (!isAbsolute(this.root) || resolve(this.root) !== this.root)
      throw unhealthy(
        "Phase 3 checkpoint root must be absolute and normalized",
      );
    const parsed = parse(this.root);
    let current = parsed.root;
    for (const segment of this.root
      .slice(parsed.root.length)
      .split(/[\\/]/u)
      .filter(Boolean)) {
      current = join(current, segment);
      try {
        const metadata = await this.filesystem.lstat(current, { bigint: true });
        if (!metadata.isDirectory())
          throw unhealthy("Phase 3 checkpoint root traverses a non-directory");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        try {
          await this.filesystem.mkdir(current, { mode: 0o700 });
        } catch (mkdirError) {
          if ((mkdirError as NodeJS.ErrnoException).code !== "EEXIST")
            throw mkdirError;
          const metadata = await this.filesystem.lstat(current, {
            bigint: true,
          });
          if (!metadata.isDirectory())
            throw unhealthy(
              "Phase 3 checkpoint root traverses a non-directory",
            );
        }
      }
    }
    await this.assertDirectory(this.root);
  }

  private async assertDirectory(path: string): Promise<BigIntStats> {
    const metadata = await this.filesystem.lstat(path, { bigint: true });
    if (
      !metadata.isDirectory() ||
      metadata.nlink < 1n ||
      !this.durability.privateMode(metadata.mode) ||
      !privateOwner(metadata)
    )
      throw unhealthy("Phase 3 checkpoint directory is unsafe");
    return metadata;
  }

  private async assertFile(
    path: string,
    allowLinked = false,
  ): Promise<BigIntStats> {
    const metadata = await this.filesystem.lstat(path, { bigint: true });
    if (
      !metadata.isFile() ||
      (metadata.nlink !== 1n && (!allowLinked || metadata.nlink !== 2n)) ||
      !this.durability.privateMode(metadata.mode) ||
      !privateOwner(metadata)
    )
      throw unhealthy("Phase 3 checkpoint record file is unsafe");
    return metadata;
  }

  private finalPath(checkpointId: string): string {
    return join(this.root, checkpointId);
  }

  private validatedPath(path: string): string {
    try {
      return canonicalPhase3Path(path);
    } catch {
      throw illegal("Phase 3 checkpoint path is invalid");
    }
  }

  private async afterStage(
    stage: Phase3CheckpointHookStage,
    pendingPath: string,
    finalPath: string,
    recordPath: string,
    record: Phase3CheckpointRecord,
  ): Promise<void> {
    await this.hooks.afterStage?.({
      stage,
      root: this.root,
      pendingPath,
      finalPath,
      recordPath,
      record,
    });
  }

  private async removeOwnPending(path: string): Promise<void> {
    if (basename(path).startsWith(".pending-"))
      await this.filesystem.rm(path, { recursive: true, force: true });
  }

  private assertHealthy(): void {
    if (!this.initialized || this.unhealthy)
      throw new Phase3CheckpointError(
        "checkpoint_unhealthy",
        "Phase 3 checkpoint store is unhealthy",
      );
  }
}

function checkpointEnvelope(
  nonce: string,
  path: string,
  expectedSha256: string,
  bytes: Uint8Array,
): Phase3CheckpointRecord {
  if (!lowercaseUuid.test(nonce))
    throw unhealthy("Phase 3 checkpoint nonce identity is not canonical");
  let contentBase64: string;
  const contentCopy = Buffer.from(bytes);
  try {
    contentBase64 = contentCopy.toString("base64");
  } finally {
    contentCopy.fill(0);
  }
  const identity = {
    schemaVersion: 1 as const,
    nonce,
    path,
    expectedSha256,
    sourceSha256: expectedSha256,
    contentSha256: sha256(bytes),
    contentBase64,
  };
  const checkpointId = uuidFromDigest(sha256(canonicalJson(identity)));
  const core = {
    ...identity,
    checkpointId,
  };
  return Object.freeze({
    ...core,
    storageSha256: sha256(canonicalJson(core)),
  });
}

function parseEnvelope(bytes: Uint8Array): {
  readonly record: Phase3CheckpointRecord;
  readonly content: Buffer;
} {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw unhealthy("Phase 3 checkpoint record is malformed");
  }
  const parsed = checkpointRecordSchema.safeParse(value);
  if (!parsed.success || canonicalJson(parsed.data) !== text)
    throw unhealthy("Phase 3 checkpoint record is non-canonical");
  const { storageSha256, ...core } = parsed.data;
  if (sha256(canonicalJson(core)) !== storageSha256)
    throw unhealthy("Phase 3 checkpoint storage digest mismatch");
  const identity = {
    schemaVersion: parsed.data.schemaVersion,
    nonce: parsed.data.nonce,
    path: parsed.data.path,
    expectedSha256: parsed.data.expectedSha256,
    sourceSha256: parsed.data.sourceSha256,
    contentSha256: parsed.data.contentSha256,
    contentBase64: parsed.data.contentBase64,
  };
  if (
    uuidFromDigest(sha256(canonicalJson(identity))) !== parsed.data.checkpointId
  )
    throw unhealthy("Phase 3 checkpoint UUID binding mismatch");
  let canonicalPath: string;
  try {
    canonicalPath = canonicalPhase3Path(parsed.data.path);
  } catch {
    throw unhealthy("Phase 3 checkpoint path is invalid");
  }
  if (canonicalPath !== parsed.data.path)
    throw unhealthy("Phase 3 checkpoint path is non-canonical");
  const content = Buffer.from(parsed.data.contentBase64, "base64");
  try {
    if (content.byteLength > PHASE3_CHECKPOINT_LIMITS.contentBytes)
      throw unhealthy("Phase 3 checkpoint content exceeds size limit");
    if (sha256(content) !== parsed.data.contentSha256)
      throw unhealthy("Phase 3 checkpoint content digest mismatch");
    if (
      parsed.data.contentSha256 !== parsed.data.sourceSha256 ||
      parsed.data.sourceSha256 !== parsed.data.expectedSha256
    )
      throw unhealthy("Phase 3 checkpoint source digest mismatch");
    return {
      record: Object.freeze(parsed.data),
      content,
    };
  } catch (error) {
    content.fill(0);
    throw error;
  }
}

async function writeAll(
  handle: Phase3CheckpointFileHandle,
  bytes: Uint8Array,
  context: Phase3OperationContext,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    assertActive(context);
    try {
      const remaining = bytes.subarray(offset);
      const { bytesWritten } = await handle.write(
        remaining,
        0,
        remaining.byteLength,
        offset,
      );
      if (
        !Number.isSafeInteger(bytesWritten) ||
        bytesWritten <= 0 ||
        bytesWritten > bytes.byteLength - offset
      )
        throw unhealthy("Phase 3 checkpoint write did not make progress");
      offset += bytesWritten;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}

function assertActive(context: Phase3OperationContext): void {
  if (context.signal.aborted)
    throw new Phase3CheckpointError(
      "checkpoint_illegal",
      "Phase 3 checkpoint operation was cancelled before commit",
    );
  if (Date.now() >= context.deadlineAt)
    throw new Phase3CheckpointError(
      "checkpoint_illegal",
      "Phase 3 checkpoint deadline expired before commit",
    );
}

function privateOwner(metadata: { readonly uid: bigint }): boolean {
  const uid =
    typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;
  return uid === undefined || metadata.uid === uid;
}

function sameIdentity(
  left: BigIntStats,
  right: BigIntStats,
  durability: Phase2DurabilityPort,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    right.isFile() &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    (left.ctimeNs === right.ctimeNs ||
      (left.nlink === 2n && right.nlink === 1n)) &&
    (left.nlink === right.nlink || (left.nlink === 2n && right.nlink === 1n)) &&
    (right.nlink === 1n || right.nlink === 2n) &&
    durability.privateMode(right.mode) &&
    privateOwner(right)
  );
}

function isEintr(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === "EINTR"
  );
}

function retainPending(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "retainPhase3Pending" in error &&
    (error as { readonly retainPhase3Pending?: unknown })
      .retainPhase3Pending === true
  );
}

function illegal(message: string): Phase3CheckpointError {
  return new Phase3CheckpointError("checkpoint_illegal", message);
}

function unhealthy(message: string): Phase3CheckpointError {
  return new Phase3CheckpointError("checkpoint_unhealthy", message);
}

function normalize(error: unknown, message: string): Phase3CheckpointError {
  return error instanceof Phase3CheckpointError ? error : unhealthy(message);
}

function uuidFromDigest(hex: string): string {
  const bytes = Buffer.from(hex.slice(0, 32), "hex");
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const text = bytes.toString("hex");
  bytes.fill(0);
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(
    12,
    16,
  )}-${text.slice(16, 20)}-${text.slice(20, 32)}`;
}
