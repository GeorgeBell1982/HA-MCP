import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { basename, isAbsolute, join, parse, resolve } from "node:path";
import { z } from "zod";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "../proposals/durability.js";
import {
  assertPhase3TransactionRecord,
  canonicalJson,
  phase3CanRecordTransition,
  phase3CanTransition,
  phase3TransactionRecordSchema,
  sha256,
  sha256Schema,
  type Phase3JournalPort,
  type Phase3StructuredFailure,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "./contracts.js";

export const PHASE3_JOURNAL_LIMITS = Object.freeze({
  transactions: 64,
  finalEntries: 512,
  pendingEntries: 64,
  historyPerTransaction: 128,
  recordBytes: 64 * 1024,
  aggregateBytes: 32 * 1024 * 1024,
  scanEntries: 1024,
  versionWidth: 12,
});

export type Phase3JournalHookStage =
  | "file_synced"
  | "file_closed"
  | "entry_synced"
  | "pre_link"
  | "post_link"
  | "parent_synced";

export type Phase3JournalErrorCode =
  | "journal_unhealthy"
  | "journal_missing"
  | "journal_conflict"
  | "journal_cas_conflict"
  | "journal_illegal"
  | "journal_commit_unknown";

export class Phase3JournalError extends Error {
  constructor(
    public readonly code: Phase3JournalErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Phase3JournalError";
  }
}

export class Phase3JournalSimulatedCrash extends Error {
  readonly retainPhase3Pending = true;

  constructor(
    public readonly stage: Phase3JournalHookStage,
    message = `Simulated Phase 3 journal crash at ${stage}`,
  ) {
    super(message);
    this.name = "Phase3JournalSimulatedCrash";
  }
}

export interface Phase3JournalHookContext {
  readonly stage: Phase3JournalHookStage;
  readonly root: string;
  readonly pendingPath: string;
  readonly finalPath: string;
  readonly recordPath: string;
  readonly record: Phase3TransactionRecord;
}

export interface Phase3JournalHooks {
  readonly afterStage?: (context: Phase3JournalHookContext) => Promise<void>;
}

export interface Phase3JournalFileHandle {
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

export interface Phase3JournalFilesystem {
  readonly lstat: typeof lstat;
  readonly mkdir: typeof mkdir;
  readonly open: (
    path: string,
    flags: number,
    mode?: number,
  ) => Promise<Phase3JournalFileHandle>;
  readonly readFile: typeof readFile;
  readonly readdir: typeof readdir;
  readonly link: typeof link;
  readonly rm: typeof rm;
}

export interface DurablePhase3JournalOptions {
  readonly durability?: Phase2DurabilityPort;
  readonly filesystem?: Phase3JournalFilesystem;
  readonly hooks?: Phase3JournalHooks;
  readonly now?: () => number;
}

const lowercaseUuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const finalNamePattern =
  /^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([0-9]{12})\.entry$/u;
const pendingNamePattern =
  /^\.pending-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const envelopeSchema = z
  .object({
    schemaVersion: z.literal(2),
    record: phase3TransactionRecordSchema,
    recordSha256: sha256Schema,
  })
  .strict();

type Phase3JournalEnvelope = z.infer<typeof envelopeSchema>;

const defaultFilesystem: Phase3JournalFilesystem = Object.freeze({
  link,
  lstat,
  mkdir,
  open: async (path: string, flags: number, mode?: number) =>
    await open(path, flags, mode),
  readFile,
  readdir,
  rm,
});

export class DurablePhase3Journal implements Phase3JournalPort {
  private readonly durability: Phase2DurabilityPort;
  private readonly filesystem: Phase3JournalFilesystem;
  private readonly hooks: Phase3JournalHooks;
  private readonly now: () => number;
  private unhealthy = true;
  private initialized = false;
  private readonly nativeDurability: boolean;
  private latest = new Map<string, Phase3TransactionRecord>();
  private histories = new Map<string, readonly Phase3TransactionRecord[]>();

  constructor(
    private readonly root: string,
    options: DurablePhase3JournalOptions = {},
  ) {
    this.nativeDurability = options.durability === undefined;
    this.durability = options.durability ?? strictPhase2Durability;
    this.filesystem = options.filesystem ?? defaultFilesystem;
    this.hooks = options.hooks ?? {};
    this.now = options.now ?? Date.now;
  }

  async initialize(): Promise<void> {
    this.unhealthy = true;
    try {
      if (this.nativeDurability && process.platform !== "linux")
        throw unhealthy("Native Phase 3 journal durability requires Linux");
      await this.ensureRoot();
      const { histories, latest } = await this.scan();
      this.histories = histories;
      this.latest = latest;
      this.initialized = true;
      this.unhealthy = false;
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Phase 3 journal initialization failed");
    }
  }

  async createIntent(
    record: Phase3TransactionRecord,
  ): Promise<Phase3TransactionRecord> {
    this.assertHealthy();
    await this.refresh();
    const parsedResult = phase3TransactionRecordSchema.safeParse(record);
    if (!parsedResult.success)
      throw illegal("Phase 3 journal intent record is invalid");
    const parsed = parsedResult.data;
    if (
      parsed.state !== "intent_prepared" ||
      parsed.version !== 0 ||
      parsed.priorState !== null ||
      parsed.failure !== null ||
      parsed.rollbackReloadRequired !== false ||
      parsed.createdAt !== parsed.updatedAt
    )
      throw illegal("Phase 3 journal intent must start at version 0");
    if (!canonicalRecordIdentity(parsed))
      throw illegal("Phase 3 journal UUID identity is not canonical");
    await this.assertCapacity(true);
    if (this.latest.has(parsed.transactionId))
      throw new Phase3JournalError(
        "journal_conflict",
        "Phase 3 transaction already exists",
      );
    await this.append(parsed, "journal_conflict");
    this.cache(parsed);
    return freezeRecord(parsed);
  }

  async transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch: Readonly<{
      failure?: Phase3StructuredFailure | null;
      rollbackReloadRequired?: boolean;
    }> = {},
  ): Promise<Phase3TransactionRecord> {
    this.assertHealthy();
    await this.refresh();
    if (!lowercaseUuid.test(transactionId))
      throw new Phase3JournalError(
        "journal_missing",
        "Phase 3 transaction is missing",
      );
    const current = this.latest.get(transactionId);
    if (!current)
      throw new Phase3JournalError(
        "journal_missing",
        "Phase 3 transaction is missing",
      );
    if (current.version !== expectedVersion)
      throw new Phase3JournalError(
        "journal_cas_conflict",
        "Phase 3 transaction version changed",
      );
    if (!phase3CanTransition(current.state, state))
      throw illegal("Phase 3 journal transition is illegal");
    if (
      Object.hasOwn(patch, "rollbackReloadRequired") &&
      (patch.rollbackReloadRequired !== true || state !== "rollback_intent")
    )
      throw illegal("Phase 3 rollback reload flag transition is illegal");
    await this.assertCapacity(false);
    const nextResult = phase3TransactionRecordSchema.safeParse({
      ...current,
      state,
      priorState: current.state,
      version: current.version + 1,
      updatedAt: new Date(this.now()).toISOString(),
      failure: Object.hasOwn(patch, "failure")
        ? (patch.failure ?? null)
        : current.failure,
      rollbackReloadRequired:
        current.rollbackReloadRequired || patch.rollbackReloadRequired === true,
    });
    if (!nextResult.success)
      throw illegal("Phase 3 journal transition record is invalid");
    const next = nextResult.data;
    if (!phase3CanRecordTransition(current, next))
      throw illegal("Phase 3 journal transition context is illegal");
    await this.append(next, "journal_cas_conflict");
    this.cache(next);
    return freezeRecord(next);
  }

  async load(transactionId: string): Promise<Phase3TransactionRecord | null> {
    this.assertHealthy();
    await this.refresh();
    return this.latest.get(transactionId) ?? null;
  }

  async listRecoverable(): Promise<readonly Phase3TransactionRecord[]> {
    this.assertHealthy();
    await this.refresh();
    return Object.freeze(
      [...this.latest.values()]
        .sort((left, right) =>
          left.transactionId.localeCompare(right.transactionId),
        )
        .map(freezeRecord),
    );
  }

  private async append(
    record: Phase3TransactionRecord,
    conflictCode: "journal_conflict" | "journal_cas_conflict",
  ): Promise<void> {
    const finalPath = this.finalPath(record.transactionId, record.version);
    const pendingPath = await this.reservePendingDirectory();
    const recordPath = join(pendingPath, "record.json");
    const envelope = journalEnvelope(record);
    const bytes = Buffer.from(canonicalJson(envelope), "utf8");
    let opened: BigIntStats | undefined;
    let linked = false;
    try {
      if (bytes.byteLength > PHASE3_JOURNAL_LIMITS.recordBytes)
        throw unhealthy("Phase 3 journal record exceeds size limit");
      await this.assertFinalAbsent(finalPath, conflictCode);
      const handle = await this.filesystem.open(
        recordPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      try {
        await writeAll(handle, bytes);
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
      await this.afterStage(
        "file_closed",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      await this.durability.syncDirectory(pendingPath);
      await this.afterStage(
        "entry_synced",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      if (!opened) throw unhealthy("Phase 3 journal record identity is absent");
      await this.assertRecordIdentity(recordPath, opened, bytes);
      await this.afterStage(
        "pre_link",
        pendingPath,
        finalPath,
        recordPath,
        record,
      );
      await this.assertFinalAbsent(finalPath, conflictCode);
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
      if (linked) {
        throw new Phase3JournalError(
          "journal_commit_unknown",
          "Phase 3 journal link commit point was crossed but durability confirmation failed",
        );
      }
      if (retainPending(error)) throw error;
      await this.removeOwnPending(pendingPath);
      if (error instanceof Phase3JournalError) throw error;
      if (await this.finalPathExists(finalPath))
        await this.classifyFinalConflict(finalPath, conflictCode);
      throw normalize(error, "Phase 3 journal append failed");
    } finally {
      bytes.fill(0);
    }
  }

  private async refresh(): Promise<void> {
    try {
      const { histories, latest } = await this.scan();
      this.histories = histories;
      this.latest = latest;
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Phase 3 journal refresh failed");
    }
  }

  private async scan(): Promise<{
    readonly histories: Map<string, readonly Phase3TransactionRecord[]>;
    readonly latest: Map<string, Phase3TransactionRecord>;
  }> {
    const names = (await this.filesystem.readdir(this.root)).sort();
    if (names.length > PHASE3_JOURNAL_LIMITS.scanEntries)
      throw unhealthy("Phase 3 journal scan limit exceeded");

    const pendingNames = names.filter((name) => pendingNamePattern.test(name));
    if (pendingNames.length > PHASE3_JOURNAL_LIMITS.pendingEntries)
      throw unhealthy("Phase 3 journal pending entry limit exceeded");
    const pendingRecords: BigIntStats[] = [];
    for (const name of pendingNames) {
      const metadata = await this.validatePending(join(this.root, name));
      if (metadata) pendingRecords.push(metadata);
    }

    const finals: Phase3TransactionRecord[] = [];
    let aggregateBytes = 0;
    for (const name of names) {
      if (pendingNamePattern.test(name)) continue;
      const match = finalNamePattern.exec(name);
      if (!match) throw unhealthy("Phase 3 journal contains unknown artifact");
      if (finals.length >= PHASE3_JOURNAL_LIMITS.finalEntries)
        throw unhealthy("Phase 3 journal final entry limit exceeded");
      const { record, bytes } = await this.readFinal(
        join(this.root, name),
        pendingRecords,
      );
      aggregateBytes += bytes;
      if (aggregateBytes > PHASE3_JOURNAL_LIMITS.aggregateBytes)
        throw unhealthy("Phase 3 journal aggregate byte limit exceeded");
      const [, transactionId, versionText] = match;
      if (
        !transactionId ||
        !versionText ||
        record.transactionId !== transactionId ||
        record.version !== Number(versionText)
      )
        throw unhealthy("Phase 3 journal history fork detected");
      finals.push(record);
    }
    return this.buildHistories(finals);
  }

  private async readFinal(
    path: string,
    pendingRecords: readonly BigIntStats[],
  ): Promise<{
    readonly record: Phase3TransactionRecord;
    readonly bytes: number;
  }> {
    const metadata = await this.assertFile(path, true);
    if (metadata.nlink === 2n) {
      const matches = pendingRecords.filter(
        (pending) =>
          pending.dev === metadata.dev && pending.ino === metadata.ino,
      );
      if (matches.length !== 1)
        throw unhealthy("Phase 3 journal final hard link is unsafe");
    }
    if (metadata.size > BigInt(PHASE3_JOURNAL_LIMITS.recordBytes))
      throw unhealthy("Phase 3 journal record exceeds size limit");
    return {
      record: await this.readRecord(path, metadata),
      bytes: Number(metadata.size),
    };
  }

  private async validatePending(path: string): Promise<BigIntStats | null> {
    try {
      await this.assertDirectory(path);
      const children = (await this.filesystem.readdir(path)).sort();
      if (children.length === 0) return null;
      if (children.length !== 1 || children[0] !== "record.json")
        throw unhealthy("Phase 3 journal pending entry is malformed");
      const metadata = await this.assertFile(join(path, "record.json"), true);
      if (metadata.size > BigInt(PHASE3_JOURNAL_LIMITS.recordBytes))
        throw unhealthy("Phase 3 journal pending record exceeds size limit");
      return metadata;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  private buildHistories(finals: readonly Phase3TransactionRecord[]): {
    readonly histories: Map<string, readonly Phase3TransactionRecord[]>;
    readonly latest: Map<string, Phase3TransactionRecord>;
  } {
    const mutable = new Map<string, Phase3TransactionRecord[]>();
    for (const record of finals) {
      this.assertLowercaseIdentity(record);
      const records = mutable.get(record.transactionId) ?? [];
      records.push(record);
      mutable.set(record.transactionId, records);
    }
    if (mutable.size > PHASE3_JOURNAL_LIMITS.transactions)
      throw unhealthy("Phase 3 journal transaction limit exceeded");
    const histories = new Map<string, readonly Phase3TransactionRecord[]>();
    const latest = new Map<string, Phase3TransactionRecord>();
    for (const [transactionId, records] of mutable) {
      records.sort((left, right) => left.version - right.version);
      if (records.length > PHASE3_JOURNAL_LIMITS.historyPerTransaction)
        throw unhealthy("Phase 3 journal history limit exceeded");
      for (let index = 0; index < records.length; index += 1) {
        const record = records[index];
        if (!record || record.version !== index)
          throw unhealthy("Phase 3 journal history has a version gap");
        if (index === 0) this.assertInitial(record);
        else {
          const previous = records[index - 1];
          if (!previous)
            throw unhealthy("Phase 3 journal history is malformed");
          this.assertSuccessor(previous, record);
        }
      }
      histories.set(transactionId, Object.freeze(records.map(freezeRecord)));
      const last = records.at(-1);
      if (!last) throw unhealthy("Phase 3 journal history is empty");
      latest.set(transactionId, freezeRecord(last));
    }
    return { histories, latest };
  }

  private assertInitial(record: Phase3TransactionRecord): void {
    if (
      record.state !== "intent_prepared" ||
      record.version !== 0 ||
      record.priorState !== null ||
      record.failure !== null ||
      record.rollbackReloadRequired !== false ||
      record.createdAt !== record.updatedAt
    )
      throw unhealthy("Phase 3 journal initial record is illegal");
  }

  private assertSuccessor(
    previous: Phase3TransactionRecord,
    record: Phase3TransactionRecord,
  ): void {
    if (
      previous.transactionId !== record.transactionId ||
      previous.proposalId !== record.proposalId ||
      previous.proposalStorageSha256 !== record.proposalStorageSha256 ||
      previous.path !== record.path ||
      previous.expectedSha256 !== record.expectedSha256 ||
      previous.candidateSha256 !== record.candidateSha256 ||
      previous.diffSha256 !== record.diffSha256 ||
      previous.checkpointId !== record.checkpointId ||
      previous.checkpointSha256 !== record.checkpointSha256 ||
      previous.impact !== record.impact ||
      previous.reloadTarget !== record.reloadTarget ||
      previous.createdAt !== record.createdAt
    )
      throw unhealthy("Phase 3 journal immutable identity changed");
    if (
      record.rollbackReloadRequired !== previous.rollbackReloadRequired &&
      !(
        previous.rollbackReloadRequired === false &&
        record.rollbackReloadRequired === true &&
        record.state === "rollback_intent"
      )
    )
      throw unhealthy(
        "Phase 3 journal rollback reload flag regressed or changed illegally",
      );
    if (
      record.version !== previous.version + 1 ||
      record.priorState !== previous.state ||
      !phase3CanRecordTransition(previous, record)
    )
      throw unhealthy("Phase 3 journal history adjacency is illegal");
  }

  private cache(record: Phase3TransactionRecord): void {
    const current = this.histories.get(record.transactionId) ?? [];
    const next = Object.freeze([...current, freezeRecord(record)]);
    this.histories.set(record.transactionId, next);
    this.latest.set(record.transactionId, freezeRecord(record));
  }

  private async readRecord(
    path: string,
    before: BigIntStats,
  ): Promise<Phase3TransactionRecord> {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    const handle = await this.filesystem.open(path, flags);
    let bytes: Buffer | undefined;
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameIdentity(before, opened, this.durability))
        throw unhealthy("Phase 3 journal record identity changed");
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const linked = await this.filesystem.lstat(path, { bigint: true });
      if (
        !sameIdentity(opened, after, this.durability) ||
        !sameIdentity(opened, linked, this.durability)
      )
        throw unhealthy("Phase 3 journal record identity changed");
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
        throw unhealthy("Phase 3 journal record identity changed after close");
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const linked = await this.filesystem.lstat(path, { bigint: true });
      if (
        !sameIdentity(before, after, this.durability) ||
        !sameIdentity(before, linked, this.durability)
      )
        throw unhealthy("Phase 3 journal record identity changed after close");
      if (bytes.byteLength !== expectedBytes.byteLength)
        throw unhealthy("Phase 3 journal record size changed after close");
      if (Buffer.compare(bytes, expectedBytes) !== 0)
        throw unhealthy("Phase 3 journal record changed after close");
    } finally {
      bytes?.fill(0);
      await handle.close();
    }
  }

  private async assertFinalAbsent(
    path: string,
    conflictCode: "journal_conflict" | "journal_cas_conflict",
  ): Promise<void> {
    if (!(await this.finalPathExists(path))) return;
    await this.classifyFinalConflict(path, conflictCode);
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

  private async classifyFinalConflict(
    path: string,
    conflictCode: "journal_conflict" | "journal_cas_conflict",
  ): Promise<void> {
    await this.refresh();
    const match = finalNamePattern.exec(basename(path));
    const transactionId = match?.[1];
    const versionText = match?.[2];
    if (
      transactionId &&
      versionText &&
      this.histories
        .get(transactionId)
        ?.some((record) => record.version === Number(versionText))
    )
      throw new Phase3JournalError(
        conflictCode,
        "Phase 3 journal final entry already exists",
      );
    if (await this.finalPathExists(path))
      throw unhealthy("Phase 3 journal final entry is unsafe");
  }

  private async assertCapacity(newTransaction: boolean): Promise<void> {
    if (
      newTransaction &&
      this.latest.size >= PHASE3_JOURNAL_LIMITS.transactions
    )
      throw unhealthy("Phase 3 journal transaction limit exceeded");
    const finalEntries = [...this.histories.values()].reduce(
      (total, history) => total + history.length,
      0,
    );
    if (finalEntries >= PHASE3_JOURNAL_LIMITS.finalEntries)
      throw unhealthy("Phase 3 journal final entry limit exceeded");
    const pendingEntries = (await this.filesystem.readdir(this.root)).filter(
      (name) => pendingNamePattern.test(name),
    ).length;
    if (pendingEntries >= PHASE3_JOURNAL_LIMITS.pendingEntries)
      throw unhealthy("Phase 3 journal pending entry limit exceeded");
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
    throw unhealthy("Phase 3 journal pending reservation failed");
  }

  private async ensureRoot(): Promise<void> {
    if (!isAbsolute(this.root) || resolve(this.root) !== this.root)
      throw unhealthy("Phase 3 journal root must be absolute and normalized");
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
          throw unhealthy("Phase 3 journal root traverses a non-directory");
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
            throw unhealthy("Phase 3 journal root traverses a non-directory");
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
      throw unhealthy("Phase 3 journal directory is unsafe");
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
      throw unhealthy("Phase 3 journal record file is unsafe");
    return metadata;
  }

  private assertLowercaseIdentity(record: Phase3TransactionRecord): void {
    if (!canonicalRecordIdentity(record))
      throw unhealthy("Phase 3 journal UUID identity is not canonical");
  }

  private finalPath(transactionId: string, version: number): string {
    return join(
      this.root,
      `${transactionId}.${String(version).padStart(
        PHASE3_JOURNAL_LIMITS.versionWidth,
        "0",
      )}.entry`,
    );
  }

  private async afterStage(
    stage: Phase3JournalHookStage,
    pendingPath: string,
    finalPath: string,
    recordPath: string,
    record: Phase3TransactionRecord,
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
      throw new Phase3JournalError(
        "journal_unhealthy",
        "Phase 3 journal is unhealthy",
      );
  }
}

function journalEnvelope(
  record: Phase3TransactionRecord,
): Phase3JournalEnvelope {
  const core = {
    schemaVersion: 2 as const,
    record,
  };
  return Object.freeze({
    ...core,
    recordSha256: sha256(canonicalJson(core)),
  });
}

function parseEnvelope(bytes: Uint8Array): Phase3TransactionRecord {
  let value: unknown;
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  try {
    value = JSON.parse(text);
  } catch {
    throw unhealthy("Phase 3 journal record is malformed");
  }
  if (
    typeof value === "object" &&
    value !== null &&
    (value as { readonly schemaVersion?: unknown }).schemaVersion === 1
  )
    throw unhealthy("Phase 3 v1 journal entries are rejected without mutation");
  const parsed = envelopeSchema.safeParse(value);
  if (!parsed.success || canonicalJson(parsed.data) !== text)
    throw unhealthy("Phase 3 journal record is non-canonical");
  const { recordSha256, ...core } = parsed.data;
  if (sha256(canonicalJson(core)) !== recordSha256)
    throw unhealthy("Phase 3 journal record digest mismatch");
  return freezeRecord(assertPhase3TransactionRecord(parsed.data.record));
}

async function writeAll(
  handle: Phase3JournalFileHandle,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
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
        throw unhealthy("Phase 3 journal write did not make progress");
      offset += bytesWritten;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}

function freezeRecord(
  record: Phase3TransactionRecord,
): Phase3TransactionRecord {
  if (record.failure) Object.freeze(record.failure);
  return Object.freeze({ ...record });
}

function privateOwner(metadata: { readonly uid: bigint }): boolean {
  const uid =
    typeof process.getuid === "function" ? BigInt(process.getuid()) : undefined;
  return uid === undefined || metadata.uid === uid;
}

function canonicalRecordIdentity(record: Phase3TransactionRecord): boolean {
  return [record.transactionId, record.proposalId, record.checkpointId].every(
    (value) => lowercaseUuid.test(value),
  );
}

function sameIdentity(
  left: BigIntStats,
  right: BigIntStats,
  durability: Phase2DurabilityPort,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
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

function illegal(message: string): Phase3JournalError {
  return new Phase3JournalError("journal_illegal", message);
}

function unhealthy(message: string): Phase3JournalError {
  return new Phase3JournalError("journal_unhealthy", message);
}

function normalize(error: unknown, message: string): Phase3JournalError {
  return error instanceof Phase3JournalError ? error : unhealthy(message);
}
