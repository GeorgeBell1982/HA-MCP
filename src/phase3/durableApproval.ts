import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  rmdir,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { types } from "node:util";
import { z } from "zod";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "../proposals/durability.js";
import {
  assertPhase3ApprovalNotCancelled,
  Phase3ApprovalError,
  validatePhase3ApplyGrant,
  validatePhase3ApprovalProposal,
  type Phase3ApprovalActiveContext,
  type Phase3ApprovalContext,
  type Phase3ApprovalPort,
} from "./approval.js";
import {
  canonicalJson,
  phase3ApprovalGrantSchema,
  type Phase3ApprovalGrant,
  type Phase3ProposalSnapshot,
} from "./contracts.js";

export const PHASE3_APPROVAL_LIMITS = Object.freeze({
  slots: 256,
  headerStages: 4,
  grantStages: 32,
  usedStages: 4,
  rootScanEntries: 293,
  slotScanEntries: 6,
  headerBytes: 1024,
  grantBytes: 4096,
  receiptBytes: 1024,
  grantTtlMs: 120_000,
  uuidAttempts: 4,
});

export const PHASE3_APPROVAL_DOMAINS = Object.freeze({
  keyId: "HA_PHASE3_APPROVAL_KEY_ID_V1\0",
  header: "HA_PHASE3_APPROVAL_HEADER_V1\0",
  grant: "HA_PHASE3_APPROVAL_GRANT_V1\0",
  receipt: "HA_PHASE3_APPROVAL_RECEIPT_V1\0",
});

export type Phase3ApprovalCommitState =
  | "not_committed"
  | "possibly_committed"
  | "durably_committed";

export type Phase3ApprovalHookStage =
  | "header_file_synced"
  | "header_pre_commit"
  | "header_post_commit"
  | "header_parent_synced"
  | "header_cleanup"
  | "header_housekeeping_synced"
  | "grant_file_synced"
  | "grant_stage_synced"
  | "grant_pre_commit"
  | "grant_post_commit"
  | "grant_parent_synced"
  | "grant_cleanup"
  | "grant_housekeeping_synced"
  | "receipt_file_synced"
  | "receipt_pre_commit"
  | "receipt_post_commit"
  | "receipt_parent_synced"
  | "receipt_cleanup"
  | "receipt_housekeeping_synced";

export interface Phase3ApprovalHookContext {
  readonly stage: Phase3ApprovalHookStage;
  readonly commitState: Phase3ApprovalCommitState;
  readonly root: string;
  readonly pendingPath: string;
  readonly finalPath: string;
  readonly grantId?: string;
}

export interface Phase3ApprovalHooks {
  readonly afterStage?: (context: Phase3ApprovalHookContext) => Promise<void>;
}

const retainedStageErrors = new WeakSet<object>();

function markRetainedStage(error: object): void {
  Object.defineProperty(error, "retainPhase3ApprovalStage", {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false,
  });
  retainedStageErrors.add(error);
}

export class Phase3ApprovalSimulatedCrash extends Error {
  constructor(public readonly stage: Phase3ApprovalHookStage) {
    super("Simulated Phase 3 approval crash");
    this.name = "Phase3ApprovalSimulatedCrash";
    markRetainedStage(this);
  }
}

export interface Phase3ApprovalFileHandle {
  write(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ bytesWritten: number }>;
  sync(): Promise<void>;
  stat(options: { bigint: true }): Promise<BigIntStats>;
  readFile(): Promise<Buffer>;
}

export interface Phase3ApprovalOpenLease {
  /**
   * Providers must register cleanup before resolving `open`. Until this
   * succeeds, providers retain responsibility for closing acquired resources.
   */
  register(cleanup: () => Promise<void>): void;
}

export interface Phase3ApprovalCustodyLease {
  readonly release: () => Promise<void>;
}

export type Phase3ApprovalCustodyProvider = (
  root: string,
) => Promise<Phase3ApprovalCustodyLease>;

export interface Phase3ApprovalRemediationCounts {
  readonly headerStages: number;
  readonly grantStages: number;
  readonly receiptStages: number;
}

export interface Phase3ApprovalFilesystem {
  readonly lstat: (
    path: string,
    options: { bigint: true },
  ) => Promise<BigIntStats>;
  readonly mkdir: (path: string, options: { mode: number }) => Promise<unknown>;
  readonly open: (
    path: string,
    flags: number,
    mode: number | undefined,
    lease: Phase3ApprovalOpenLease,
  ) => Promise<Phase3ApprovalFileHandle>;
  readonly readdir: (path: string) => Promise<string[]>;
  readonly link: (source: string, target: string) => Promise<void>;
  readonly rename: (source: string, target: string) => Promise<void>;
  readonly rm: (
    path: string,
    options: { force: boolean; recursive?: boolean },
  ) => Promise<void>;
  readonly rmdir: (path: string) => Promise<void>;
}

export interface DurablePhase3ApprovalOptions {
  readonly acquireExclusiveRootCustody?: Phase3ApprovalCustodyProvider;
  readonly durability?: Phase2DurabilityPort;
  readonly filesystem?: Phase3ApprovalFilesystem;
  readonly hooks?: Phase3ApprovalHooks;
  readonly now?: () => number;
  readonly randomUUID?: () => string;
}

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const macPattern = /^[0-9a-f]{64}$/u;
const isoMillisecondsPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const slotPattern = /^slot-(\d{3})$/u;
const headerStagePattern = /^\.header-stage-([0-3])$/u;
const grantStagePattern = /^\.grant-stage-(\d{2})$/u;
const usedStagePattern = /^\.used-stage-([0-3])$/u;

const strictTimeSchema = z
  .string()
  .regex(isoMillisecondsPattern)
  .refine((value) => {
    const parsed = Date.parse(value);
    return (
      Number.isSafeInteger(parsed) && new Date(parsed).toISOString() === value
    );
  });

const strictGrantSchema = phase3ApprovalGrantSchema.superRefine(
  (grant, context) => {
    if (!uuidPattern.test(grant.grantId))
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["grantId"] });
    if (!uuidPattern.test(grant.proposalId))
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["proposalId"] });
    if (
      !strictTimeSchema.safeParse(grant.issuedAt).success ||
      !strictTimeSchema.safeParse(grant.expiresAt).success
    )
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["issuedAt"] });
  },
);

const keyIdCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    purpose: z.literal("phase3_approval_key_identity"),
  })
  .strict();
const headerCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    storeId: z.string().regex(uuidPattern),
    keyId: z.string().regex(macPattern),
  })
  .strict();
const headerEnvelopeSchema = headerCoreSchema
  .extend({ headerHmac: z.string().regex(macPattern) })
  .strict();
const grantCoreSchema = z
  .object({ schemaVersion: z.literal(1), grant: strictGrantSchema })
  .strict();
const grantEnvelopeSchema = grantCoreSchema
  .extend({ grantHmac: z.string().regex(macPattern) })
  .strict();
const receiptCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    grantId: z.string().regex(uuidPattern),
    grantHmac: z.string().regex(macPattern),
    consumedAt: strictTimeSchema,
  })
  .strict();
const receiptEnvelopeSchema = receiptCoreSchema
  .extend({ receiptHmac: z.string().regex(macPattern) })
  .strict();

type HeaderEnvelope = z.infer<typeof headerEnvelopeSchema>;
type GrantEnvelope = z.infer<typeof grantEnvelopeSchema>;
type ReceiptEnvelope = z.infer<typeof receiptEnvelopeSchema>;

interface StableFile {
  readonly metadata: ApprovalMetadata;
  readonly bytes: Buffer;
}

interface ApprovalMetadata {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly uid: bigint;
  readonly gid: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  readonly isFile: boolean;
  readonly isDirectory: boolean;
}

interface TrustedPhase3ApprovalFileHandle {
  write(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ readonly bytesWritten: number }>;
  sync(): Promise<void>;
  close(): Promise<void>;
  stat(options: { bigint: true }): Promise<ApprovalMetadata>;
  readFile(): Promise<Buffer>;
}

interface TrustedPhase3ApprovalFilesystem {
  readonly lstat: (
    path: string,
    options: { bigint: true },
  ) => Promise<ApprovalMetadata>;
  readonly mkdir: (path: string, options: { mode: number }) => Promise<void>;
  readonly open: (
    path: string,
    flags: number,
    mode?: number,
  ) => Promise<TrustedPhase3ApprovalFileHandle>;
  readonly readdir: (path: string) => Promise<string[]>;
  readonly link: (source: string, target: string) => Promise<void>;
  readonly rename: (source: string, target: string) => Promise<void>;
  readonly rm: (
    path: string,
    options: { force: boolean; recursive?: boolean },
  ) => Promise<void>;
  readonly rmdir: (path: string) => Promise<void>;
}

interface StoredGrant {
  readonly slotName: string;
  readonly slotPath: string;
  readonly slotMetadata: ApprovalMetadata;
  readonly grant: Phase3ApprovalGrant;
  readonly grantHmac: string;
  readonly grantMetadata: ApprovalMetadata;
  readonly grantBytes: Buffer;
  readonly receipt?: ReceiptEnvelope;
}

interface ScannedStore {
  readonly header?: HeaderEnvelope;
  readonly grants: Map<string, StoredGrant>;
  readonly slots: Set<string>;
}

interface RemediationFile {
  readonly name: string;
  readonly path: string;
  readonly metadata: ApprovalMetadata;
  readonly bytes: Buffer;
}

interface RemediationGrantStage {
  readonly name: string;
  readonly path: string;
  readonly metadata: ApprovalMetadata;
  readonly children: readonly string[];
  readonly grant?: RemediationFile;
}

interface RemediationFinal extends RemediationFile {
  metadata: ApprovalMetadata;
}

interface RemediationSlot {
  readonly name: string;
  readonly path: string;
  readonly metadata: ApprovalMetadata;
  readonly children: readonly string[];
  readonly grant: RemediationFinal;
  readonly grantEnvelope: GrantEnvelope;
  readonly receipt?: RemediationFinal;
  readonly receiptStages: readonly RemediationFile[];
}

interface RemediationScan {
  readonly rootMetadata: ApprovalMetadata;
  readonly rootEntries: readonly string[];
  readonly header?: RemediationFinal;
  readonly headerStages: readonly RemediationFile[];
  readonly grantStages: readonly RemediationGrantStage[];
  readonly slots: readonly RemediationSlot[];
  readonly buffers: readonly Buffer[];
}

const defaultFilesystem: Phase3ApprovalFilesystem = Object.freeze({
  lstat,
  mkdir,
  open: async (
    path: string,
    flags: number,
    mode: number | undefined,
    lease: Phase3ApprovalOpenLease | undefined,
  ) => {
    const handle = await open(path, flags, mode);
    const close = handle.close.bind(handle);
    try {
      if (!lease) throw new Error("Approval open lease is required");
      lease.register(async () => await close());
      return handle;
    } catch (error) {
      await close().catch(() => undefined);
      throw error;
    }
  },
  readdir,
  link,
  rename,
  rm,
  rmdir,
});

const preservedBoundaryErrnos = new Set([
  "EEXIST",
  "ENOTEMPTY",
  "ENOENT",
  "EPERM",
]);

function safeBoundaryErrno(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    const descriptor = Reflect.getOwnPropertyDescriptor(error, "code");
    return descriptor &&
      "value" in descriptor &&
      typeof descriptor.value === "string"
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

class Phase3ApprovalBoundaryFailure extends Error {
  readonly code: string | undefined;

  constructor(error: unknown) {
    super("Approval injected boundary failed");
    this.name = "Phase3ApprovalBoundaryFailure";
    const boundaryCode = safeBoundaryErrno(error);
    this.code =
      boundaryCode && preservedBoundaryErrnos.has(boundaryCode)
        ? boundaryCode
        : undefined;
  }
}

function boundaryFailure(error: unknown): Phase3ApprovalBoundaryFailure {
  return new Phase3ApprovalBoundaryFailure(error);
}

async function callBoundary<T, Result>(
  operation: () => Promise<T>,
  snapshot: (value: T) => Result,
): Promise<Result> {
  try {
    return snapshot(await operation());
  } catch (error) {
    throw boundaryFailure(error);
  }
}

function protectedHandle(
  value: unknown,
  closeOnce: () => Promise<unknown>,
): TrustedPhase3ApprovalFileHandle {
  if (typeof value !== "object" || value === null)
    throw boundaryFailure(new Error("invalid boundary handle"));
  const handle = value as Phase3ApprovalFileHandle;
  const write = boundaryMethod(handle, "write");
  const sync = boundaryMethod(handle, "sync");
  const stat = boundaryMethod(handle, "stat");
  const readFile = boundaryMethod(handle, "readFile");
  const protectedValue: TrustedPhase3ApprovalFileHandle = {
    write: async (buffer, offset, length, position) =>
      await callBoundary(
        async () =>
          await invokeBoundary(write, handle, [
            buffer,
            offset,
            length,
            position,
          ]),
        (result) => copyWriteResult(result, length),
      ),
    sync: async () =>
      await callBoundary(
        async () => await invokeBoundary(sync, handle, []),
        copyUndefined,
      ),
    close: async () => await callBoundary(closeOnce, copyUndefined),
    stat: async (options) =>
      await callBoundary(
        async () => await invokeBoundary(stat, handle, [options]),
        copyMetadata,
      ),
    readFile: async () =>
      await callBoundary(
        async () => await invokeBoundary(readFile, handle, []),
        copyBuffer,
      ),
  };
  return Object.freeze(protectedValue);
}

function protectedFilesystem(
  filesystem: Phase3ApprovalFilesystem,
): TrustedPhase3ApprovalFilesystem {
  const protectedValue: TrustedPhase3ApprovalFilesystem = {
    lstat: async (path, options) =>
      await callBoundary(
        async () => await filesystem.lstat(path, options),
        copyMetadata,
      ),
    mkdir: async (path, options) =>
      await callBoundary(
        async () => await filesystem.mkdir(path, options),
        copyUndefined,
      ),
    open: async (path, flags, mode) => {
      let cleanup: (() => Promise<void>) | undefined;
      let cleanupStarted = false;
      const closeOnce = async (): Promise<unknown> => {
        if (cleanupStarted) return undefined;
        cleanupStarted = true;
        if (!cleanup) throw new Error("Approval open cleanup is missing");
        return await cleanup();
      };
      const lease: Phase3ApprovalOpenLease = Object.freeze({
        register: (candidate: () => Promise<void>) => {
          if (cleanup || typeof candidate !== "function")
            throw new Error("Approval open cleanup is invalid");
          cleanup = candidate;
        },
      });
      try {
        const handle = await filesystem.open(path, flags, mode, lease);
        if (!cleanup)
          throw new Error("Approval open cleanup was not registered");
        return protectedHandle(handle, closeOnce);
      } catch (error) {
        if (cleanup)
          try {
            await closeOnce();
          } catch {
            // The original open or validation failure remains authoritative.
          }
        throw boundaryFailure(error);
      }
    },
    readdir: async (path) =>
      await callBoundary(
        async () => await filesystem.readdir(path),
        copyDirectoryEntries,
      ),
    link: async (source, target) =>
      await callBoundary(
        async () => await filesystem.link(source, target),
        copyUndefined,
      ),
    rename: async (source, target) =>
      await callBoundary(
        async () => await filesystem.rename(source, target),
        copyUndefined,
      ),
    rm: async (path, options) =>
      await callBoundary(
        async () => await filesystem.rm(path, options),
        copyUndefined,
      ),
    rmdir: async (path) =>
      await callBoundary(
        async () => await filesystem.rmdir(path),
        copyUndefined,
      ),
  };
  return Object.freeze(protectedValue);
}

function protectedDurability(
  durability: Phase2DurabilityPort,
): Phase2DurabilityPort {
  const protectedValue: Phase2DurabilityPort = {
    privateMode: (mode) => {
      try {
        const result = durability.privateMode(mode);
        if (typeof result !== "boolean") throw new Error("invalid");
        return result;
      } catch (error) {
        throw boundaryFailure(error);
      }
    },
    syncDirectory: async (path) =>
      await callBoundary(
        async () => await durability.syncDirectory(path),
        copyUndefined,
      ),
  };
  return Object.freeze(protectedValue);
}

type BoundaryMethod = (...args: unknown[]) => unknown;

function boundaryMethod(value: object, name: string): BoundaryMethod {
  const method = (value as Record<string, unknown>)[name];
  if (typeof method !== "function") throw new Error("invalid boundary method");
  return method as BoundaryMethod;
}

function invokeBoundary(
  method: BoundaryMethod,
  receiver: object,
  args: readonly unknown[],
): unknown {
  return Reflect.apply(method, receiver, args);
}

function copyUndefined(value: unknown): void {
  if (value !== undefined) throw new Error("invalid boundary result");
}

function copyWriteResult(
  value: unknown,
  requestedLength: number,
): { readonly bytesWritten: number } {
  if (typeof value !== "object" || value === null)
    throw new Error("invalid write result");
  const bytesWritten = (value as Record<string, unknown>).bytesWritten;
  if (
    !Number.isSafeInteger(bytesWritten) ||
    (bytesWritten as number) < 0 ||
    (bytesWritten as number) > requestedLength
  )
    throw new Error("invalid write result");
  return Object.freeze({ bytesWritten: bytesWritten as number });
}

function copyBuffer(value: unknown): Buffer {
  if (!Buffer.isBuffer(value)) throw new Error("invalid read result");
  let owned: Buffer | undefined;
  try {
    const length = value.byteLength;
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > PHASE3_APPROVAL_LIMITS.grantBytes
    )
      throw new Error("invalid read result length");
    owned = Buffer.alloc(length);
    for (let index = 0; index < length; index += 1) {
      const byte = value[index];
      if (
        typeof byte !== "number" ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 255
      )
        throw new Error("invalid read result byte");
      owned[index] = byte;
    }
    for (let index = 0; index < length; index += 1) value[index] = 0;
    if (value.byteLength !== length)
      throw new Error("source buffer length changed");
    for (let index = 0; index < length; index += 1)
      if (value[index] !== 0) throw new Error("source buffer was not zeroed");
    return owned;
  } catch (error) {
    owned?.fill(0);
    throw error;
  }
}

function zeroBuffer(buffer: Buffer | undefined): void {
  if (!buffer) return;
  buffer.fill(0);
}

function copyDirectoryEntries(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("invalid directory entries");
  const source = value as unknown[];
  const length = source.length;
  if (
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > PHASE3_APPROVAL_LIMITS.rootScanEntries + 1
  )
    throw new Error("invalid directory entries");
  const entries: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const entry = source[index];
    if (typeof entry !== "string") throw new Error("invalid directory entry");
    entries.push(entry);
  }
  return entries;
}

function copyMetadata(value: unknown): ApprovalMetadata {
  if (typeof value !== "object" || value === null)
    throw new Error("invalid metadata");
  const record = value as Record<string, unknown>;
  const isFile = boundaryMethod(value, "isFile");
  const isDirectory = boundaryMethod(value, "isDirectory");
  const snapshot = {
    dev: record.dev,
    ino: record.ino,
    mode: record.mode,
    nlink: record.nlink,
    uid: record.uid,
    gid: record.gid,
    size: record.size,
    mtimeNs: record.mtimeNs,
    ctimeNs: record.ctimeNs,
    isFile: invokeBoundary(isFile, value, []),
    isDirectory: invokeBoundary(isDirectory, value, []),
  };
  if (
    typeof snapshot.dev !== "bigint" ||
    typeof snapshot.ino !== "bigint" ||
    typeof snapshot.mode !== "bigint" ||
    typeof snapshot.nlink !== "bigint" ||
    typeof snapshot.uid !== "bigint" ||
    typeof snapshot.gid !== "bigint" ||
    typeof snapshot.size !== "bigint" ||
    typeof snapshot.mtimeNs !== "bigint" ||
    typeof snapshot.ctimeNs !== "bigint" ||
    typeof snapshot.isFile !== "boolean" ||
    typeof snapshot.isDirectory !== "boolean"
  )
    throw new Error("invalid metadata");
  return Object.freeze(snapshot as ApprovalMetadata);
}

function copyCustodyLease(value: unknown): {
  readonly lease: Phase3ApprovalCustodyLease;
  readonly release: BoundaryMethod;
} {
  if (
    typeof value !== "object" ||
    value === null ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !Object.isFrozen(value)
  )
    throw new Error("invalid custody lease");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 1 || keys[0] !== "release")
    throw new Error("invalid custody lease");
  const descriptor = Reflect.getOwnPropertyDescriptor(value, "release");
  if (
    !descriptor ||
    !("value" in descriptor) ||
    descriptor.enumerable !== true ||
    descriptor.configurable !== false ||
    descriptor.writable !== false
  )
    throw new Error("invalid custody lease");
  const release: unknown = descriptor.value;
  if (typeof release !== "function" || types.isProxy(release))
    throw new Error("invalid custody release");
  return Object.freeze({
    lease: value as Phase3ApprovalCustodyLease,
    release: release as BoundaryMethod,
  });
}

export class DurablePhase3ApprovalGrants implements Phase3ApprovalPort {
  private readonly root: string;
  private readonly key: Buffer;
  private readonly acquireExclusiveRootCustody:
    | Phase3ApprovalCustodyProvider
    | undefined;
  private readonly durability: Phase2DurabilityPort;
  private readonly filesystem: TrustedPhase3ApprovalFilesystem;
  private readonly hooks: Phase3ApprovalHooks;
  private readonly now: () => unknown;
  private readonly uuid: () => unknown;
  private readonly nativeDurability: boolean;
  private initialized = false;
  private unhealthy = false;
  private header: HeaderEnvelope | undefined;
  private grants = new Map<string, StoredGrant>();
  private lifecycle: "open" | "closing" | "closed" = "open";
  private inFlight = 0;
  private remediationReserved = false;
  private readonly closeWaiters: Array<() => void> = [];
  private closePromise: Promise<void> | undefined;

  constructor(
    root: string,
    key: Uint8Array,
    options: DurablePhase3ApprovalOptions = {},
  ) {
    if (!isAbsolute(root) || resolve(root) !== root)
      throw unhealthy("Approval root must be absolute and normalized");
    if (key.byteLength !== 32)
      throw unhealthy("Approval key must be exactly 32 bytes");
    let acquireExclusiveRootCustody: Phase3ApprovalCustodyProvider | undefined;
    let durability: Phase2DurabilityPort | undefined;
    let filesystem: Phase3ApprovalFilesystem | undefined;
    let hooks: Phase3ApprovalHooks | undefined;
    let now: (() => number) | undefined;
    let uuid: (() => string) | undefined;
    try {
      acquireExclusiveRootCustody = options.acquireExclusiveRootCustody;
      durability = options.durability;
      filesystem = options.filesystem;
      hooks = options.hooks;
      now = options.now;
      uuid = options.randomUUID;
      if (
        acquireExclusiveRootCustody !== undefined &&
        typeof acquireExclusiveRootCustody !== "function"
      )
        throw new Error("invalid custody provider");
      if (now !== undefined && typeof now !== "function")
        throw new Error("invalid clock");
      if (uuid !== undefined && typeof uuid !== "function")
        throw new Error("invalid UUID source");
    } catch {
      throw unhealthy("Approval injected options are invalid");
    }
    this.root = root;
    this.key = Buffer.from(key);
    this.acquireExclusiveRootCustody = acquireExclusiveRootCustody;
    this.nativeDurability = durability === undefined;
    this.durability = protectedDurability(durability ?? strictPhase2Durability);
    this.filesystem = protectedFilesystem(filesystem ?? defaultFilesystem);
    this.hooks = hooks ?? {};
    this.now = now ?? Date.now;
    this.uuid = uuid ?? randomUUID;
  }

  initialize(): Promise<void> {
    return this.run(async () => {
      if (this.unhealthy) throw unhealthy("Approval store is unhealthy");
      try {
        if (this.nativeDurability && process.platform !== "linux")
          throw unhealthy("Native approval durability requires Linux");
        await this.assertDirectory(this.root);
        let scanned = await this.scan();
        if (!scanned.header) {
          if (scanned.grants.size !== 0) {
            this.zeroScanned(scanned);
            throw unhealthy("Approval header is missing");
          }
          await this.initializeHeader();
          scanned = await this.scan();
        }
        if (!scanned.header) {
          this.zeroScanned(scanned);
          throw unhealthy("Approval header is missing");
        }
        this.replaceScanned(scanned);
        this.initialized = true;
      } catch (error) {
        if (!isCapacity(error)) this.latchIfStoreFailure(error);
        throw normalize(error, "Approval initialization failed");
      }
    });
  }

  issueApplyGrant(
    proposal: Phase3ProposalSnapshot,
    context: Phase3ApprovalContext,
  ): Promise<Phase3ApprovalGrant> {
    return this.run(async () => {
      try {
        this.assertHealthy();
        const active = assertPhase3ApprovalNotCancelled(context);
        const trustedProposal = validatePhase3ApprovalProposal(
          proposal,
          context,
        ).proposal;
        const issuedAt = this.trustedNow();
        validatePhase3ApprovalProposal(trustedProposal, {
          now: issuedAt,
          signal: active.signal,
        });
        await this.refresh();
        if (this.grants.size >= PHASE3_APPROVAL_LIMITS.slots)
          throw capacity("Approval slot capacity is exhausted");
        for (
          let uuidAttempt = 0;
          uuidAttempt < PHASE3_APPROVAL_LIMITS.uuidAttempts;
          uuidAttempt += 1
        ) {
          const grantId = this.trustedUuid();
          const grant = this.buildGrant(grantId, trustedProposal, issuedAt);
          const result = await this.issueAttempt(
            grant,
            trustedProposal,
            active,
          );
          if (result === "uuid_collision") continue;
          return result;
        }
        throw capacity("Approval UUID attempt capacity is exhausted");
      } catch (error) {
        throw this.publicFailure(error, "Approval grant issue failed");
      }
    });
  }

  consumeApplyGrant(
    grantId: string,
    proposal: Phase3ProposalSnapshot,
    context: Phase3ApprovalContext,
  ): Promise<Phase3ApprovalGrant> {
    return this.run(async () => {
      try {
        this.assertHealthy();
        const active = assertPhase3ApprovalNotCancelled(context);
        await this.refresh();
        const stored = this.grants.get(grantId);
        if (!stored)
          throw new Phase3ApprovalError(
            "approval_not_found",
            "Approval grant was not found",
          );
        if (stored.receipt)
          throw new Phase3ApprovalError(
            "approval_replayed",
            "Approval grant has already been consumed",
          );
        const trustedProposal = validatePhase3ApplyGrant(
          stored.grant,
          proposal,
          context,
          active,
        );
        return await this.consumeStored(stored, trustedProposal, active);
      } catch (error) {
        throw this.publicFailure(error, "Approval grant consumption failed");
      }
    });
  }

  remediateStaleStages(): Promise<Phase3ApprovalRemediationCounts> {
    if (
      this.lifecycle !== "open" ||
      this.initialized ||
      this.unhealthy ||
      this.remediationReserved ||
      this.inFlight !== 0
    )
      return Promise.reject(
        unhealthy("Approval stale-stage remediation is unavailable"),
      );
    this.remediationReserved = true;
    this.inFlight += 1;
    return Promise.resolve()
      .then(async () => await this.remediateWithCustody())
      .finally(() => {
        this.remediationReserved = false;
        this.finishInFlight();
      });
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.lifecycle = "closing";
    this.closePromise = (async () => {
      if (this.inFlight !== 0)
        await new Promise<void>((resolveClose) => {
          this.closeWaiters.push(resolveClose);
        });
      zeroBuffer(this.key);
      for (const stored of this.grants.values()) zeroBuffer(stored.grantBytes);
      this.grants.clear();
      this.header = undefined;
      this.initialized = false;
      this.unhealthy = false;
      this.lifecycle = "closed";
    })();
    return this.closePromise;
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.lifecycle !== "open")
      return Promise.reject(unhealthy("Approval store is closed"));
    if (this.remediationReserved)
      return Promise.reject(
        unhealthy("Approval stale-stage remediation is reserved"),
      );
    this.inFlight += 1;
    return Promise.resolve()
      .then(operation)
      .finally(() => {
        this.finishInFlight();
      });
  }

  private finishInFlight(): void {
    this.inFlight -= 1;
    if (this.inFlight === 0)
      for (const waiter of this.closeWaiters.splice(0)) waiter();
  }

  private assertHealthy(): void {
    if (!this.initialized || this.unhealthy)
      throw unhealthy("Approval store is not healthy and initialized");
  }

  private trustedNow(): number {
    try {
      const value = this.now();
      if (
        !Number.isSafeInteger(value) ||
        (value as number) < -8_640_000_000_000_000 ||
        (value as number) > 8_640_000_000_000_000
      )
        throw new Error("invalid clock result");
      return value as number;
    } catch {
      throw unhealthy("Approval trusted clock failed");
    }
  }

  private trustedUuid(): string {
    try {
      const value = this.uuid();
      if (typeof value !== "string" || !uuidPattern.test(value))
        throw new Error("invalid UUID result");
      return value;
    } catch {
      throw unhealthy("Approval UUID source failed");
    }
  }

  private buildGrant(
    grantId: string,
    proposal: Phase3ProposalSnapshot,
    issuedAt: number,
  ): Phase3ApprovalGrant {
    const proposalExpiry = Date.parse(proposal.expiresAt);
    const expiresAt = Math.min(
      issuedAt + PHASE3_APPROVAL_LIMITS.grantTtlMs,
      proposalExpiry,
    );
    const parsed = strictGrantSchema.safeParse({
      grantId,
      proposalId: proposal.proposalId,
      proposalStorageSha256: proposal.proposalStorageSha256,
      candidateSha256: proposal.candidateSha256,
      diffSha256: proposal.diffSha256,
      operation: "apply",
      risk: proposal.risk,
      impact: proposal.impact,
      reloadTarget: proposal.reloadTarget,
      issuedAt: new Date(issuedAt).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
    });
    if (!parsed.success) throw unhealthy("Approval grant construction failed");
    return Object.freeze(parsed.data);
  }

  private async initializeHeader(): Promise<void> {
    const core = {
      schemaVersion: 1 as const,
      storeId: this.trustedUuid(),
      keyId: this.mac(PHASE3_APPROVAL_DOMAINS.keyId, {
        schemaVersion: 1,
        purpose: "phase3_approval_key_identity",
      }),
    };
    const envelope = {
      ...core,
      headerHmac: this.mac(PHASE3_APPROVAL_DOMAINS.header, core),
    };
    const bytes = this.envelopeBytes(
      envelope,
      PHASE3_APPROVAL_LIMITS.headerBytes,
    );
    let stage: { path: string; metadata: ApprovalMetadata } | undefined;
    try {
      stage = await this.claimFileStage(
        ".header-stage-",
        PHASE3_APPROVAL_LIMITS.headerStages,
        bytes,
        PHASE3_APPROVAL_LIMITS.headerBytes,
        "header_file_synced",
        join(this.root, "header.json"),
      );
      await this.commitHeader(stage.path, stage.metadata, bytes);
    } finally {
      zeroBuffer(bytes);
    }
  }

  private async commitHeader(
    pendingPath: string,
    pendingMetadata: ApprovalMetadata,
    bytes: Buffer,
  ): Promise<void> {
    const finalPath = join(this.root, "header.json");
    let state: Phase3ApprovalCommitState = "not_committed";
    let syscallError: unknown;
    await this.after("header_pre_commit", state, pendingPath, finalPath);
    state = "possibly_committed";
    try {
      await this.filesystem.link(pendingPath, finalPath);
      await this.after("header_post_commit", state, pendingPath, finalPath);
    } catch (error) {
      syscallError = error;
    }
    if (syscallError) {
      let finalExists: boolean;
      let sourceMatches: boolean;
      try {
        finalExists = await this.pathExists(finalPath);
        sourceMatches = await this.matchFile(
          pendingPath,
          pendingMetadata,
          bytes,
        );
      } catch (error) {
        return this.commitUnknown(
          "Approval header reconciliation is unknown",
          error,
        );
      }
      if (!finalExists && sourceMatches)
        throw normalize(
          syscallError,
          "Approval header link failed before commit",
        );
    }
    try {
      await this.durability.syncDirectory(this.root);
      const winner = await this.readHeader(finalPath);
      state = "durably_committed";
      this.header = winner.envelope;
      await this.afterBestEffort(
        "header_parent_synced",
        state,
        pendingPath,
        finalPath,
      );
    } catch (error) {
      if (state !== "durably_committed") {
        this.unhealthy = true;
        throw commitUnknown("Approval header commit is unknown", error);
      }
    }
    await this.cleanupFileBestEffort(
      pendingPath,
      pendingMetadata,
      bytes,
      "header_cleanup",
      "header_housekeeping_synced",
      finalPath,
    );
  }

  private async issueAttempt(
    grant: Phase3ApprovalGrant,
    proposal: Phase3ProposalSnapshot,
    active: Phase3ApprovalActiveContext,
  ): Promise<Phase3ApprovalGrant | "uuid_collision"> {
    const core = { schemaVersion: 1 as const, grant };
    const envelope = {
      ...core,
      grantHmac: this.mac(PHASE3_APPROVAL_DOMAINS.grant, core),
    };
    const bytes = this.envelopeBytes(
      envelope,
      PHASE3_APPROVAL_LIMITS.grantBytes,
    );
    let stage:
      | { readonly path: string; readonly metadata: ApprovalMetadata }
      | undefined;
    let recordMetadata: ApprovalMetadata | undefined;
    try {
      stage = await this.claimGrantStage();
      const recordPath = join(stage.path, "grant.json");
      recordMetadata = await this.writeExclusiveFile(
        recordPath,
        bytes,
        PHASE3_APPROVAL_LIMITS.grantBytes,
      );
      await this.after(
        "grant_file_synced",
        "not_committed",
        stage.path,
        recordPath,
        grant.grantId,
      );
      await this.durability.syncDirectory(stage.path);
      await this.after(
        "grant_stage_synced",
        "not_committed",
        stage.path,
        recordPath,
        grant.grantId,
      );
      await this.assertExactFile(recordPath, recordMetadata, bytes);
      const preCommitNow = this.trustedNow();
      validatePhase3ApplyGrant(
        grant,
        proposal,
        { now: preCommitNow, signal: active.signal },
        active,
      );
      await this.refresh();
      if (this.grants.has(grant.grantId)) {
        await this.cleanupDirectoryBeforeCommit(
          stage.path,
          stage.metadata,
          recordMetadata,
          bytes,
        );
        return "uuid_collision";
      }
      for (let index = 0; index < PHASE3_APPROVAL_LIMITS.slots; index += 1) {
        const slotName = "slot-" + String(index).padStart(3, "0");
        if (this.slotOccupied(slotName)) continue;
        const outcome = await this.commitGrantToSlot(
          stage.path,
          stage.metadata,
          recordMetadata,
          bytes,
          grant,
          proposal,
          active,
          slotName,
        );
        if (outcome === "contention") continue;
        if (outcome === "uuid_collision") return outcome;
        await this.refreshAfterDurable();
        return grant;
      }
      await this.cleanupDirectoryBeforeCommit(
        stage.path,
        stage.metadata,
        recordMetadata,
        bytes,
      );
      throw capacity("Approval slot capacity is exhausted");
    } catch (error) {
      if (retainStage(error)) throw error;
      if (stage && !isCommitUnknown(error))
        await this.cleanupDirectoryBeforeCommit(
          stage.path,
          stage.metadata,
          recordMetadata,
          bytes,
        );
      throw normalize(error, "Approval grant issue failed");
    } finally {
      zeroBuffer(bytes);
    }
  }

  private async commitGrantToSlot(
    pendingPath: string,
    pendingMetadata: ApprovalMetadata,
    recordMetadata: ApprovalMetadata,
    bytes: Buffer,
    grant: Phase3ApprovalGrant,
    proposal: Phase3ProposalSnapshot,
    active: Phase3ApprovalActiveContext,
    slotName: string,
  ): Promise<"committed" | "contention" | "uuid_collision"> {
    const finalPath = join(this.root, slotName);
    let state: Phase3ApprovalCommitState = "not_committed";
    let syscallError: unknown;
    await this.after(
      "grant_pre_commit",
      state,
      pendingPath,
      finalPath,
      grant.grantId,
    );
    validatePhase3ApplyGrant(
      grant,
      proposal,
      { now: this.trustedNow(), signal: active.signal },
      active,
    );
    state = "possibly_committed";
    try {
      await this.filesystem.rename(pendingPath, finalPath);
      await this.after(
        "grant_post_commit",
        state,
        pendingPath,
        finalPath,
        grant.grantId,
      );
    } catch (error) {
      syscallError = error;
    }
    let source: boolean;
    let target: StoredGrant | undefined;
    try {
      source = await this.matchDirectory(
        pendingPath,
        pendingMetadata,
        recordMetadata,
        bytes,
      );
      target = await this.tryReadSlot(slotName);
    } catch (error) {
      return this.commitUnknown(
        "Approval grant reconciliation observation failed",
        error,
      );
    }
    if (!source && target && target.grant.grantId === grant.grantId) {
      if (Buffer.compare(target.grantBytes, bytes) !== 0) {
        zeroBuffer(target.grantBytes);
        return this.commitUnknown("Approval grant rename target conflicts");
      }
      try {
        await this.durability.syncDirectory(this.root);
      } catch (error) {
        zeroBuffer(target.grantBytes);
        return this.commitUnknown(
          "Approval grant durability is unknown",
          error,
        );
      }
      try {
        const reconciled = await this.scan();
        const committed = reconciled.grants.get(grant.grantId);
        if (
          !committed ||
          committed.slotName !== slotName ||
          Buffer.compare(committed.grantBytes, bytes) !== 0
        ) {
          for (const entry of reconciled.grants.values())
            zeroBuffer(entry.grantBytes);
          return this.commitUnknown("Approval grant reconciliation conflicts");
        }
        this.replaceScanned(reconciled);
      } catch (error) {
        zeroBuffer(target.grantBytes);
        return this.commitUnknown(
          "Approval grant reconciliation is unknown",
          error,
        );
      }
      state = "durably_committed";
      await this.afterBestEffort(
        "grant_parent_synced",
        state,
        pendingPath,
        finalPath,
        grant.grantId,
      );
      await this.grantHousekeeping(pendingPath, finalPath, grant.grantId);
      zeroBuffer(target.grantBytes);
      return "committed";
    }
    if (source && target) {
      try {
        try {
          await this.durability.syncDirectory(this.root);
        } catch (error) {
          return this.commitUnknown(
            "Approval contention durability is unknown",
            error,
          );
        }
        if (target.grant.grantId === grant.grantId) {
          await this.refresh();
          if (
            [...this.grants.values()].filter(
              (entry) => entry.grant.grantId === grant.grantId,
            ).length !== 1
          )
            return this.commitUnknown("Approval UUID collision is ambiguous");
          await this.cleanupDirectoryBeforeCommit(
            pendingPath,
            pendingMetadata,
            recordMetadata,
            bytes,
          );
          return "uuid_collision";
        }
        if (!syscallError || !isExpectedContention(syscallError))
          return this.commitUnknown(
            "Approval rename contention is indeterminate",
          );
        return "contention";
      } finally {
        zeroBuffer(target.grantBytes);
      }
    }
    if (source && !target) {
      if (!syscallError)
        return this.commitUnknown("Approval rename result is indeterminate");
      throw normalize(syscallError, "Approval grant rename failed");
    }
    zeroBuffer(target?.grantBytes);
    return this.commitUnknown("Approval grant commit is unknown");
  }

  private async grantHousekeeping(
    pendingPath: string,
    finalPath: string,
    grantId: string,
  ): Promise<void> {
    await this.afterBestEffort(
      "grant_cleanup",
      "durably_committed",
      pendingPath,
      finalPath,
      grantId,
    );
    try {
      await this.durability.syncDirectory(this.root);
      await this.afterBestEffort(
        "grant_housekeeping_synced",
        "durably_committed",
        pendingPath,
        finalPath,
        grantId,
      );
    } catch {
      this.unhealthy = true;
    }
  }

  private async consumeStored(
    stored: StoredGrant,
    proposal: Phase3ProposalSnapshot,
    active: Phase3ApprovalActiveContext,
  ): Promise<Phase3ApprovalGrant> {
    const consumedAt = this.trustedNow();
    validatePhase3ApplyGrant(
      stored.grant,
      proposal,
      { now: consumedAt, signal: active.signal },
      active,
    );
    const core = {
      schemaVersion: 1 as const,
      grantId: stored.grant.grantId,
      grantHmac: stored.grantHmac,
      consumedAt: new Date(consumedAt).toISOString(),
    };
    const envelope = {
      ...core,
      receiptHmac: this.mac(PHASE3_APPROVAL_DOMAINS.receipt, core),
    };
    const bytes = this.envelopeBytes(
      envelope,
      PHASE3_APPROVAL_LIMITS.receiptBytes,
    );
    const finalPath = join(stored.slotPath, "used.json");
    let stage: { path: string; metadata: ApprovalMetadata } | undefined;
    try {
      stage = await this.claimFileStage(
        ".used-stage-",
        PHASE3_APPROVAL_LIMITS.usedStages,
        bytes,
        PHASE3_APPROVAL_LIMITS.receiptBytes,
        "receipt_file_synced",
        finalPath,
        stored.slotPath,
        stored.grant.grantId,
      );
      const preLinkNow = this.trustedNow();
      validatePhase3ApplyGrant(
        stored.grant,
        proposal,
        { now: preLinkNow, signal: active.signal },
        active,
      );
      const result = await this.commitReceipt(
        stage.path,
        stage.metadata,
        bytes,
        stored,
        proposal,
        active,
      );
      if (result === "replayed")
        throw new Phase3ApprovalError(
          "approval_replayed",
          "Approval grant has already been consumed",
        );
      await this.refreshAfterDurable();
      return stored.grant;
    } finally {
      zeroBuffer(bytes);
    }
  }

  private async commitReceipt(
    pendingPath: string,
    pendingMetadata: ApprovalMetadata,
    bytes: Buffer,
    stored: StoredGrant,
    proposal: Phase3ProposalSnapshot,
    active: Phase3ApprovalActiveContext,
  ): Promise<"committed" | "replayed"> {
    const finalPath = join(stored.slotPath, "used.json");
    let state: Phase3ApprovalCommitState = "not_committed";
    let syscallError: unknown;
    await this.after(
      "receipt_pre_commit",
      state,
      pendingPath,
      finalPath,
      stored.grant.grantId,
    );
    validatePhase3ApplyGrant(
      stored.grant,
      proposal,
      { now: this.trustedNow(), signal: active.signal },
      active,
    );
    state = "possibly_committed";
    try {
      await this.filesystem.link(pendingPath, finalPath);
      await this.after(
        "receipt_post_commit",
        state,
        pendingPath,
        finalPath,
        stored.grant.grantId,
      );
    } catch (error) {
      syscallError = error;
    }
    if (syscallError) {
      let finalExists: boolean;
      let sourceMatches: boolean;
      try {
        finalExists = await this.pathExists(finalPath);
        sourceMatches = await this.matchFile(
          pendingPath,
          pendingMetadata,
          bytes,
        );
      } catch (error) {
        return this.commitUnknown(
          "Approval receipt reconciliation observation failed",
          error,
        );
      }
      if (!finalExists && sourceMatches)
        throw normalize(
          syscallError,
          "Approval receipt link failed before commit",
        );
    }
    try {
      await this.durability.syncDirectory(stored.slotPath);
      const refreshed = await this.scanSlot(stored.slotName);
      try {
        if (!refreshed.receipt)
          throw commitUnknown("Approval receipt commit is unknown");
      } finally {
        zeroBuffer(refreshed.grantBytes);
      }
      const finalStable = await this.readStableFile(
        finalPath,
        PHASE3_APPROVAL_LIMITS.receiptBytes,
        true,
      );
      const own =
        sameInode(finalStable.metadata, pendingMetadata) &&
        Buffer.compare(finalStable.bytes, bytes) === 0;
      zeroBuffer(finalStable.bytes);
      state = "durably_committed";
      await this.afterBestEffort(
        "receipt_parent_synced",
        state,
        pendingPath,
        finalPath,
        stored.grant.grantId,
      );
      await this.cleanupFileBestEffort(
        pendingPath,
        pendingMetadata,
        bytes,
        "receipt_cleanup",
        "receipt_housekeeping_synced",
        finalPath,
        stored.slotPath,
        stored.grant.grantId,
      );
      return own ? "committed" : "replayed";
    } catch (error) {
      return this.commitUnknown("Approval receipt commit is unknown", error);
    }
  }

  private async remediateWithCustody(): Promise<Phase3ApprovalRemediationCounts> {
    const acquire = this.acquireExclusiveRootCustody;
    if (!acquire) {
      this.unhealthy = true;
      throw unhealthy("Approval root custody acquisition failed");
    }
    let custody:
      | {
          readonly lease: Phase3ApprovalCustodyLease;
          readonly release: BoundaryMethod;
        }
      | undefined;
    try {
      const candidate = await Reflect.apply(acquire, undefined, [this.root]);
      custody = copyCustodyLease(candidate);
    } catch {
      this.unhealthy = true;
      throw unhealthy("Approval root custody acquisition failed");
    }

    let counts: Phase3ApprovalRemediationCounts | undefined;
    let remediationFailed = false;
    try {
      counts = await this.remediateUnderCustody();
    } catch {
      remediationFailed = true;
    } finally {
      try {
        copyUndefined(await Reflect.apply(custody.release, custody.lease, []));
      } catch {
        remediationFailed = true;
      }
    }
    if (remediationFailed || !counts) {
      this.unhealthy = true;
      throw unhealthy("Approval stale-stage remediation failed");
    }
    return counts;
  }

  private async remediateUnderCustody(): Promise<Phase3ApprovalRemediationCounts> {
    if (this.nativeDurability && process.platform !== "linux")
      throw unhealthy("Native approval durability requires Linux");
    const scanned = await this.scanRemediationOnce();
    let finalScan: RemediationScan | undefined;
    try {
      let rootMetadata = scanned.rootMetadata;
      let rootEntries = [...scanned.rootEntries];
      let headerStages = 0;
      let grantStages = 0;
      let receiptStages = 0;

      for (const stage of scanned.headerStages) {
        const removed = await this.removeRemediationFile(
          stage,
          this.root,
          rootMetadata,
          rootEntries,
          scanned.header
            ? {
                final: scanned.header,
                authenticate: (bytes) => {
                  this.parseHeader(bytes);
                },
                limit: PHASE3_APPROVAL_LIMITS.headerBytes,
              }
            : undefined,
        );
        rootMetadata = removed;
        rootEntries = withoutEntry(rootEntries, stage.name);
        headerStages += 1;
      }

      for (const stage of scanned.grantStages) {
        const removed = await this.removeRemediationGrantStage(
          stage,
          rootMetadata,
          rootEntries,
        );
        rootMetadata = removed;
        rootEntries = withoutEntry(rootEntries, stage.name);
        grantStages += 1;
      }

      for (const slot of scanned.slots) {
        let slotMetadata = slot.metadata;
        let slotEntries = [...slot.children];
        for (const stage of slot.receiptStages) {
          const removed = await this.removeRemediationFile(
            stage,
            slot.path,
            slotMetadata,
            slotEntries,
            slot.receipt
              ? {
                  final: slot.receipt,
                  authenticate: (bytes) => {
                    this.parseReceipt(bytes, slot.grantEnvelope);
                  },
                  limit: PHASE3_APPROVAL_LIMITS.receiptBytes,
                }
              : undefined,
          );
          slotMetadata = removed;
          slotEntries = withoutEntry(slotEntries, stage.name);
          receiptStages += 1;
        }
      }

      if (scanned.header) {
        await this.durability.syncDirectory(this.root);
        for (const slot of scanned.slots)
          await this.durability.syncDirectory(slot.path);
      }
      finalScan = await this.scanRemediationOnce();
      if (!finalScan.header && finalScan.rootEntries.length === 0) {
        await this.durability.syncDirectory(this.root);
        throw unhealthy("Approval header is missing");
      }
      this.assertFinalRemediationScan(
        scanned,
        finalScan,
        rootMetadata,
        rootEntries,
      );
      return Object.freeze({ headerStages, grantStages, receiptStages });
    } finally {
      zeroRemediationScan(finalScan);
      zeroRemediationScan(scanned);
    }
  }

  private async scanRemediationOnce(): Promise<RemediationScan> {
    const buffers: Buffer[] = [];
    try {
      const rootMetadata = await this.assertDirectory(this.root);
      const rootEntries = sortedUniqueDirectoryEntries(
        await this.filesystem.readdir(this.root),
        PHASE3_APPROVAL_LIMITS.rootScanEntries,
        "Approval root topology is unsafe",
      );
      const headerName = rootEntries.includes("header.json");
      const slotNames: string[] = [];
      const headerStageNames: string[] = [];
      const grantStageNames: string[] = [];
      for (const name of rootEntries) {
        if (name === "header.json") continue;
        const headerStage = headerStagePattern.exec(name);
        if (headerStage) {
          headerStageNames.push(name);
          continue;
        }
        const grantStage = grantStagePattern.exec(name);
        if (
          grantStage &&
          Number(grantStage[1]) < PHASE3_APPROVAL_LIMITS.grantStages
        ) {
          grantStageNames.push(name);
          continue;
        }
        const slot = slotPattern.exec(name);
        if (slot && Number(slot[1]) < PHASE3_APPROVAL_LIMITS.slots) {
          slotNames.push(name);
          continue;
        }
        throw unhealthy("Approval root contains an unknown artifact");
      }
      if (!headerName && slotNames.length !== 0)
        throw unhealthy("Approval header is missing");

      let header: RemediationFinal | undefined;
      if (headerName) {
        const stable = await this.readStableFile(
          join(this.root, "header.json"),
          PHASE3_APPROVAL_LIMITS.headerBytes,
          true,
          true,
        );
        buffers.push(stable.bytes);
        this.parseHeader(stable.bytes);
        header = {
          name: "header.json",
          path: join(this.root, "header.json"),
          metadata: stable.metadata,
          bytes: stable.bytes,
        };
      }

      const slots: RemediationSlot[] = [];
      const grantIds = new Set<string>();
      for (const slotName of slotNames) {
        const slot = await this.scanRemediationSlot(slotName, buffers);
        if (grantIds.has(slot.grantEnvelope.grant.grantId))
          throw unhealthy("Approval store contains duplicate grant IDs");
        grantIds.add(slot.grantEnvelope.grant.grantId);
        slots.push(slot);
      }

      const headerStages: RemediationFile[] = [];
      for (const name of headerStageNames) {
        const stage = await this.readRemediationStage(
          this.root,
          name,
          PHASE3_APPROVAL_LIMITS.headerBytes,
          buffers,
        );
        this.authenticatePotentialStage(stage.bytes, (bytes) => {
          this.parseHeader(bytes);
        });
        headerStages.push(stage);
      }
      validateRemediationAliasTopology(
        header,
        headerStages,
        "Approval header link topology is unsafe",
      );

      const grantStages: RemediationGrantStage[] = [];
      for (const name of grantStageNames) {
        const path = join(this.root, name);
        const metadata = await this.assertDirectory(path);
        const children = sortedUniqueDirectoryEntries(
          await this.filesystem.readdir(path),
          1,
          "Approval grant stage topology is unsafe",
        );
        if (children.length === 1 && children[0] !== "grant.json")
          throw unhealthy("Approval grant stage topology is unsafe");
        let grant: RemediationFile | undefined;
        if (children[0] === "grant.json") {
          grant = await this.readRemediationStage(
            path,
            "grant.json",
            PHASE3_APPROVAL_LIMITS.grantBytes,
            buffers,
            false,
          );
          this.authenticatePotentialStage(grant.bytes, (bytes) => {
            this.parseGrant(bytes);
          });
        }
        const after = await this.assertDirectory(path);
        if (!sameNode(metadata, after))
          throw unhealthy("Approval grant stage identity changed");
        grantStages.push({
          name,
          path,
          metadata,
          children,
          ...(grant ? { grant } : {}),
        });
      }

      const rootAfter = await this.assertDirectory(this.root);
      if (!sameNode(rootMetadata, rootAfter))
        throw unhealthy("Approval root identity changed");
      return {
        rootMetadata,
        rootEntries,
        ...(header ? { header } : {}),
        headerStages,
        grantStages,
        slots,
        buffers,
      };
    } catch (error) {
      for (const buffer of buffers) zeroBuffer(buffer);
      throw error;
    }
  }

  private async scanRemediationSlot(
    slotName: string,
    buffers: Buffer[],
  ): Promise<RemediationSlot> {
    const path = join(this.root, slotName);
    const metadata = await this.assertDirectory(path);
    const children = sortedUniqueDirectoryEntries(
      await this.filesystem.readdir(path),
      PHASE3_APPROVAL_LIMITS.slotScanEntries,
      "Approval slot topology is unsafe",
    );
    if (!children.includes("grant.json"))
      throw unhealthy("Approval slot grant is missing");
    for (const name of children)
      if (
        name !== "grant.json" &&
        name !== "used.json" &&
        !usedStagePattern.test(name)
      )
        throw unhealthy("Approval slot contains an unknown artifact");

    const grantStable = await this.readStableFile(
      join(path, "grant.json"),
      PHASE3_APPROVAL_LIMITS.grantBytes,
      false,
      true,
    );
    buffers.push(grantStable.bytes);
    const grantEnvelope = this.parseGrant(grantStable.bytes);
    const grant: RemediationFinal = {
      name: "grant.json",
      path: join(path, "grant.json"),
      metadata: grantStable.metadata,
      bytes: grantStable.bytes,
    };

    let receipt: RemediationFinal | undefined;
    if (children.includes("used.json")) {
      const stable = await this.readStableFile(
        join(path, "used.json"),
        PHASE3_APPROVAL_LIMITS.receiptBytes,
        true,
        true,
      );
      buffers.push(stable.bytes);
      this.parseReceipt(stable.bytes, grantEnvelope);
      receipt = {
        name: "used.json",
        path: join(path, "used.json"),
        metadata: stable.metadata,
        bytes: stable.bytes,
      };
    }

    const receiptStages: RemediationFile[] = [];
    for (const name of children.filter((entry) =>
      usedStagePattern.test(entry),
    )) {
      const stage = await this.readRemediationStage(
        path,
        name,
        PHASE3_APPROVAL_LIMITS.receiptBytes,
        buffers,
      );
      this.authenticatePotentialStage(stage.bytes, (bytes) => {
        this.parseReceipt(bytes, grantEnvelope);
      });
      receiptStages.push(stage);
    }
    validateRemediationAliasTopology(
      receipt,
      receiptStages,
      "Approval receipt link topology is unsafe",
    );
    const after = await this.assertDirectory(path);
    if (!sameNode(metadata, after))
      throw unhealthy("Approval slot identity changed");
    return {
      name: slotName,
      path,
      metadata,
      children,
      grant,
      grantEnvelope,
      ...(receipt ? { receipt } : {}),
      receiptStages,
    };
  }

  private async readRemediationStage(
    parent: string,
    name: string,
    limit: number,
    buffers: Buffer[],
    allowLinked = true,
  ): Promise<RemediationFile> {
    const path = join(parent, name);
    const stable = await this.readStableFile(path, limit, allowLinked, true);
    buffers.push(stable.bytes);
    return { name, path, metadata: stable.metadata, bytes: stable.bytes };
  }

  private authenticatePotentialStage(
    bytes: Buffer,
    authenticate: (bytes: Buffer) => void,
  ): void {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw unhealthy("Approval stage encoding is unsafe");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      throw unhealthy("Approval stage content is unsafe");
    authenticate(bytes);
  }

  private async removeRemediationFile(
    stage: RemediationFile,
    parentPath: string,
    parentMetadata: ApprovalMetadata,
    parentEntries: readonly string[],
    linkedFinal:
      | {
          readonly final: RemediationFinal;
          readonly authenticate: (bytes: Buffer) => void;
          readonly limit: number;
        }
      | undefined,
  ): Promise<ApprovalMetadata> {
    await this.proveRemediationParent(
      parentPath,
      parentMetadata,
      parentEntries,
    );
    await this.assertExactFile(stage.path, stage.metadata, stage.bytes, true);
    await this.removeExactRemediationFile(stage);
    await this.durability.syncDirectory(parentPath);
    const remainingEntries = withoutEntry(parentEntries, stage.name);
    const refreshed = await this.refreshRemediationParent(
      parentPath,
      parentMetadata,
      remainingEntries,
    );
    if (stage.metadata.nlink === 2n) {
      if (
        !linkedFinal ||
        linkedFinal.final.metadata.nlink !== 2n ||
        !sameInode(stage.metadata, linkedFinal.final.metadata)
      )
        throw unhealthy("Approval linked stage topology changed");
      const stable = await this.readStableFile(
        linkedFinal.final.path,
        linkedFinal.limit,
        true,
        true,
      );
      try {
        linkedFinal.authenticate(stable.bytes);
        if (
          stable.metadata.nlink !== 1n ||
          !sameImmutableNode(linkedFinal.final.metadata, stable.metadata) ||
          linkedFinal.final.metadata.size !== stable.metadata.size ||
          Buffer.compare(linkedFinal.final.bytes, stable.bytes) !== 0
        )
          throw unhealthy("Approval linked final changed during remediation");
        linkedFinal.final.metadata = stable.metadata;
      } finally {
        zeroBuffer(stable.bytes);
      }
    }
    return refreshed;
  }

  private async removeRemediationGrantStage(
    stage: RemediationGrantStage,
    rootMetadata: ApprovalMetadata,
    rootEntries: readonly string[],
  ): Promise<ApprovalMetadata> {
    await this.proveRemediationParent(this.root, rootMetadata, rootEntries);
    const stageHandle = await this.filesystem.open(
      stage.path,
      constants.O_RDONLY |
        (constants.O_DIRECTORY ?? 0) |
        (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = await stageHandle.stat({ bigint: true });
      if (!sameNode(stage.metadata, opened))
        throw unhealthy("Approval grant stage identity changed");
      let stageMetadata = await this.proveRemediationParent(
        stage.path,
        stage.metadata,
        stage.children,
        true,
      );
      let stageEntries = [...stage.children];
      if (stage.grant) {
        await this.assertExactFile(
          stage.grant.path,
          stage.grant.metadata,
          stage.grant.bytes,
          true,
        );
        await this.removeExactRemediationFile(stage.grant);
        await this.durability.syncDirectory(stage.path);
        stageEntries = [];
        stageMetadata = await this.refreshRemediationParent(
          stage.path,
          stageMetadata,
          stageEntries,
        );
      }
      const held = await stageHandle.stat({ bigint: true });
      if (!sameImmutableNode(stageMetadata, held))
        throw unhealthy("Approval grant stage identity changed");
      await this.proveRemediationParent(
        stage.path,
        stageMetadata,
        stageEntries,
      );
      await this.removeExactRemediationDirectory(
        stage.path,
        stageMetadata,
        stageEntries,
      );
      await this.durability.syncDirectory(this.root);
      return await this.refreshRemediationParent(
        this.root,
        rootMetadata,
        withoutEntry(rootEntries, stage.name),
      );
    } finally {
      await stageHandle.close();
    }
  }

  private async removeExactRemediationFile(
    stage: RemediationFile,
  ): Promise<void> {
    let failure: unknown;
    try {
      await this.filesystem.rm(stage.path, { force: false });
    } catch (error) {
      failure = error;
    }
    const observation = await this.observeRemediationFile(stage);
    if (observation === "absent") return;
    if (observation === "unchanged" && failure) throw failure;
    if (observation === "unchanged")
      throw unhealthy("Approval stage removal had no effect");
    throw unhealthy("Approval stage changed during removal");
  }

  private async observeRemediationFile(
    stage: RemediationFile,
  ): Promise<"absent" | "unchanged" | "changed"> {
    let stable: StableFile;
    try {
      stable = await this.readStableFile(
        stage.path,
        stage.bytes.byteLength,
        stage.metadata.nlink === 2n,
        true,
      );
    } catch (error) {
      if (errno(error) === "ENOENT") return "absent";
      throw error;
    }
    try {
      return sameNode(stage.metadata, stable.metadata) &&
        Buffer.compare(stage.bytes, stable.bytes) === 0
        ? "unchanged"
        : "changed";
    } finally {
      zeroBuffer(stable.bytes);
    }
  }

  private async removeExactRemediationDirectory(
    path: string,
    metadata: ApprovalMetadata,
    entries: readonly string[],
  ): Promise<void> {
    let failure: unknown;
    try {
      await this.filesystem.rmdir(path);
    } catch (error) {
      failure = error;
    }
    const observation = await this.observeRemediationDirectory(
      path,
      metadata,
      entries,
    );
    if (observation === "absent") return;
    if (observation === "unchanged" && failure) throw failure;
    if (observation === "unchanged")
      throw unhealthy("Approval grant stage removal had no effect");
    throw unhealthy("Approval grant stage changed during removal");
  }

  private async observeRemediationDirectory(
    path: string,
    metadata: ApprovalMetadata,
    entries: readonly string[],
  ): Promise<"absent" | "unchanged" | "changed"> {
    let current: ApprovalMetadata;
    try {
      current = await this.assertDirectory(path);
    } catch (error) {
      if (errno(error) === "ENOENT") return "absent";
      throw error;
    }
    const currentEntries = sortedUniqueDirectoryEntries(
      await this.filesystem.readdir(path),
      entries.length,
      "Approval grant stage topology changed",
    );
    return sameNode(metadata, current) && equalStrings(entries, currentEntries)
      ? "unchanged"
      : "changed";
  }

  private async proveRemediationParent(
    path: string,
    metadata: ApprovalMetadata,
    entries: readonly string[],
    exactNode = false,
  ): Promise<ApprovalMetadata> {
    const before = await this.assertDirectory(path);
    if (
      !(exactNode
        ? sameNode(metadata, before)
        : sameImmutableNode(metadata, before))
    )
      throw unhealthy("Approval remediation parent identity changed");
    const currentEntries = sortedUniqueDirectoryEntries(
      await this.filesystem.readdir(path),
      entries.length,
      "Approval remediation parent topology changed",
    );
    if (!equalStrings(entries, currentEntries))
      throw unhealthy("Approval remediation parent topology changed");
    const after = await this.assertDirectory(path);
    if (!sameImmutableNode(before, after))
      throw unhealthy("Approval remediation parent identity changed");
    return after;
  }

  private async refreshRemediationParent(
    path: string,
    previous: ApprovalMetadata,
    entries: readonly string[],
  ): Promise<ApprovalMetadata> {
    const refreshed = await this.assertDirectory(path);
    if (!sameImmutableNode(previous, refreshed))
      throw unhealthy("Approval remediation parent identity changed");
    const currentEntries = sortedUniqueDirectoryEntries(
      await this.filesystem.readdir(path),
      entries.length,
      "Approval remediation parent topology changed",
    );
    if (!equalStrings(entries, currentEntries))
      throw unhealthy("Approval remediation parent topology changed");
    const after = await this.assertDirectory(path);
    if (!sameImmutableNode(refreshed, after))
      throw unhealthy("Approval remediation parent identity changed");
    return after;
  }

  private assertFinalRemediationScan(
    initial: RemediationScan,
    final: RemediationScan,
    rootMetadata: ApprovalMetadata,
    rootEntries: readonly string[],
  ): void {
    if (
      final.headerStages.length !== 0 ||
      final.grantStages.length !== 0 ||
      final.slots.some((slot) => slot.receiptStages.length !== 0) ||
      !sameImmutableNode(rootMetadata, final.rootMetadata) ||
      !equalStrings(rootEntries, final.rootEntries)
    )
      throw unhealthy("Approval remediation final topology is unsafe");
    compareRemediationFinal(initial.header, final.header);
    if (initial.slots.length !== final.slots.length)
      throw unhealthy("Approval remediation final slot topology changed");
    for (let index = 0; index < initial.slots.length; index += 1) {
      const before = initial.slots[index];
      const after = final.slots[index];
      if (
        !before ||
        !after ||
        before.name !== after.name ||
        !sameImmutableNode(before.metadata, after.metadata)
      )
        throw unhealthy("Approval remediation final slot identity changed");
      compareRemediationFinal(before.grant, after.grant);
      compareRemediationFinal(before.receipt, after.receipt);
    }
  }

  private async refresh(): Promise<void> {
    try {
      const scanned = await this.scan();
      if (!scanned.header) {
        this.zeroScanned(scanned);
        throw unhealthy("Approval header is missing");
      }
      this.replaceScanned(scanned);
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Approval refresh failed");
    }
  }

  private async refreshAfterDurable(): Promise<void> {
    try {
      const scanned = await this.scan();
      if (!scanned.header) {
        this.zeroScanned(scanned);
        throw unhealthy("Approval header is missing");
      }
      this.replaceScanned(scanned);
    } catch {
      this.unhealthy = true;
    }
  }

  private replaceScanned(scanned: ScannedStore): void {
    for (const stored of this.grants.values()) zeroBuffer(stored.grantBytes);
    this.header = scanned.header;
    this.grants = scanned.grants;
  }

  private zeroScanned(scanned: ScannedStore): void {
    for (const stored of scanned.grants.values()) zeroBuffer(stored.grantBytes);
  }

  private async scan(): Promise<ScannedStore> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.scanOnce();
      } catch (error) {
        lastError = error;
      }
    }
    throw normalize(lastError, "Approval store scan did not stabilize");
  }

  private async scanOnce(): Promise<ScannedStore> {
    await this.assertDirectory(this.root);
    const names = (await this.filesystem.readdir(this.root)).sort();
    if (names.length > PHASE3_APPROVAL_LIMITS.rootScanEntries)
      throw unhealthy("Approval root scan limit exceeded");
    const slots = new Set<string>();
    const grants = new Map<string, StoredGrant>();
    const headerStages: ApprovalMetadata[] = [];
    let header: HeaderEnvelope | undefined;
    let headerMetadata: ApprovalMetadata | undefined;
    try {
      for (const name of names) {
        const path = join(this.root, name);
        if (name === "header.json") {
          const read = await this.readHeader(path);
          header = read.envelope;
          headerMetadata = read.metadata;
          continue;
        }
        if (headerStagePattern.test(name)) {
          const metadata = await this.assertFile(path, true);
          if (metadata.size > BigInt(PHASE3_APPROVAL_LIMITS.headerBytes))
            throw unhealthy("Approval header stage exceeds size limit");
          headerStages.push(metadata);
          continue;
        }
        const grantStageMatch = grantStagePattern.exec(name);
        if (
          grantStageMatch &&
          Number(grantStageMatch[1]) < PHASE3_APPROVAL_LIMITS.grantStages
        ) {
          await this.validateGrantStage(path);
          continue;
        }
        const slotMatch = slotPattern.exec(name);
        const slotNumber = slotMatch ? Number(slotMatch[1]) : -1;
        if (
          !slotMatch ||
          slotNumber < 0 ||
          slotNumber >= PHASE3_APPROVAL_LIMITS.slots
        )
          throw unhealthy("Approval root contains an unknown artifact");
        const stored = await this.scanSlot(name);
        if (grants.has(stored.grant.grantId)) {
          zeroBuffer(stored.grantBytes);
          throw unhealthy("Approval store contains duplicate grant IDs");
        }
        grants.set(stored.grant.grantId, stored);
        slots.add(name);
      }
      this.validateLinkedStage(
        headerMetadata,
        headerStages,
        "Approval header link topology is unsafe",
      );
      return { ...(header ? { header } : {}), grants, slots };
    } catch (error) {
      for (const stored of grants.values()) zeroBuffer(stored.grantBytes);
      throw error;
    }
  }

  private async readHeader(
    path: string,
  ): Promise<{ envelope: HeaderEnvelope; metadata: ApprovalMetadata }> {
    const stable = await this.readStableFile(
      path,
      PHASE3_APPROVAL_LIMITS.headerBytes,
      true,
    );
    try {
      const envelope = this.parseHeader(stable.bytes);
      return { envelope, metadata: stable.metadata };
    } finally {
      zeroBuffer(stable.bytes);
    }
  }

  private async validateGrantStage(path: string): Promise<void> {
    const before = await this.assertDirectory(path);
    const children = (await this.filesystem.readdir(path)).sort();
    if (
      children.length > 1 ||
      (children.length === 1 && children[0] !== "grant.json")
    )
      throw unhealthy("Approval grant stage topology is unsafe");
    if (children[0] === "grant.json") {
      const metadata = await this.assertFile(join(path, "grant.json"));
      if (metadata.size > BigInt(PHASE3_APPROVAL_LIMITS.grantBytes))
        throw unhealthy("Approval grant stage exceeds size limit");
    }
    const after = await this.assertDirectory(path);
    if (!sameNode(before, after))
      throw unhealthy("Approval grant stage identity changed");
  }

  private async scanSlot(slotName: string): Promise<StoredGrant> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.scanSlotOnce(slotName);
      } catch (error) {
        lastError = error;
      }
    }
    if (errno(lastError) === "ENOENT") throw lastError;
    throw normalize(lastError, "Approval slot scan did not stabilize");
  }

  private async scanSlotOnce(slotName: string): Promise<StoredGrant> {
    const slotPath = join(this.root, slotName);
    const slotMetadata = await this.assertDirectory(slotPath);
    const children = (await this.filesystem.readdir(slotPath)).sort();
    if (children.length > PHASE3_APPROVAL_LIMITS.slotScanEntries)
      throw unhealthy("Approval slot scan limit exceeded");
    if (!children.includes("grant.json"))
      throw unhealthy("Approval slot grant is missing");
    const allowed = new Set([
      "grant.json",
      "used.json",
      ".used-stage-0",
      ".used-stage-1",
      ".used-stage-2",
      ".used-stage-3",
    ]);
    if (children.some((name) => !allowed.has(name)))
      throw unhealthy("Approval slot contains an unknown artifact");
    const grantStable = await this.readStableFile(
      join(slotPath, "grant.json"),
      PHASE3_APPROVAL_LIMITS.grantBytes,
      false,
    );
    let transferGrantBytes = false;
    try {
      const grantEnvelope = this.parseGrant(grantStable.bytes);
      const usedStages: ApprovalMetadata[] = [];
      for (const child of children.filter((name) =>
        usedStagePattern.test(name),
      )) {
        let metadata: ApprovalMetadata;
        try {
          metadata = await this.assertFile(join(slotPath, child), true);
        } catch (error) {
          if (errno(error) === "ENOENT") continue;
          throw error;
        }
        if (metadata.size > BigInt(PHASE3_APPROVAL_LIMITS.receiptBytes))
          throw unhealthy("Approval receipt stage exceeds size limit");
        usedStages.push(metadata);
      }
      let receipt: ReceiptEnvelope | undefined;
      let receiptMetadata: ApprovalMetadata | undefined;
      if (children.includes("used.json")) {
        const stable = await this.readStableFile(
          join(slotPath, "used.json"),
          PHASE3_APPROVAL_LIMITS.receiptBytes,
          true,
        );
        try {
          receipt = this.parseReceipt(stable.bytes, grantEnvelope);
          receiptMetadata = stable.metadata;
        } finally {
          zeroBuffer(stable.bytes);
        }
      }
      this.validateLinkedStage(
        receiptMetadata,
        usedStages,
        "Approval receipt link topology is unsafe",
      );
      const slotAfter = await this.assertDirectory(slotPath);
      if (!sameDirectoryIdentity(slotMetadata, slotAfter))
        throw unhealthy("Approval slot identity changed");
      const stored = {
        slotName,
        slotPath,
        slotMetadata,
        grant: Object.freeze(grantEnvelope.grant),
        grantHmac: grantEnvelope.grantHmac,
        grantMetadata: grantStable.metadata,
        grantBytes: grantStable.bytes,
        ...(receipt ? { receipt } : {}),
      };
      transferGrantBytes = true;
      return stored;
    } finally {
      if (!transferGrantBytes) {
        zeroBuffer(grantStable.bytes);
      }
    }
  }

  private validateLinkedStage(
    finalMetadata: ApprovalMetadata | undefined,
    stages: readonly ApprovalMetadata[],
    message: string,
  ): void {
    for (const stage of stages) {
      if (stage.nlink === 1n) continue;
      if (
        stage.nlink !== 2n ||
        !finalMetadata ||
        !sameInode(stage, finalMetadata)
      )
        throw unhealthy(message);
    }
    if (finalMetadata?.nlink === 2n) {
      const matches = stages.filter((stage) => sameInode(stage, finalMetadata));
      if (matches.length !== 1) throw unhealthy(message);
    }
  }

  private parseHeader(bytes: Buffer): HeaderEnvelope {
    const parsed = this.parseCanonical(bytes, headerEnvelopeSchema);
    const core = {
      schemaVersion: parsed.schemaVersion,
      storeId: parsed.storeId,
      keyId: parsed.keyId,
    };
    const expectedKeyId = this.mac(
      PHASE3_APPROVAL_DOMAINS.keyId,
      keyIdCoreSchema.parse({
        schemaVersion: 1,
        purpose: "phase3_approval_key_identity",
      }),
    );
    if (parsed.keyId !== expectedKeyId)
      throw unhealthy("Approval header key identity does not match");
    this.verifyMac(PHASE3_APPROVAL_DOMAINS.header, core, parsed.headerHmac);
    return Object.freeze(parsed);
  }

  private parseGrant(bytes: Buffer): GrantEnvelope {
    const parsed = this.parseCanonical(bytes, grantEnvelopeSchema);
    const core = { schemaVersion: parsed.schemaVersion, grant: parsed.grant };
    this.verifyMac(PHASE3_APPROVAL_DOMAINS.grant, core, parsed.grantHmac);
    return Object.freeze({ ...parsed, grant: Object.freeze(parsed.grant) });
  }

  private parseReceipt(bytes: Buffer, grant: GrantEnvelope): ReceiptEnvelope {
    const parsed = this.parseCanonical(bytes, receiptEnvelopeSchema);
    const core = {
      schemaVersion: parsed.schemaVersion,
      grantId: parsed.grantId,
      grantHmac: parsed.grantHmac,
      consumedAt: parsed.consumedAt,
    };
    this.verifyMac(PHASE3_APPROVAL_DOMAINS.receipt, core, parsed.receiptHmac);
    const consumedAt = Date.parse(parsed.consumedAt);
    if (
      parsed.grantId !== grant.grant.grantId ||
      parsed.grantHmac !== grant.grantHmac ||
      consumedAt < Date.parse(grant.grant.issuedAt) ||
      consumedAt >= Date.parse(grant.grant.expiresAt)
    )
      throw unhealthy("Approval receipt binding is invalid");
    return Object.freeze(parsed);
  }

  private parseCanonical<T>(bytes: Buffer, schema: z.ZodType<T>): T {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw unhealthy("Approval artifact encoding is invalid");
    }
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw unhealthy("Approval artifact JSON is invalid");
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success || canonicalJson(parsed.data) !== text)
      throw unhealthy("Approval artifact is noncanonical or invalid");
    return parsed.data;
  }

  private envelopeBytes(value: unknown, limit: number): Buffer {
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    if (bytes.byteLength > limit) {
      zeroBuffer(bytes);
      throw capacity("Approval artifact byte capacity is exhausted");
    }
    return bytes;
  }

  private mac(domain: string, core: unknown): string {
    const record = Buffer.from(canonicalJson(core), "utf8");
    const domainBytes = Buffer.from(domain, "ascii");
    let digest: Buffer | undefined;
    try {
      digest = createHmac("sha256", this.key)
        .update(domainBytes)
        .update(record)
        .digest();
      return digest.toString("hex");
    } finally {
      zeroBuffer(domainBytes);
      zeroBuffer(record);
      zeroBuffer(digest);
    }
  }

  private verifyMac(domain: string, core: unknown, supplied: string): void {
    const expectedHex = this.mac(domain, core);
    const expected = Buffer.from(expectedHex, "hex");
    const actual = Buffer.from(supplied, "hex");
    try {
      if (
        expected.byteLength !== 32 ||
        actual.byteLength !== 32 ||
        !timingSafeEqual(expected, actual)
      )
        throw unhealthy("Approval artifact authentication failed");
    } finally {
      zeroBuffer(expected);
      zeroBuffer(actual);
    }
  }

  private async claimGrantStage(): Promise<{
    path: string;
    metadata: ApprovalMetadata;
  }> {
    for (
      let index = 0;
      index < PHASE3_APPROVAL_LIMITS.grantStages;
      index += 1
    ) {
      const path = join(
        this.root,
        ".grant-stage-" + String(index).padStart(2, "0"),
      );
      try {
        await this.filesystem.mkdir(path, { mode: 0o700 });
        return { path, metadata: await this.assertDirectory(path) };
      } catch (error) {
        if (errno(error) !== "EEXIST") throw error;
      }
    }
    throw capacity("Approval grant stage capacity is exhausted");
  }

  private async claimFileStage(
    prefix: string,
    count: number,
    bytes: Buffer,
    limit: number,
    stage: Phase3ApprovalHookStage,
    finalPath: string,
    parent = this.root,
    grantId?: string,
  ): Promise<{ path: string; metadata: ApprovalMetadata }> {
    for (let index = 0; index < count; index += 1) {
      const path = join(parent, prefix + index);
      try {
        const metadata = await this.writeExclusiveFile(path, bytes, limit);
        await this.after(stage, "not_committed", path, finalPath, grantId);
        return { path, metadata };
      } catch (error) {
        if (errno(error) !== "EEXIST") throw error;
      }
    }
    throw capacity("Approval fixed stage capacity is exhausted");
  }

  private async writeExclusiveFile(
    path: string,
    bytes: Buffer,
    limit: number,
  ): Promise<ApprovalMetadata> {
    if (bytes.byteLength > limit)
      throw capacity("Approval artifact byte capacity is exhausted");
    const handle = await this.filesystem.open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    let metadata: ApprovalMetadata;
    try {
      await writeAll(handle, bytes);
      await handle.sync();
      metadata = await handle.stat({ bigint: true });
    } finally {
      await handle.close();
    }
    await this.assertExactFile(path, metadata, bytes);
    return metadata;
  }

  private async readStableFile(
    path: string,
    limit: number,
    allowLinked: boolean,
    strictIdentity = false,
  ): Promise<StableFile> {
    const before = await this.assertFile(path, allowLinked);
    if (before.size > BigInt(limit))
      throw unhealthy("Approval artifact exceeds size limit");
    const handle = await this.filesystem.open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    let bytes: Buffer | undefined;
    let result: StableFile | undefined;
    let failure: { error: unknown } | undefined;
    try {
      const opened = await handle.stat({ bigint: true });
      if (!sameReadableFile(before, opened, allowLinked, strictIdentity))
        throw unhealthy("Approval artifact identity changed");
      bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      const linked = await this.filesystem.lstat(path, { bigint: true });
      if (
        bytes.byteLength > limit ||
        !sameReadableFile(opened, after, allowLinked, strictIdentity) ||
        !sameReadableFile(opened, linked, allowLinked, strictIdentity) ||
        opened.size !== BigInt(bytes.byteLength)
      )
        throw unhealthy("Approval artifact changed during read");
      result = { metadata: opened, bytes };
    } catch (error) {
      failure = { error };
    }
    try {
      await handle.close();
    } catch (error) {
      if (!failure) failure = { error };
    }
    if (failure) {
      zeroBuffer(bytes);
      throw failure.error;
    }
    if (!result) throw unhealthy("Approval stable read failed");
    return result;
  }

  private async assertExactFile(
    path: string,
    expectedMetadata: ApprovalMetadata,
    expectedBytes: Buffer,
    strictIdentity = false,
  ): Promise<void> {
    const stable = await this.readStableFile(
      path,
      expectedBytes.byteLength,
      expectedMetadata.nlink === 2n,
      strictIdentity,
    );
    try {
      if (
        !sameNode(expectedMetadata, stable.metadata) ||
        Buffer.compare(expectedBytes, stable.bytes) !== 0
      )
        throw unhealthy("Approval stage identity or content changed");
    } finally {
      zeroBuffer(stable.bytes);
    }
  }

  private async assertDirectory(path: string): Promise<ApprovalMetadata> {
    const metadata = await this.filesystem.lstat(path, { bigint: true });
    if (
      !metadata.isDirectory ||
      metadata.nlink < 1n ||
      !this.durability.privateMode(metadata.mode) ||
      !privateOwner(metadata)
    )
      throw unhealthy("Approval directory is unsafe");
    return metadata;
  }

  private async assertFile(
    path: string,
    allowLinked = false,
  ): Promise<ApprovalMetadata> {
    const metadata = await this.filesystem.lstat(path, { bigint: true });
    if (
      !metadata.isFile ||
      (metadata.nlink !== 1n && (!allowLinked || metadata.nlink !== 2n)) ||
      !this.durability.privateMode(metadata.mode) ||
      !privateOwner(metadata)
    )
      throw unhealthy("Approval file is unsafe");
    return metadata;
  }

  private slotOccupied(slotName: string): boolean {
    for (const stored of this.grants.values())
      if (stored.slotName === slotName) return true;
    return false;
  }

  private async tryReadSlot(
    slotName: string,
  ): Promise<StoredGrant | undefined> {
    try {
      return await this.scanSlot(slotName);
    } catch (error) {
      if (errno(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  private async matchDirectory(
    path: string,
    directoryMetadata: ApprovalMetadata,
    recordMetadata: ApprovalMetadata,
    bytes: Buffer,
  ): Promise<boolean> {
    try {
      const current = await this.assertDirectory(path);
      if (!sameDirectoryIdentity(directoryMetadata, current)) return false;
      await this.assertExactFile(
        join(path, "grant.json"),
        recordMetadata,
        bytes,
      );
      return true;
    } catch (error) {
      if (errno(error) === "ENOENT") return false;
      throw error;
    }
  }

  private async cleanupDirectoryBeforeCommit(
    path: string,
    directoryMetadata: ApprovalMetadata,
    recordMetadata: ApprovalMetadata | undefined,
    bytes: Buffer,
  ): Promise<void> {
    if (!recordMetadata) return;
    if (
      !(await this.matchDirectory(
        path,
        directoryMetadata,
        recordMetadata,
        bytes,
      ))
    )
      return;
    await this.filesystem.rm(path, { recursive: true, force: true });
  }

  private async cleanupFileBestEffort(
    path: string,
    metadata: ApprovalMetadata,
    bytes: Buffer,
    cleanupStage: Phase3ApprovalHookStage,
    housekeepingStage: Phase3ApprovalHookStage,
    finalPath: string,
    parent = this.root,
    grantId?: string,
  ): Promise<void> {
    try {
      if (!(await this.matchFile(path, metadata, bytes))) return;
      await this.filesystem.rm(path, { force: true });
      await this.afterBestEffort(
        cleanupStage,
        "durably_committed",
        path,
        finalPath,
        grantId,
      );
      try {
        await this.durability.syncDirectory(parent);
        await this.afterBestEffort(
          housekeepingStage,
          "durably_committed",
          path,
          finalPath,
          grantId,
        );
      } catch {
        this.unhealthy = true;
      }
    } catch {
      // A valid owned stage may remain after the durable commit.
    }
  }

  private async matchFile(
    path: string,
    metadata: ApprovalMetadata,
    bytes: Buffer,
  ): Promise<boolean> {
    try {
      const stable = await this.readStableFile(path, bytes.byteLength, true);
      try {
        return (
          sameInode(metadata, stable.metadata) &&
          metadata.mode === stable.metadata.mode &&
          metadata.uid === stable.metadata.uid &&
          metadata.gid === stable.metadata.gid &&
          Buffer.compare(bytes, stable.bytes) === 0
        );
      } finally {
        zeroBuffer(stable.bytes);
      }
    } catch (error) {
      if (errno(error) === "ENOENT") return false;
      throw error;
    }
  }

  private async pathExists(path: string): Promise<boolean> {
    try {
      await this.filesystem.lstat(path, { bigint: true });
      return true;
    } catch (error) {
      if (errno(error) === "ENOENT") return false;
      throw error;
    }
  }

  private async after(
    stage: Phase3ApprovalHookStage,
    commitState: Phase3ApprovalCommitState,
    pendingPath: string,
    finalPath: string,
    grantId?: string,
  ): Promise<void> {
    try {
      const result = await this.hooks.afterStage?.({
        stage,
        commitState,
        root: this.root,
        pendingPath,
        finalPath,
        ...(grantId ? { grantId } : {}),
      });
      if (result !== undefined) throw new Error("invalid hook result");
    } catch (error) {
      const failure = unhealthy("Approval lifecycle hook failed");
      if (retainStage(error)) markRetainedStage(failure);
      throw failure;
    }
  }

  private async afterBestEffort(
    stage: Phase3ApprovalHookStage,
    commitState: Phase3ApprovalCommitState,
    pendingPath: string,
    finalPath: string,
    grantId?: string,
  ): Promise<void> {
    try {
      await this.after(stage, commitState, pendingPath, finalPath, grantId);
    } catch {
      // Hooks after containing-directory sync cannot change a durable result.
    }
  }

  private commitUnknown(message: string, cause?: unknown): never {
    this.unhealthy = true;
    throw commitUnknown(message, cause);
  }

  private publicFailure(error: unknown, message: string): Phase3ApprovalError {
    const failure = normalize(error, message);
    this.latchIfStoreFailure(failure);
    return failure;
  }

  private latchIfStoreFailure(error: unknown): void {
    if (
      !(error instanceof Phase3ApprovalError) ||
      error.code === "approval_store_unhealthy" ||
      error.code === "approval_commit_unknown"
    )
      this.unhealthy = true;
  }
}

async function writeAll(
  handle: TrustedPhase3ApprovalFileHandle,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      offset,
    );
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0)
      throw unhealthy("Approval stage write made no progress");
    offset += bytesWritten;
  }
}

function sameInode(left: ApprovalMetadata, right: ApprovalMetadata): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameDirectoryIdentity(
  left: ApprovalMetadata,
  right: ApprovalMetadata,
): boolean {
  return (
    sameInode(left, right) &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid
  );
}

function sameReadableFile(
  left: ApprovalMetadata,
  right: ApprovalMetadata,
  allowLinked: boolean,
  strictIdentity = false,
): boolean {
  const readable =
    sameInode(left, right) &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    (allowLinked
      ? (left.nlink === 1n || left.nlink === 2n) &&
        (right.nlink === 1n || right.nlink === 2n)
      : left.nlink === 1n && right.nlink === 1n);
  return readable && (!strictIdentity || sameNode(left, right));
}

function sameNode(left: ApprovalMetadata, right: ApprovalMetadata): boolean {
  return (
    sameInode(left, right) &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function sameImmutableNode(
  left: ApprovalMetadata,
  right: ApprovalMetadata,
): boolean {
  return (
    sameInode(left, right) &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.isFile === right.isFile &&
    left.isDirectory === right.isDirectory
  );
}

function sortedUniqueDirectoryEntries(
  entries: readonly string[],
  limit: number,
  message: string,
): string[] {
  if (entries.length > limit) throw unhealthy(message);
  const sorted = [...entries].sort();
  for (let index = 1; index < sorted.length; index += 1)
    if (sorted[index - 1] === sorted[index]) throw unhealthy(message);
  return sorted;
}

function equalStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function withoutEntry(entries: readonly string[], removed: string): string[] {
  const result = entries.filter((entry) => entry !== removed);
  if (result.length !== entries.length - 1)
    throw unhealthy("Approval remediation topology changed");
  return result;
}

function validateRemediationAliasTopology(
  final: RemediationFinal | undefined,
  stages: readonly RemediationFile[],
  message: string,
): void {
  for (const stage of stages) {
    const aliasesFinal = final
      ? sameInode(stage.metadata, final.metadata)
      : false;
    if (stage.metadata.nlink === 1n) {
      if (aliasesFinal) throw unhealthy(message);
      continue;
    }
    if (
      stage.metadata.nlink !== 2n ||
      !final ||
      final.metadata.nlink !== 2n ||
      !aliasesFinal ||
      !sameImmutableNode(stage.metadata, final.metadata) ||
      Buffer.compare(stage.bytes, final.bytes) !== 0
    )
      throw unhealthy(message);
  }
  if (final?.metadata.nlink === 2n) {
    const aliases = stages.filter((stage) =>
      sameInode(stage.metadata, final.metadata),
    );
    if (aliases.length !== 1 || aliases[0]?.metadata.nlink !== 2n)
      throw unhealthy(message);
  }
}

function compareRemediationFinal(
  expected: RemediationFinal | undefined,
  actual: RemediationFinal | undefined,
): void {
  if (!expected && !actual) return;
  if (
    !expected ||
    !actual ||
    expected.name !== actual.name ||
    !sameNode(expected.metadata, actual.metadata) ||
    Buffer.compare(expected.bytes, actual.bytes) !== 0
  )
    throw unhealthy("Approval final artifact changed during remediation");
}

function zeroRemediationScan(scan: RemediationScan | undefined): void {
  if (!scan) return;
  for (const buffer of scan.buffers) zeroBuffer(buffer);
}

function privateOwner(metadata: ApprovalMetadata): boolean {
  return (
    typeof process.getuid !== "function" ||
    metadata.uid === BigInt(process.getuid())
  );
}

function errno(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

function isExpectedContention(error: unknown): boolean {
  const code = errno(error);
  return (
    code === "EEXIST" ||
    code === "ENOTEMPTY" ||
    (process.platform === "win32" && code === "EPERM")
  );
}

function retainStage(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  try {
    const descriptor = Reflect.getOwnPropertyDescriptor(
      error,
      "retainPhase3ApprovalStage",
    );
    return (
      retainedStageErrors.has(error) &&
      descriptor !== undefined &&
      "value" in descriptor &&
      descriptor.value === true &&
      descriptor.configurable === false &&
      descriptor.writable === false
    );
  } catch {
    return false;
  }
}

function isCapacity(error: unknown): boolean {
  return (
    error instanceof Phase3ApprovalError &&
    error.code === "approval_capacity_exhausted"
  );
}

function isCommitUnknown(error: unknown): boolean {
  return (
    error instanceof Phase3ApprovalError &&
    error.code === "approval_commit_unknown"
  );
}

function capacity(message: string): Phase3ApprovalError {
  return new Phase3ApprovalError("approval_capacity_exhausted", message);
}

function unhealthy(message: string): Phase3ApprovalError {
  return new Phase3ApprovalError("approval_store_unhealthy", message);
}

function commitUnknown(message: string, cause?: unknown): Phase3ApprovalError {
  void cause;
  return new Phase3ApprovalError("approval_commit_unknown", message);
}

function normalize(error: unknown, message: string): Phase3ApprovalError {
  if (error instanceof Phase3ApprovalError) return error;
  return unhealthy(message);
}
