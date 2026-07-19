import { constants } from "node:fs";
import { lstat, mkdir, open, rename, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";
import {
  phase2AuditRecordSchema,
  type Phase2OperationContext,
  type Phase2ToolName,
} from "../phase2Contracts.js";
import {
  RepositoryBoundaryError,
  assertOperationActive,
} from "../security/repositoryBoundary.js";
import { canonicalJson } from "./storage.js";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "./durability.js";

export const PHASE2_AUDIT_LIMITS = Object.freeze({
  recordBytes: 16 * 1024,
  fileBytes: 4 * 1024 * 1024,
  rotations: 4,
});

export type Phase2AuditRecord = Parameters<
  typeof phase2AuditRecordSchema.parse
>[0];

export interface PendingPhase2AuditAttempt {
  readonly requestId: string;
  readonly operationId: string;
  readonly tool: Phase2ToolName;
}

export interface Phase2AuditHooks {
  readonly checkpoint?: (
    stage:
      | "before_write"
      | "after_write"
      | "after_sync"
      | "after_rotate_rename"
      | "after_rotate_create"
      | "after_rotate_dirsync",
  ) => Promise<void>;
}

function isEintr(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === "EINTR"
  );
}

async function appendAllAuditBytes(
  handle: FileHandle,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    try {
      const { bytesWritten } = await handle.write(
        bytes,
        offset,
        bytes.byteLength - offset,
      );
      if (
        !Number.isSafeInteger(bytesWritten) ||
        bytesWritten <= 0 ||
        bytesWritten > bytes.byteLength - offset
      )
        throw unhealthy("Phase 2 audit write did not make progress");
      offset += bytesWritten;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}
export class Phase2AuditAdapter {
  private chain = Promise.resolve();
  private unhealthy = true;
  private readonly seenAttemptIds = new Set<string>();
  private readonly pendingAttempts = new Map<
    string,
    PendingPhase2AuditAttempt
  >();
  private readonly outcomes = new Set<string>();

  constructor(
    readonly path: string,
    private readonly hooks: Phase2AuditHooks = {},
    private readonly durability: Phase2DurabilityPort = strictPhase2Durability,
  ) {}

  async recover(): Promise<void> {
    this.unhealthy = true;
    this.seenAttemptIds.clear();
    this.pendingAttempts.clear();
    this.outcomes.clear();
    const directory = dirname(this.path);
    try {
      await ensureAuditDirectory(directory, this.durability);
      let rotationCount = 0;
      let gap = false;
      for (let index = 1; index <= PHASE2_AUDIT_LIMITS.rotations; index += 1) {
        if (await fileExists(`${this.path}.${index}`)) {
          if (gap)
            throw unhealthy("Phase 2 audit rotation sequence is ambiguous");
          rotationCount = index;
        } else gap = true;
      }
      if (!(await fileExists(this.path))) {
        const handle = await open(
          this.path,
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
          0o600,
        );
        try {
          await handle.sync();
        } finally {
          await handle.close();
        }
        await this.durability.syncDirectory(directory);
      }
      for (let index = 1; index <= rotationCount; index += 1) {
        const rotated = `${this.path}.${index}`;
        await assertFile(rotated, this.durability);
        await this.recoverFile(rotated, false);
      }
      await assertFile(this.path, this.durability);
      await this.recoverFile(this.path, true);
      this.unhealthy = false;
    } catch (error) {
      throw normalize(error, "Phase 2 audit recovery failed");
    }
  }

  isHealthy(): boolean {
    return !this.unhealthy;
  }
  hasOutcome(operationId: string): boolean {
    return this.outcomes.has(operationId);
  }

  pendingAuditAttempts(): readonly PendingPhase2AuditAttempt[] {
    if (this.unhealthy) throw unhealthy("Phase 2 audit is unhealthy");
    return Object.freeze([...this.pendingAttempts.values()]);
  }

  append(record: unknown, context?: Phase2OperationContext): Promise<void> {
    if (this.unhealthy)
      return Promise.reject(unhealthy("Phase 2 audit is unhealthy"));
    const parsed = phase2AuditRecordSchema.safeParse(record);
    if (!parsed.success) {
      this.unhealthy = true;
      return Promise.reject(unhealthy("Phase 2 audit record is invalid"));
    }

    const bytes = Buffer.from(`${canonicalJson(parsed.data)}\n`, "utf8");
    if (bytes.byteLength > PHASE2_AUDIT_LIMITS.recordBytes) {
      bytes.fill(0);
      this.unhealthy = true;
      return Promise.reject(
        unhealthy("Phase 2 audit record exceeds its boundary"),
      );
    }
    const task = async () => {
      try {
        this.assertCanAcceptRecord(parsed.data);
        if (context) assertOperationActive(context);
        await this.rotateIfNeeded(bytes.byteLength);
        await this.hooks.checkpoint?.("before_write");
        const opened = await openVerified(
          this.path,
          constants.O_APPEND | constants.O_WRONLY,
          this.durability,
        );
        try {
          await appendAllAuditBytes(opened.handle, bytes);
          await this.hooks.checkpoint?.("after_write");
          await opened.handle.sync();
          await this.hooks.checkpoint?.("after_sync");
          await verifyOpened(this.path, opened, this.durability);
        } finally {
          await opened.handle.close();
        }
        await assertPathIdentity(this.path, opened, this.durability);
        this.rememberRecord(parsed.data);
      } catch (error) {
        this.unhealthy = true;
        throw normalize(error, "Phase 2 audit append failed");
      } finally {
        bytes.fill(0);
      }
    };
    const result = this.chain.then(task, task);
    this.chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async recoverFile(
    path: string,
    allowIncompleteTail: boolean,
  ): Promise<void> {
    const bytes = await readAuditFile(path, this.durability);
    try {
      if (bytes.byteLength === 0 && !allowIncompleteTail)
        throw unhealthy("Rotated Phase 2 audit file is ambiguously empty");
      const lastLf = bytes.lastIndexOf(0x0a);
      const prefixEnd = lastLf < 0 ? 0 : lastLf + 1;
      if (prefixEnd > 0) {
        const prefix = new TextDecoder("utf-8", { fatal: true }).decode(
          bytes.subarray(0, prefixEnd),
        );
        const lines = prefix.split("\n");
        lines.pop();
        for (const line of lines) this.acceptLine(line);
      }
      if (prefixEnd === bytes.byteLength) return;
      if (!allowIncompleteTail)
        throw unhealthy("Rotated Phase 2 audit has an incomplete tail");
      const tailBytes = bytes.subarray(prefixEnd);
      let tail: string | undefined;
      try {
        tail = new TextDecoder("utf-8", { fatal: true }).decode(tailBytes);
      } catch {
        if (tailBytes[0] !== 0x7b)
          throw unhealthy("Phase 2 audit tail is not provably incomplete");
      }
      if (tail !== undefined) {
        if (!tail.startsWith("{") || tail.endsWith("}"))
          throw unhealthy("Phase 2 audit tail is not provably incomplete");
        try {
          const candidate = JSON.parse(tail) as unknown;
          if (phase2AuditRecordSchema.safeParse(candidate).success)
            throw unhealthy("Complete Phase 2 audit record lacks a delimiter");
        } catch (error) {
          if (error instanceof RepositoryBoundaryError) throw error;
        }
      }
      const opened = await openVerified(
        path,
        constants.O_WRONLY,
        this.durability,
      );
      try {
        await opened.handle.truncate(prefixEnd);
        await opened.handle.sync();
        await verifyOpened(path, opened, this.durability);
      } finally {
        await opened.handle.close();
      }
      await assertPathIdentity(path, opened, this.durability);
      await this.durability.syncDirectory(dirname(path));
    } catch (error) {
      throw normalize(error, "Phase 2 audit content is invalid");
    } finally {
      bytes.fill(0);
    }
  }

  private acceptLine(line: string): void {
    if (Buffer.byteLength(line, "utf8") + 1 > PHASE2_AUDIT_LIMITS.recordBytes)
      throw unhealthy("Phase 2 audit record exceeds its boundary");
    let unknown: unknown;
    try {
      unknown = JSON.parse(line);
    } catch {
      throw unhealthy("Phase 2 audit record is invalid JSON");
    }
    const parsed = phase2AuditRecordSchema.safeParse(unknown);
    if (!parsed.success || canonicalJson(parsed.data) !== line)
      throw unhealthy("Phase 2 audit record is invalid or non-canonical");
    this.rememberRecord(parsed.data);
  }

  private assertCanAcceptRecord(
    record: Readonly<{
      phase: "attempt" | "outcome";
      requestId: string;
      operationId: string;
      tool: Phase2ToolName;
    }>,
  ): void {
    if (record.phase === "attempt") {
      if (
        this.seenAttemptIds.has(record.operationId) ||
        this.outcomes.has(record.operationId)
      )
        throw unhealthy("Phase 2 audit attempt operation is duplicated");
      return;
    }
    if (!this.seenAttemptIds.has(record.operationId))
      throw unhealthy("Phase 2 audit outcome has no prior attempt");
    if (this.outcomes.has(record.operationId))
      throw unhealthy("Phase 2 audit terminal outcome is duplicated");
  }

  private rememberRecord(
    record: Readonly<{
      phase: "attempt" | "outcome";
      requestId: string;
      operationId: string;
      tool: Phase2ToolName;
    }>,
  ): void {
    this.assertCanAcceptRecord(record);
    if (record.phase === "attempt") {
      this.seenAttemptIds.add(record.operationId);
      this.pendingAttempts.set(
        record.operationId,
        Object.freeze({
          requestId: record.requestId,
          operationId: record.operationId,
          tool: record.tool,
        }),
      );
      return;
    }
    this.outcomes.add(record.operationId);
    this.pendingAttempts.delete(record.operationId);
  }

  private async rotateIfNeeded(nextBytes: number): Promise<void> {
    const bytes = await readAuditFile(this.path, this.durability);
    const size = bytes.byteLength;
    bytes.fill(0);
    if (size + nextBytes <= PHASE2_AUDIT_LIMITS.fileBytes) return;
    let next = 1;
    while (
      next <= PHASE2_AUDIT_LIMITS.rotations &&
      (await fileExists(`${this.path}.${next}`))
    )
      next += 1;
    if (next > PHASE2_AUDIT_LIMITS.rotations)
      throw unhealthy("Phase 2 audit rotation boundary is exhausted");
    const rotated = `${this.path}.${next}`;
    const reservation = await open(
      rotated,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    try {
      await reservation.sync();
    } finally {
      await reservation.close();
    }
    await rename(this.path, rotated);
    await this.hooks.checkpoint?.("after_rotate_rename");
    const handle = await open(
      this.path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await this.hooks.checkpoint?.("after_rotate_create");
    await this.durability.syncDirectory(dirname(this.path));
    await this.hooks.checkpoint?.("after_rotate_dirsync");
  }
}

interface OpenedAuditFile {
  readonly handle: FileHandle;
  readonly dev: bigint;
  readonly ino: bigint;
}

async function openVerified(
  path: string,
  flags: number,
  durability: Phase2DurabilityPort,
): Promise<OpenedAuditFile> {
  const before = await lstat(path, { bigint: true });
  if (!safeAuditMetadata(before, durability))
    throw unhealthy("Phase 2 audit file is unsafe");
  const handle = await open(path, flags | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened, durability))
      throw unhealthy("Phase 2 audit file identity changed");
    return { handle, dev: opened.dev, ino: opened.ino };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function verifyOpened(
  path: string,
  opened: OpenedAuditFile,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const current = await opened.handle.stat({ bigint: true });
  const linked = await lstat(path, { bigint: true });
  if (
    current.dev !== opened.dev ||
    current.ino !== opened.ino ||
    !sameIdentity(current, linked, durability)
  )
    throw unhealthy("Phase 2 audit file identity changed");
}

async function assertPathIdentity(
  path: string,
  opened: OpenedAuditFile,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const linked = await lstat(path, { bigint: true });
  if (
    linked.dev !== opened.dev ||
    linked.ino !== opened.ino ||
    !safeAuditMetadata(linked, durability)
  )
    throw unhealthy("Phase 2 audit file identity changed");
}

async function readAuditFile(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<Buffer> {
  const opened = await openVerified(path, constants.O_RDONLY, durability);
  try {
    const metadata = await opened.handle.stat({ bigint: true });
    if (metadata.size > BigInt(PHASE2_AUDIT_LIMITS.fileBytes))
      throw unhealthy("Phase 2 audit file exceeds its boundary");
    const bytes = await opened.handle.readFile();
    try {
      await verifyOpened(path, opened, durability);
    } catch (error) {
      bytes.fill(0);
      throw error;
    }
    return bytes;
  } finally {
    await opened.handle.close();
    await assertPathIdentity(path, opened, durability);
  }
}

function safeAuditMetadata(
  metadata: {
    isFile(): boolean;
    nlink: bigint;
    mode: bigint;
  },
  durability: Phase2DurabilityPort,
): boolean {
  return (
    metadata.isFile() &&
    metadata.nlink === 1n &&
    durability.privateMode(metadata.mode)
  );
}

function sameIdentity(
  left: {
    dev: bigint;
    ino: bigint;
    nlink: bigint;
    mode: bigint;
    isFile(): boolean;
  },
  right: {
    dev: bigint;
    ino: bigint;
    nlink: bigint;
    mode: bigint;
    isFile(): boolean;
  },
  durability: Phase2DurabilityPort,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    safeAuditMetadata(right, durability)
  );
}
async function fileExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function ensureAuditDirectory(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  if (!isAbsolute(path) || resolve(path) !== path)
    throw unhealthy("Phase 2 audit directory must be absolute and normalized");
  const parsed = parse(path);
  let current = parsed.root;
  for (const segment of path
    .slice(parsed.root.length)
    .split(/[\\/]/u)
    .filter(Boolean)) {
    current = join(current, segment);
    try {
      const metadata = await lstat(current, { bigint: true });
      if (!metadata.isDirectory())
        throw unhealthy("Phase 2 audit path traverses a non-directory");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(current, { mode: 0o700 });
    }
  }
  await assertDirectory(path, durability);
}
async function assertDirectory(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const metadata = await lstat(path, { bigint: true });
  if (!metadata.isDirectory() || !durability.privateMode(metadata.mode))
    throw unhealthy("Phase 2 audit directory is unsafe");
}

async function assertFile(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const metadata = await lstat(path, { bigint: true });
  if (
    !metadata.isFile() ||
    metadata.nlink !== 1n ||
    !durability.privateMode(metadata.mode)
  )
    throw unhealthy("Phase 2 audit file is unsafe");
}

function unhealthy(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("service_unhealthy", message);
}

function normalize(error: unknown, message: string): RepositoryBoundaryError {
  return error instanceof RepositoryBoundaryError ? error : unhealthy(message);
}
