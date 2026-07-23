import { randomBytes as nativeRandomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat as nativeLstat, open as nativeOpen } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

export const PHASE3_APPROVAL_KEY_STATE_DIRECTORY = "/data/phase3";
export const PHASE3_APPROVAL_KEY_PATH = "/data/phase3/approval.key";
export const PHASE3_APPROVAL_KEY_BYTES = 32;
export const PHASE3_APPROVAL_KEY_IO_ATTEMPTS = 64;

const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const dataViewPrototype = DataView.prototype;
const IntrinsicUint8Array = Uint8Array;

export const phase3ApprovalKeyErrorCodes = Object.freeze([
  "approval_key_invalid",
  "approval_key_missing",
  "approval_key_exists",
  "approval_key_unsafe",
  "approval_key_corrupt",
  "approval_key_commit_unknown",
  "approval_key_io_failure",
] as const);

export type Phase3ApprovalKeyErrorCode =
  (typeof phase3ApprovalKeyErrorCodes)[number];

const errorMessages: Readonly<Record<Phase3ApprovalKeyErrorCode, string>> =
  Object.freeze({
    approval_key_invalid: "Phase 3 approval key input is invalid",
    approval_key_missing: "Phase 3 approval key is missing",
    approval_key_exists: "Phase 3 approval key already exists",
    approval_key_unsafe: "Phase 3 approval key state is unsafe",
    approval_key_corrupt: "Phase 3 approval key is corrupt",
    approval_key_commit_unknown: "Phase 3 approval key commit is unknown",
    approval_key_io_failure: "Phase 3 approval key I/O failed",
  });

export class Phase3ApprovalKeyError extends Error {
  constructor(public readonly code: Phase3ApprovalKeyErrorCode) {
    super(errorMessages[code]);
    this.name = "Phase3ApprovalKeyError";
  }
}

export interface Phase3ApprovalKeyMetadata {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly uid: bigint;
  readonly nlink: bigint;
  readonly size: bigint;
  readonly kind: "directory" | "regular" | "other";
}

export interface Phase3ApprovalKeyFileHandle {
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
  sync(): Promise<void>;
  stat(): Promise<Phase3ApprovalKeyMetadata>;
  close(): Promise<void>;
}

export interface Phase3ApprovalKeyFilesystemFlags {
  readonly O_RDONLY: number | undefined;
  readonly O_DIRECTORY: number | undefined;
  readonly O_NOFOLLOW: number | undefined;
  readonly O_CREAT: number | undefined;
  readonly O_EXCL: number | undefined;
  readonly O_WRONLY: number | undefined;
}

export interface Phase3ApprovalKeyFilesystem {
  readonly flags: Phase3ApprovalKeyFilesystemFlags;
  lstat(path: string): Promise<Phase3ApprovalKeyMetadata>;
  open(
    path: string,
    flags: number,
    mode?: number,
  ): Promise<Phase3ApprovalKeyFileHandle>;
}

export interface Phase3ApprovalKeyProcess {
  readonly platform: NodeJS.Platform;
  readonly getuid: (() => number) | undefined;
  readonly geteuid: (() => number) | undefined;
}

export type Phase3ApprovalKeyRandomBytes = (size: number) => Buffer;

export interface Phase3ApprovalKeyOptions {
  readonly stateDirectory?: string;
  readonly keyPath?: string;
  readonly filesystem?: Phase3ApprovalKeyFilesystem;
  readonly randomBytes?: Phase3ApprovalKeyRandomBytes;
  readonly process?: Phase3ApprovalKeyProcess;
}

export interface Phase3ApprovalKeyLease {
  readonly key: Buffer;
  readonly release: () => void;
}

interface TrustedHandle {
  read(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<number>;
  write(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<number>;
  sync(): Promise<void>;
  stat(): Promise<Phase3ApprovalKeyMetadata>;
  close(): Promise<void>;
}

interface ApprovalKeyContext {
  readonly stateDirectory: string;
  readonly keyPath: string;
  readonly filesystem: Phase3ApprovalKeyFilesystem;
  readonly randomBytes: Phase3ApprovalKeyRandomBytes;
  readonly uid: bigint;
  readonly flags: Readonly<{
    readonlyDirectory: number;
    readonlyKey: number;
    createKey: number;
  }>;
}

const nativeFilesystem: Phase3ApprovalKeyFilesystem = Object.freeze({
  flags: Object.freeze({
    O_RDONLY: constants.O_RDONLY,
    O_DIRECTORY: constants.O_DIRECTORY,
    O_NOFOLLOW: constants.O_NOFOLLOW,
    O_CREAT: constants.O_CREAT,
    O_EXCL: constants.O_EXCL,
    O_WRONLY: constants.O_WRONLY,
  }),
  lstat: async (path: string) =>
    nativeMetadata(await nativeLstat(path, { bigint: true })),
  open: async (path: string, flags: number, mode?: number) => {
    const handle = await nativeOpen(path, flags, mode);
    return Object.freeze({
      read: async (
        buffer: Uint8Array,
        offset: number,
        length: number,
        position: number,
      ) => await handle.read(buffer, offset, length, position),
      write: async (
        buffer: Uint8Array,
        offset: number,
        length: number,
        position: number,
      ) => await handle.write(buffer, offset, length, position),
      sync: async () => await handle.sync(),
      stat: async () => nativeMetadata(await handle.stat({ bigint: true })),
      close: async () => await handle.close(),
    });
  },
});

const nativeProcess: Phase3ApprovalKeyProcess = Object.freeze({
  platform: process.platform,
  getuid:
    process.getuid === undefined ? undefined : process.getuid.bind(process),
  geteuid:
    process.geteuid === undefined ? undefined : process.geteuid.bind(process),
});

class BoundaryFailure extends Error {
  readonly errno: string | undefined;

  constructor(error: unknown) {
    super("Phase 3 approval key boundary failed");
    this.name = "BoundaryFailure";
    this.errno = safeErrno(error);
  }
}

export async function provisionPhase3ApprovalKey(
  options: Phase3ApprovalKeyOptions = {},
): Promise<void> {
  const context = configure(options);
  let directory: TrustedHandle | undefined;
  let keyHandle: TrustedHandle | undefined;
  let pinnedDirectory: Phase3ApprovalKeyMetadata | undefined;
  let scratch: Buffer | undefined;
  let primary: Phase3ApprovalKeyErrorCode | undefined;
  let exclusiveOpenFulfilled = false;
  let directoryReadyForClose = false;

  try {
    pinnedDirectory = await filesystemLstat(context, context.stateDirectory);
    assertDirectory(pinnedDirectory, context.uid);
    directory = await filesystemOpen(
      context,
      context.stateDirectory,
      context.flags.readonlyDirectory,
    );
    const openedDirectory = await directory.stat();
    assertDirectory(openedDirectory, context.uid);
    assertSameDirectory(pinnedDirectory, openedDirectory);

    await revalidateDirectory(context, directory, pinnedDirectory);
    scratch = randomScratch(context);
    await revalidateDirectory(context, directory, pinnedDirectory);

    try {
      keyHandle = await filesystemOpen(
        context,
        context.keyPath,
        context.flags.createKey,
        0o600,
        () => {
          exclusiveOpenFulfilled = true;
        },
      );
    } catch (error) {
      if (error instanceof BoundaryFailure && error.errno === "EEXIST")
        throw keyError("approval_key_exists");
      throw error;
    }

    await writeExact(keyHandle, scratch);
    await keyHandle.sync();
    const descriptorKey = await keyHandle.stat();
    assertKey(descriptorKey, context.uid);
    const completedKeyHandle = keyHandle;
    keyHandle = undefined;
    await completedKeyHandle.close();

    let finalKey: Phase3ApprovalKeyMetadata;
    try {
      finalKey = await filesystemLstat(context, context.keyPath);
    } catch (error) {
      throw laterKeyFailure(error);
    }
    assertKey(finalKey, context.uid);
    assertSameKey(descriptorKey, finalKey);
    await revalidateDirectory(context, directory, pinnedDirectory);
    await directory.sync();
    await revalidateDirectory(context, directory, pinnedDirectory);
    directoryReadyForClose = true;
  } catch (error) {
    primary = publicCode(error);
  } finally {
    zero(scratch);
    if (keyHandle !== undefined) {
      const handle = keyHandle;
      const cleanup = await cleanupCall(async () => {
        await handle.close();
      });
      primary ??= cleanup;
      keyHandle = undefined;
    }
    if (
      directory !== undefined &&
      pinnedDirectory !== undefined &&
      !directoryReadyForClose
    ) {
      const handle = directory;
      const pinned = pinnedDirectory;
      const cleanup = await cleanupCall(async () => {
        await revalidateDirectory(context, handle, pinned);
      });
      primary ??= cleanup;
    }
    if (directory !== undefined) {
      const handle = directory;
      const cleanup = await cleanupCall(async () => {
        await handle.close();
      });
      primary ??= cleanup;
      directory = undefined;
    }
  }

  if (exclusiveOpenFulfilled && primary !== undefined)
    throw keyError("approval_key_commit_unknown");
  if (primary !== undefined) throw keyError(primary);
}

export async function loadPhase3ApprovalKey(
  options: Phase3ApprovalKeyOptions = {},
): Promise<Phase3ApprovalKeyLease> {
  const context = configure(options);
  let directory: TrustedHandle | undefined;
  let keyHandle: TrustedHandle | undefined;
  let pinnedDirectory: Phase3ApprovalKeyMetadata | undefined;
  let candidate: Buffer | undefined;
  let primary: Phase3ApprovalKeyErrorCode | undefined;
  let directoryReadyForClose = false;

  try {
    pinnedDirectory = await filesystemLstat(context, context.stateDirectory);
    assertDirectory(pinnedDirectory, context.uid);
    directory = await filesystemOpen(
      context,
      context.stateDirectory,
      context.flags.readonlyDirectory,
    );
    const openedDirectory = await directory.stat();
    assertDirectory(openedDirectory, context.uid);
    assertSameDirectory(pinnedDirectory, openedDirectory);
    await revalidateDirectory(context, directory, pinnedDirectory);

    let pathKey: Phase3ApprovalKeyMetadata;
    try {
      pathKey = await filesystemLstat(context, context.keyPath);
    } catch (error) {
      if (error instanceof BoundaryFailure && error.errno === "ENOENT")
        throw keyError("approval_key_missing");
      throw error;
    }
    assertKey(pathKey, context.uid);

    try {
      keyHandle = await filesystemOpen(
        context,
        context.keyPath,
        context.flags.readonlyKey,
      );
    } catch (error) {
      throw laterKeyFailure(error);
    }
    const descriptorKey = await keyHandle.stat();
    assertSameKey(pathKey, descriptorKey);
    assertKey(descriptorKey, context.uid);

    candidate = Buffer.alloc(PHASE3_APPROVAL_KEY_BYTES);
    await readExact(keyHandle, candidate);
    const afterRead = await keyHandle.stat();
    assertSameKey(descriptorKey, afterRead);
    assertKey(afterRead, context.uid);
    if (isAllZero(candidate, PHASE3_APPROVAL_KEY_BYTES))
      throw keyError("approval_key_corrupt");

    let finalKey: Phase3ApprovalKeyMetadata;
    try {
      finalKey = await filesystemLstat(context, context.keyPath);
    } catch (error) {
      throw laterKeyFailure(error);
    }
    assertSameKey(descriptorKey, finalKey);
    assertKey(finalKey, context.uid);
    await revalidateDirectory(context, directory, pinnedDirectory);
    directoryReadyForClose = true;
  } catch (error) {
    primary = publicCode(error);
  } finally {
    if (keyHandle !== undefined) {
      const handle = keyHandle;
      const cleanup = await cleanupCall(async () => {
        await handle.close();
      });
      primary ??= cleanup;
      keyHandle = undefined;
    }
    if (
      directory !== undefined &&
      pinnedDirectory !== undefined &&
      !directoryReadyForClose
    ) {
      const handle = directory;
      const pinned = pinnedDirectory;
      const cleanup = await cleanupCall(async () => {
        await revalidateDirectory(context, handle, pinned);
      });
      primary ??= cleanup;
    }
    if (directory !== undefined) {
      const handle = directory;
      const cleanup = await cleanupCall(async () => {
        await handle.close();
      });
      primary ??= cleanup;
      directory = undefined;
    }
  }

  if (primary !== undefined) {
    zero(candidate);
    throw keyError(primary);
  }
  if (candidate === undefined) throw keyError("approval_key_io_failure");

  const key = candidate;
  const release = (): void => {
    wipeBytes(key, PHASE3_APPROVAL_KEY_BYTES);
  };
  return Object.freeze({ key, release });
}

function configure(options: Phase3ApprovalKeyOptions): ApprovalKeyContext {
  let stateDirectory: unknown;
  let keyPath: unknown;
  let filesystem: unknown;
  let randomBytes: unknown;
  let processBoundary: unknown;
  try {
    stateDirectory =
      options.stateDirectory ?? PHASE3_APPROVAL_KEY_STATE_DIRECTORY;
    keyPath = options.keyPath ?? PHASE3_APPROVAL_KEY_PATH;
    filesystem = options.filesystem ?? nativeFilesystem;
    randomBytes = options.randomBytes ?? nativeRandomBytes;
    processBoundary = options.process ?? nativeProcess;
  } catch {
    throw keyError("approval_key_invalid");
  }

  if (
    !validAbsolutePath(stateDirectory) ||
    !validAbsolutePath(keyPath) ||
    dirname(keyPath) !== stateDirectory
  )
    throw keyError("approval_key_invalid");
  if (
    typeof filesystem !== "object" ||
    filesystem === null ||
    typeof randomBytes !== "function" ||
    typeof processBoundary !== "object" ||
    processBoundary === null
  )
    throw keyError("approval_key_invalid");

  const trustedProcess = processBoundary as Phase3ApprovalKeyProcess;
  let platform: unknown;
  let getuid: unknown;
  let geteuid: unknown;
  try {
    platform = trustedProcess.platform;
    getuid = trustedProcess.getuid;
    geteuid = trustedProcess.geteuid;
  } catch {
    throw keyError("approval_key_invalid");
  }
  if (
    platform !== "linux" ||
    typeof getuid !== "function" ||
    typeof geteuid !== "function"
  )
    throw keyError("approval_key_invalid");

  let uid: unknown;
  let euid: unknown;
  try {
    uid = Reflect.apply(getuid, trustedProcess, []);
    euid = Reflect.apply(geteuid, trustedProcess, []);
  } catch {
    throw keyError("approval_key_invalid");
  }
  if (
    !Number.isSafeInteger(uid) ||
    (uid as number) < 0 ||
    !Number.isSafeInteger(euid) ||
    euid !== uid
  )
    throw keyError("approval_key_invalid");

  const trustedFilesystem = filesystem as Phase3ApprovalKeyFilesystem;
  let flags: Phase3ApprovalKeyFilesystemFlags;
  try {
    flags = trustedFilesystem.flags;
  } catch {
    throw keyError("approval_key_invalid");
  }
  let O_RDONLY: unknown;
  let O_DIRECTORY: unknown;
  let O_NOFOLLOW: unknown;
  let O_CREAT: unknown;
  let O_EXCL: unknown;
  let O_WRONLY: unknown;
  try {
    O_RDONLY = flags?.O_RDONLY;
    O_DIRECTORY = flags?.O_DIRECTORY;
    O_NOFOLLOW = flags?.O_NOFOLLOW;
    O_CREAT = flags?.O_CREAT;
    O_EXCL = flags?.O_EXCL;
    O_WRONLY = flags?.O_WRONLY;
  } catch {
    throw keyError("approval_key_invalid");
  }
  if (
    !validFlag(O_RDONLY) ||
    !validFlag(O_DIRECTORY) ||
    !validFlag(O_NOFOLLOW) ||
    !validFlag(O_CREAT) ||
    !validFlag(O_EXCL) ||
    !validFlag(O_WRONLY)
  )
    throw keyError("approval_key_invalid");

  return Object.freeze({
    stateDirectory,
    keyPath,
    filesystem: trustedFilesystem,
    randomBytes: randomBytes as Phase3ApprovalKeyRandomBytes,
    uid: BigInt(uid as number),
    flags: Object.freeze({
      readonlyDirectory: O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
      readonlyKey: O_RDONLY | O_NOFOLLOW,
      createKey: O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW,
    }),
  });
}

function validAbsolutePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0"))
    return false;
  try {
    return isAbsolute(value) && resolve(value) === value;
  } catch {
    return false;
  }
}

function validFlag(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function nativeMetadata(metadata: BigIntStats): Phase3ApprovalKeyMetadata {
  return Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino,
    mode: metadata.mode,
    uid: metadata.uid,
    nlink: metadata.nlink,
    size: metadata.size,
    kind: metadata.isDirectory()
      ? "directory"
      : metadata.isFile()
        ? "regular"
        : "other",
  });
}

function copyMetadata(value: unknown): Phase3ApprovalKeyMetadata {
  if (typeof value !== "object" || value === null)
    throw new Error("invalid metadata");
  const record = value as Record<string, unknown>;
  const snapshot = {
    dev: record.dev,
    ino: record.ino,
    mode: record.mode,
    uid: record.uid,
    nlink: record.nlink,
    size: record.size,
    kind: record.kind,
  };
  if (
    typeof snapshot.dev !== "bigint" ||
    snapshot.dev < 0n ||
    typeof snapshot.ino !== "bigint" ||
    snapshot.ino < 0n ||
    typeof snapshot.mode !== "bigint" ||
    snapshot.mode < 0n ||
    typeof snapshot.uid !== "bigint" ||
    snapshot.uid < 0n ||
    typeof snapshot.nlink !== "bigint" ||
    snapshot.nlink < 0n ||
    typeof snapshot.size !== "bigint" ||
    snapshot.size < 0n ||
    (snapshot.kind !== "directory" &&
      snapshot.kind !== "regular" &&
      snapshot.kind !== "other")
  )
    throw new Error("invalid metadata");
  return Object.freeze(snapshot as Phase3ApprovalKeyMetadata);
}

type BoundaryMethod = (...args: unknown[]) => unknown;

function boundaryMethod(value: object, name: string): BoundaryMethod {
  const candidate = (value as Record<string, unknown>)[name];
  if (typeof candidate !== "function")
    throw new Error("invalid boundary method");
  return candidate as BoundaryMethod;
}

function protectHandle(value: unknown): TrustedHandle {
  if (typeof value !== "object" || value === null)
    throw new Error("invalid file handle");
  const read = boundaryMethod(value, "read");
  const write = boundaryMethod(value, "write");
  const sync = boundaryMethod(value, "sync");
  const stat = boundaryMethod(value, "stat");
  const close = boundaryMethod(value, "close");
  const trusted: TrustedHandle = {
    read: async (buffer, offset, length, position) =>
      await boundaryCall(
        async () =>
          await Reflect.apply(read, value, [buffer, offset, length, position]),
        (result) => copyIoCount(result, "bytesRead"),
      ),
    write: async (buffer, offset, length, position) =>
      await boundaryCall(
        async () =>
          await Reflect.apply(write, value, [buffer, offset, length, position]),
        (result) => copyIoCount(result, "bytesWritten"),
      ),
    sync: async () =>
      await boundaryCall(
        async () => await Reflect.apply(sync, value, []),
        copyUndefined,
      ),
    stat: async () =>
      await boundaryCall(
        async () => await Reflect.apply(stat, value, []),
        copyMetadata,
      ),
    close: async () =>
      await boundaryCall(
        async () => await Reflect.apply(close, value, []),
        copyUndefined,
      ),
  };
  return Object.freeze(trusted);
}

async function boundaryCall<T, Result>(
  operation: () => Promise<T>,
  copy: (value: T) => Result,
): Promise<Result> {
  try {
    return copy(await operation());
  } catch (error) {
    if (error instanceof BoundaryFailure) throw error;
    throw new BoundaryFailure(error);
  }
}

function copyUndefined(value: unknown): void {
  if (value !== undefined) throw new Error("invalid boundary result");
}

function copyIoCount(value: unknown, name: string): number {
  if (typeof value !== "object" || value === null)
    throw new Error("invalid I/O result");
  const count = (value as Record<string, unknown>)[name];
  if (!Number.isSafeInteger(count) || (count as number) < 0)
    throw new Error("invalid I/O result");
  return count as number;
}

async function filesystemLstat(
  context: ApprovalKeyContext,
  path: string,
): Promise<Phase3ApprovalKeyMetadata> {
  return await boundaryCall(
    async () => await context.filesystem.lstat(path),
    copyMetadata,
  );
}

async function filesystemOpen(
  context: ApprovalKeyContext,
  path: string,
  flags: number,
  mode?: number,
  fulfilled?: () => void,
): Promise<TrustedHandle> {
  try {
    const value = await context.filesystem.open(path, flags, mode);
    fulfilled?.();
    return protectHandle(value);
  } catch (error) {
    if (error instanceof BoundaryFailure) throw error;
    throw new BoundaryFailure(error);
  }
}

function randomScratch(context: ApprovalKeyContext): Buffer {
  let value: unknown;
  try {
    value = context.randomBytes(PHASE3_APPROVAL_KEY_BYTES);
  } catch (error) {
    throw new BoundaryFailure(error);
  }
  if (!Buffer.isBuffer(value)) {
    wipeMalformedRandomView(value);
    throw keyError("approval_key_invalid");
  }
  const byteLength = intrinsicByteLength(value);
  if (
    byteLength !== PHASE3_APPROVAL_KEY_BYTES ||
    isAllZero(value, byteLength)
  ) {
    wipeBytes(value, byteLength);
    throw keyError("approval_key_invalid");
  }
  return value;
}

async function revalidateDirectory(
  context: ApprovalKeyContext,
  handle: TrustedHandle,
  pinned: Phase3ApprovalKeyMetadata,
): Promise<void> {
  const descriptor = await handle.stat();
  assertDirectory(descriptor, context.uid);
  assertSameDirectory(pinned, descriptor);
  const path = await filesystemLstat(context, context.stateDirectory);
  assertDirectory(path, context.uid);
  assertSameDirectory(pinned, path);
  assertSameDirectory(descriptor, path);
}

function assertDirectory(
  metadata: Phase3ApprovalKeyMetadata,
  uid: bigint,
): void {
  if (
    metadata.kind !== "directory" ||
    metadata.uid !== uid ||
    (metadata.mode & 0o7777n) !== 0o700n
  )
    throw keyError("approval_key_unsafe");
}

function assertKey(metadata: Phase3ApprovalKeyMetadata, uid: bigint): void {
  if (
    metadata.kind !== "regular" ||
    metadata.uid !== uid ||
    (metadata.mode & 0o7777n) !== 0o600n ||
    metadata.nlink !== 1n
  )
    throw keyError("approval_key_unsafe");
  if (metadata.size !== BigInt(PHASE3_APPROVAL_KEY_BYTES))
    throw keyError("approval_key_corrupt");
}

function assertSameDirectory(
  first: Phase3ApprovalKeyMetadata,
  second: Phase3ApprovalKeyMetadata,
): void {
  if (first.dev !== second.dev || first.ino !== second.ino)
    throw keyError("approval_key_unsafe");
}

function assertSameKey(
  first: Phase3ApprovalKeyMetadata,
  second: Phase3ApprovalKeyMetadata,
): void {
  if (
    first.dev !== second.dev ||
    first.ino !== second.ino ||
    first.mode !== second.mode ||
    first.uid !== second.uid ||
    first.nlink !== second.nlink ||
    first.size !== second.size ||
    first.kind !== second.kind
  )
    throw keyError("approval_key_unsafe");
}

async function writeExact(handle: TrustedHandle, bytes: Buffer): Promise<void> {
  let position = 0;
  let attempts = 0;
  while (position < PHASE3_APPROVAL_KEY_BYTES) {
    if (attempts >= PHASE3_APPROVAL_KEY_IO_ATTEMPTS)
      throw keyError("approval_key_io_failure");
    attempts += 1;
    const remaining = PHASE3_APPROVAL_KEY_BYTES - position;
    let written: number;
    try {
      written = await handle.write(bytes, position, remaining, position);
    } catch (error) {
      if (error instanceof BoundaryFailure && error.errno === "EINTR") continue;
      throw error;
    }
    if (written === 0 || written > remaining)
      throw keyError("approval_key_io_failure");
    position += written;
  }
}

async function readExact(
  handle: TrustedHandle,
  candidate: Buffer,
): Promise<void> {
  let position = 0;
  let attempts = 0;
  while (position < PHASE3_APPROVAL_KEY_BYTES) {
    if (attempts >= PHASE3_APPROVAL_KEY_IO_ATTEMPTS)
      throw keyError("approval_key_io_failure");
    attempts += 1;
    const remaining = PHASE3_APPROVAL_KEY_BYTES - position;
    let read: number;
    try {
      read = await handle.read(candidate, position, remaining, position);
    } catch (error) {
      if (error instanceof BoundaryFailure && error.errno === "EINTR") continue;
      throw error;
    }
    if (read === 0) throw keyError("approval_key_corrupt");
    if (read > remaining) throw keyError("approval_key_io_failure");
    position += read;
  }

  const extra = Buffer.alloc(1);
  try {
    for (;;) {
      if (attempts >= PHASE3_APPROVAL_KEY_IO_ATTEMPTS)
        throw keyError("approval_key_io_failure");
      attempts += 1;
      let read: number;
      try {
        read = await handle.read(extra, 0, 1, PHASE3_APPROVAL_KEY_BYTES);
      } catch (error) {
        if (error instanceof BoundaryFailure && error.errno === "EINTR")
          continue;
        throw error;
      }
      if (read === 0) return;
      if (read === 1) throw keyError("approval_key_corrupt");
      throw keyError("approval_key_io_failure");
    }
  } finally {
    wipeBytes(extra, 1);
  }
}

function isAllZero(bytes: Uint8Array, byteLength: number): boolean {
  let aggregate = 0;
  for (let index = 0; index < byteLength; index += 1)
    aggregate |= bytes[index] ?? 0;
  return aggregate === 0;
}

function zero(bytes: Buffer | undefined): void {
  if (bytes !== undefined) wipeBytes(bytes, PHASE3_APPROVAL_KEY_BYTES);
}

function intrinsicByteLength(bytes: Uint8Array): number {
  return intrinsicViewRegion(typedArrayPrototype, bytes).byteLength;
}

function wipeMalformedRandomView(value: unknown): void {
  if (!ArrayBuffer.isView(value)) return;
  try {
    let region: IntrinsicViewRegion;
    try {
      region = intrinsicViewRegion(typedArrayPrototype, value);
    } catch {
      region = intrinsicViewRegion(dataViewPrototype, value);
    }
    const bytes = new IntrinsicUint8Array(
      region.buffer,
      region.byteOffset,
      region.byteLength,
    );
    wipeBytes(bytes, region.byteLength);
  } catch {
    // The public invalid-input result remains fixed even for detached views.
  }
}

interface IntrinsicViewRegion {
  readonly buffer: ArrayBufferLike;
  readonly byteOffset: number;
  readonly byteLength: number;
}

function intrinsicViewRegion(
  prototype: object,
  view: ArrayBufferView,
): IntrinsicViewRegion {
  const buffer: unknown = Reflect.get(prototype, "buffer", view);
  const byteOffset: unknown = Reflect.get(prototype, "byteOffset", view);
  const byteLength: unknown = Reflect.get(prototype, "byteLength", view);
  if (
    typeof buffer !== "object" ||
    buffer === null ||
    typeof byteOffset !== "number" ||
    !Number.isSafeInteger(byteOffset) ||
    byteOffset < 0 ||
    typeof byteLength !== "number" ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < 0
  )
    throw new Error("array buffer view is unavailable");
  return { buffer: buffer as ArrayBufferLike, byteOffset, byteLength };
}

function wipeBytes(bytes: Uint8Array, byteLength: number): void {
  for (let index = 0; index < byteLength; index += 1) bytes[index] = 0;
}

async function cleanupCall(
  operation: () => Promise<void>,
): Promise<Phase3ApprovalKeyErrorCode | undefined> {
  try {
    await operation();
    return undefined;
  } catch (error) {
    return publicCode(error);
  }
}

function laterKeyFailure(error: unknown): Error {
  if (
    error instanceof BoundaryFailure &&
    (error.errno === "ENOENT" || error.errno === "ELOOP")
  )
    return keyError("approval_key_unsafe");
  return error instanceof Error ? error : keyError("approval_key_io_failure");
}

function safeErrno(error: unknown): string | undefined {
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

function publicCode(error: unknown): Phase3ApprovalKeyErrorCode {
  if (error instanceof Phase3ApprovalKeyError) return error.code;
  return "approval_key_io_failure";
}

function keyError(code: Phase3ApprovalKeyErrorCode): Phase3ApprovalKeyError {
  return new Phase3ApprovalKeyError(code);
}
