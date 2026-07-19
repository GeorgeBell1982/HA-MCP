import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import {
  PHASE2_MAX_TEXT_BYTES,
  relativeConfigPathSchema,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import { redactText } from "../redaction.js";

const HEADER_BYTES = 64;
const MAGIC = Buffer.from("HAREAD2\0", "ascii");
const MAX_HELPER_STDERR_BYTES = 4_096;
const MAX_SECRET_VALUES = 256;
const MAX_SECRET_VALUE_BYTES = 16_384;
const MAX_SECRET_TOTAL_BYTES = 128 * 1_024;
const MAX_PROTECTED_SOURCES = 64;
const MAX_REDACTION_NODES = 10_000;
const MAX_REDACTION_DEPTH = 64;
const MAX_REDACTION_TOTAL_INPUT_BYTES = 2 * 1_024 * 1_024;
const MAX_REDACTION_TOTAL_OUTPUT_BYTES = 1_024 * 1_024;
const MAX_REDACTION_EXACT_SCAN_CODE_UNITS = 16 * 1_024 * 1_024;
const MAX_REDACTION_REPLACEMENT_MATCHES = 100_000;
const REDACTION_MARKER = "[REDACTED]";
const SENSITIVE_KEY_PATTERN =
  /token|password|secret|authorization|webhook|api[_-]?key|credential/iu;

export type RepositoryBoundaryErrorCode =
  | "capability_unavailable"
  | "deadline_exceeded"
  | "operation_cancelled"
  | "path_denied"
  | "protected_resource"
  | "file_too_large"
  | "unsupported_encoding"
  | "invalid_input"
  | "stale_source"
  | "resource_not_found"
  | "service_unhealthy";

export class RepositoryBoundaryError extends Error {
  constructor(
    public readonly code: RepositoryBoundaryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "RepositoryBoundaryError";
  }
}

export interface FileIdentity {
  readonly device: string;
  readonly inode: string;
}

export interface SecureFileRead {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly rootIdentity: FileIdentity;
  readonly bytes: Uint8Array;
}

export interface SecureFileReader {
  read(path: string, context: Phase2OperationContext): Promise<SecureFileRead>;
}

export interface ProtectedSource {
  readonly path: string;
  readonly bytes: Uint8Array;
}

export interface SecretValueProvider {
  loadExactValues(
    sources: readonly ProtectedSource[],
    context: Phase2OperationContext,
  ): Promise<readonly string[]>;
}

export interface NativeOpenat2ReaderOptions {
  readonly helperPath?: string;
  readonly root?: string;
  readonly platform?: NodeJS.Platform;
  readonly maximumBytes?: number;
  readonly maximumConcurrentHelpers?: number;
}

interface PermitWaiter {
  readonly grant: () => void;
  readonly cancel: () => void;
}

export class BoundedPermitPool {
  private active = 0;
  private readonly waiters: PermitWaiter[] = [];

  constructor(
    private readonly maximum: number,
    private readonly maximumWaiters = 32,
  ) {
    if (!Number.isSafeInteger(maximum) || maximum < 1)
      throw new TypeError("maximum must be a positive safe integer");
    if (!Number.isSafeInteger(maximumWaiters) || maximumWaiters < 1)
      throw new TypeError("maximumWaiters must be a positive safe integer");
  }

  async acquire(context: Phase2OperationContext): Promise<() => void> {
    assertOperationActive(context);
    if (this.active < this.maximum) {
      this.active += 1;
      return () => this.release();
    }
    if (this.waiters.length >= this.maximumWaiters)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Repository helper wait queue exceeded its boundary",
      );
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const remove = (waiter: PermitWaiter) => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
      };
      const cleanup = () => {
        clearTimeout(timeout);
        context.signal.removeEventListener("abort", waiter.cancel);
      };
      const waiter: PermitWaiter = {
        grant: () => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve();
        },
        cancel: () => {
          if (settled) return;
          settled = true;
          remove(waiter);
          cleanup();
          reject(operationError(context));
        },
      };
      const remaining = context.deadlineAt - Date.now();
      if (remaining <= 0) {
        reject(operationError(context));
        return;
      }
      const timeout = setTimeout(waiter.cancel, remaining);
      this.waiters.push(waiter);
      context.signal.addEventListener("abort", waiter.cancel, { once: true });
      if (context.signal.aborted) waiter.cancel();
    });
    try {
      assertOperationActive(context);
    } catch (error) {
      this.release();
      throw error;
    }
    return () => this.release();
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) next.grant();
    else this.active -= 1;
  }
}
export class NativeOpenat2Reader implements SecureFileReader {
  private readonly helperPath: string | undefined;
  private readonly root: string;
  private readonly platform: NodeJS.Platform;
  private readonly maximumBytes: number;
  private readonly permits: BoundedPermitPool;
  private trustedRoot: string | undefined;
  private unhealthy = false;

  constructor(options: NativeOpenat2ReaderOptions = {}) {
    this.helperPath = options.helperPath;
    this.root = options.root ?? "/homeassistant";
    this.platform = options.platform ?? process.platform;
    this.maximumBytes = options.maximumBytes ?? 512 * 1_024;
    this.permits = new BoundedPermitPool(options.maximumConcurrentHelpers ?? 4);
    if (!Number.isSafeInteger(this.maximumBytes) || this.maximumBytes < 1)
      throw new TypeError("maximumBytes must be a positive safe integer");
    if (
      !Number.isSafeInteger(options.maximumConcurrentHelpers ?? 4) ||
      (options.maximumConcurrentHelpers ?? 4) < 1 ||
      (options.maximumConcurrentHelpers ?? 4) > 16
    )
      throw new TypeError("maximumConcurrentHelpers must be between 1 and 16");
  }

  async read(
    path: string,
    context: Phase2OperationContext,
  ): Promise<SecureFileRead> {
    assertOperationActive(context);
    if (this.unhealthy)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Repository security boundary is unhealthy",
      );
    if (this.platform !== "linux" || !this.helperPath)
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Authoritative repository confinement is not packaged for this platform",
      );
    if (!isAbsolute(this.root) || !isAbsolute(this.helperPath))
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Repository confinement helper configuration is invalid",
      );
    const parsed = relativeConfigPathSchema.safeParse(path);
    if (!parsed.success)
      throw new RepositoryBoundaryError(
        "path_denied",
        "Repository path is denied",
      );
    const release = await this.permits.acquire(context);
    try {
      const result = await runHelper(
        this.helperPath,
        this.root,
        parsed.data,
        this.maximumBytes,
        context,
      );
      assertOperationActive(context);
      const rootKey = identityKey(result.rootIdentity);
      if (this.trustedRoot === undefined) this.trustedRoot = rootKey;
      else if (this.trustedRoot !== rootKey) {
        this.unhealthy = true;
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Repository root identity changed",
        );
      }
      return result;
    } finally {
      release();
    }
  }
}

export class ExactSecretRedactor {
  private readonly values: readonly string[];

  constructor(values: readonly string[]) {
    if (values.length > MAX_SECRET_VALUES)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Exact secret value limit exceeded",
      );
    let total = 0;
    const copied = values.map((value) => {
      const bytes = Buffer.byteLength(value, "utf8");
      if (bytes === 0 || bytes > MAX_SECRET_VALUE_BYTES)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Exact secret value is outside the safe boundary",
        );
      total += bytes;
      return `${value}`;
    });
    if (total > MAX_SECRET_TOTAL_BYTES)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Exact secret value set is outside the safe boundary",
      );
    this.values = Object.freeze(
      [...new Set(copied)].sort((a, b) => b.length - a.length),
    );
    Object.freeze(this);
  }

  redact(value: unknown, context: Phase2OperationContext): unknown {
    const seen = new WeakSet<object>();
    let nodes = 0;
    let inputBytes = 0;
    let outputBytes = 0;
    const accountInput = (text: string) => {
      const bytes = Buffer.byteLength(text, "utf8");
      inputBytes += bytes;
      if (
        bytes > PHASE2_MAX_TEXT_BYTES ||
        inputBytes > MAX_REDACTION_TOTAL_INPUT_BYTES
      )
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Redaction text input exceeded the safe boundary",
        );
    };
    const accountOutput = (text: string) => {
      outputBytes += Buffer.byteLength(text, "utf8");
      if (outputBytes > MAX_REDACTION_TOTAL_OUTPUT_BYTES)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Redaction text output exceeded the safe boundary",
        );
      return text;
    };
    const transform = (text: string) => {
      accountInput(text);
      return accountOutput(
        redactText(this.redactExactString(text, context), {
          check: () => assertOperationActive(context),
        }),
      );
    };
    const visit = (item: unknown, depth: number): unknown => {
      assertOperationActive(context);
      nodes += 1;
      if (nodes > MAX_REDACTION_NODES || depth > MAX_REDACTION_DEPTH)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Redaction input exceeded the safe boundary",
        );
      if (typeof item === "string") return transform(item);
      if (Array.isArray(item)) {
        if (seen.has(item))
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Cyclic redaction input denied",
          );
        seen.add(item);
        return item.map((entry) => visit(entry, depth + 1));
      }
      if (item && typeof item === "object") {
        if (seen.has(item))
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Cyclic redaction input denied",
          );
        seen.add(item);
        return Object.fromEntries(
          Object.entries(item).map(([key, entry]) => {
            const redactedKey = transform(key);
            if (SENSITIVE_KEY_PATTERN.test(key)) {
              if (typeof entry === "string") accountInput(entry);
              return [redactedKey, accountOutput("[REDACTED]")];
            }
            return [redactedKey, visit(entry, depth + 1)];
          }),
        );
      }
      return item;
    };
    return visit(value, 0);
  }

  redactWholeText(
    value: string,
    context: Phase2OperationContext,
    maximumBytes = PHASE2_MAX_TEXT_BYTES,
  ): string {
    if (Buffer.byteLength(value, "utf8") > PHASE2_MAX_TEXT_BYTES)
      throw new RepositoryBoundaryError(
        "file_too_large",
        "Redaction text input exceeded the file boundary",
      );
    try {
      return redactText(this.redactExactString(value, context), {
        maximumBytes,
        truncate: false,
        check: () => assertOperationActive(context),
      });
    } catch (error) {
      if (error instanceof RepositoryBoundaryError) throw error;
      throw new RepositoryBoundaryError(
        "file_too_large",
        "Redacted text exceeded the output boundary",
      );
    }
  }

  private redactExactString(
    value: string,
    context: Phase2OperationContext,
  ): string {
    let output = value;
    let outputBytes = Buffer.byteLength(output, "utf8");
    let scanCodeUnits = 0;
    let replacementMatches = 0;
    const markerBytes = Buffer.byteLength(REDACTION_MARKER, "utf8");
    for (let index = 0; index < this.values.length; index += 1) {
      assertOperationActive(context);
      scanCodeUnits += output.length;
      if (scanCodeUnits > MAX_REDACTION_EXACT_SCAN_CODE_UNITS)
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Exact redaction work exceeded the safe boundary",
        );
      const exactValue = this.values[index]!;
      const exactBytes = Buffer.byteLength(exactValue, "utf8");
      let matches = 0;
      let offset = 0;
      for (;;) {
        const found = output.indexOf(exactValue, offset);
        if (found < 0) break;
        matches += 1;
        replacementMatches += 1;
        if (
          replacementMatches > MAX_REDACTION_REPLACEMENT_MATCHES ||
          outputBytes + matches * (markerBytes - exactBytes) >
            MAX_REDACTION_TOTAL_OUTPUT_BYTES
        )
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Exact redaction expansion exceeded the safe boundary",
          );
        if ((replacementMatches & 1_023) === 0) assertOperationActive(context);
        offset = found + exactValue.length;
      }
      if (matches > 0) {
        outputBytes += matches * (markerBytes - exactBytes);
        output = output.split(exactValue).join(REDACTION_MARKER);
      }
    }
    return output;
  }
}

export interface ProtectedIdentityMetadata {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly sha256: string;
}

export class ProtectedIdentityRegistry {
  private readonly identities = new Map<string, ProtectedIdentityMetadata>();
  private readonly paths = new Map<string, ProtectedIdentityMetadata>();
  private redactor: ExactSecretRedactor | undefined;
  private unhealthy = false;

  constructor(private readonly reader: SecureFileReader) {}

  async initialize(
    sourcePaths: readonly string[],
    provider: SecretValueProvider,
    context: Phase2OperationContext,
  ): Promise<void> {
    if (this.unhealthy)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Protected identity registry is unhealthy",
      );
    if (
      sourcePaths.length < 1 ||
      sourcePaths.length > MAX_PROTECTED_SOURCES ||
      new Set(sourcePaths).size !== sourcePaths.length ||
      !sourcePaths.includes("secrets.yaml")
    ) {
      this.unhealthy = true;
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Protected source configuration is outside the safe boundary",
      );
    }
    const staged = new Map<string, ProtectedIdentityMetadata>();
    const sources: ProtectedSource[] = [];
    try {
      for (const path of sourcePaths) {
        assertOperationActive(context);
        if (!relativeConfigPathSchema.safeParse(path).success)
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected source path is invalid",
          );
        const read = await this.reader.read(path, context);
        const key = identityKey(read.identity);
        if (staged.has(key)) {
          read.bytes.fill(0);
          throw new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected source identity alias is ambiguous",
          );
        }
        staged.set(
          key,
          Object.freeze({
            path,
            identity: read.identity,
            sha256: digestBytes(read.bytes),
          }),
        );
        sources.push(Object.freeze({ path, bytes: read.bytes }));
      }
      const values = await provider.loadExactValues(
        Object.freeze(sources),
        context,
      );
      assertOperationActive(context);
      const redactor = new ExactSecretRedactor(values);
      this.identities.clear();
      this.paths.clear();
      for (const [key, value] of staged) {
        this.identities.set(key, value);
        this.paths.set(value.path, value);
      }
      this.redactor = redactor;
    } catch (error) {
      this.unhealthy = true;
      throw error instanceof RepositoryBoundaryError
        ? error
        : new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected identity registration failed",
          );
    } finally {
      for (const source of sources) source.bytes.fill(0);
    }
  }
  async registerMetadataPath(
    path: string,
    context: Phase2OperationContext,
  ): Promise<void> {
    this.assertReady();
    let read: SecureFileRead | undefined;
    try {
      read = await this.reader.read(path, context);
      assertOperationActive(context);
      const metadata = Object.freeze({
        path,
        identity: read.identity,
        sha256: digestBytes(read.bytes),
      });
      this.identities.set(identityKey(read.identity), metadata);
      this.paths.set(path, metadata);
    } catch (error) {
      this.unhealthy = true;
      throw error instanceof RepositoryBoundaryError
        ? error
        : new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected identity registration failed",
          );
    } finally {
      read?.bytes.fill(0);
    }
  }

  async readContent(
    path: string,
    context: Phase2OperationContext,
  ): Promise<SecureFileRead> {
    this.assertReady();
    if (this.paths.has(path))
      throw new RepositoryBoundaryError(
        "protected_resource",
        "Protected resource content is unavailable",
      );
    const read = await this.reader.read(path, context);
    try {
      assertOperationActive(context);
      if (this.identities.has(identityKey(read.identity)))
        throw new RepositoryBoundaryError(
          "protected_resource",
          "Protected resource content is unavailable",
        );
      return read;
    } catch (error) {
      read.bytes.fill(0);
      throw error;
    }
  }
  isProtected(path: string, identity: FileIdentity): boolean {
    this.assertReady();
    return this.paths.has(path) || this.identities.has(identityKey(identity));
  }

  async assertFresh(context: Phase2OperationContext): Promise<void> {
    this.assertReady();
    try {
      for (const expected of this.paths.values()) {
        assertOperationActive(context);
        const read = await this.reader.read(expected.path, context);
        try {
          assertOperationActive(context);
          if (
            identityKey(read.identity) !== identityKey(expected.identity) ||
            digestBytes(read.bytes) !== expected.sha256
          )
            throw new RepositoryBoundaryError(
              "service_unhealthy",
              "Protected source freshness changed",
            );
        } finally {
          read.bytes.fill(0);
        }
      }
    } catch (error) {
      this.unhealthy = true;
      throw error instanceof RepositoryBoundaryError
        ? error
        : new RepositoryBoundaryError(
            "service_unhealthy",
            "Protected source freshness check failed",
          );
    }
  }

  redactWholeText(
    value: string,
    context: Phase2OperationContext,
    maximumBytes = PHASE2_MAX_TEXT_BYTES,
  ): string {
    this.assertReady();
    return this.redactor!.redactWholeText(value, context, maximumBytes);
  }

  redact(value: unknown, context: Phase2OperationContext): unknown {
    this.assertReady();
    return this.redactor!.redact(value, context);
  }

  metadata(): readonly ProtectedIdentityMetadata[] {
    this.assertReady();
    return Object.freeze([...this.identities.values()]);
  }

  private assertReady(): void {
    if (this.unhealthy)
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Protected identity registry is unhealthy",
      );
    if (!this.redactor)
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Repository content is unavailable until protected values are ready",
      );
  }
}

function digestBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function identityKey(identity: FileIdentity): string {
  return `${identity.device}:${identity.inode}`;
}

export function assertOperationActive(context: Phase2OperationContext): void {
  if (context.signal.aborted || Date.now() >= context.deadlineAt)
    throw operationError(context);
}

function operationError(
  context: Phase2OperationContext,
): RepositoryBoundaryError {
  return context.signal.aborted
    ? new RepositoryBoundaryError(
        "operation_cancelled",
        "Operation was cancelled",
      )
    : new RepositoryBoundaryError(
        "deadline_exceeded",
        "Operation deadline expired",
      );
}

async function runHelper(
  helperPath: string,
  root: string,
  path: string,
  maximumBytes: number,
  context: Phase2OperationContext,
): Promise<SecureFileRead> {
  const child = spawn(
    helperPath,
    ["--root", root, "--path", path, "--max-bytes", String(maximumBytes)],
    {
      cwd: root,
      env: {},
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const stdout: Buffer[] = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let settled = false;
  const terminate = () => {
    if (!settled) child.kill("SIGKILL");
  };
  const remaining = context.deadlineAt - Date.now();
  const timer = setTimeout(terminate, Math.max(0, remaining));
  context.signal.addEventListener("abort", terminate, { once: true });
  if (context.signal.aborted) terminate();
  let combined: Buffer | undefined;
  try {
    const exit = await new Promise<{
      code: number | null;
      signal: NodeJS.Signals | null;
    }>((resolve, reject) => {
      child.once("error", reject);
      child.stdout.on("data", (chunk: Buffer) => {
        stdoutBytes += chunk.byteLength;
        if (stdoutBytes > HEADER_BYTES + maximumBytes) {
          chunk.fill(0);
          terminate();
        } else stdout.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderrBytes += chunk.byteLength;
        chunk.fill(0);
        if (stderrBytes > MAX_HELPER_STDERR_BYTES) terminate();
      });
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    settled = true;
    assertOperationActive(context);
    if (
      stderrBytes > MAX_HELPER_STDERR_BYTES ||
      stdoutBytes > HEADER_BYTES + maximumBytes
    )
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Repository helper output exceeded its boundary",
      );
    if (exit.code !== 0 || exit.signal)
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Repository confinement helper failed safely",
      );
    combined = Buffer.concat(stdout);
    return decodeHelperOutput(combined, path, maximumBytes);
  } catch (error) {
    assertOperationActive(context);
    throw error instanceof RepositoryBoundaryError
      ? error
      : new RepositoryBoundaryError(
          "capability_unavailable",
          "Repository confinement helper is unavailable",
        );
  } finally {
    settled = true;
    clearTimeout(timer);
    context.signal.removeEventListener("abort", terminate);
    terminate();
    combined?.fill(0);
    for (const chunk of stdout) chunk.fill(0);
  }
}

export function decodeHelperOutput(
  output: Uint8Array,
  path: string,
  maximumBytes: number,
): SecureFileRead {
  const buffer = Buffer.from(output);
  try {
    if (
      buffer.byteLength < HEADER_BYTES ||
      !buffer.subarray(0, 8).equals(MAGIC) ||
      buffer.readUInt32BE(8) !== 1
    )
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Repository helper protocol was invalid",
      );
    const status = buffer.readUInt32BE(12);
    if (status !== 0) {
      const code: RepositoryBoundaryErrorCode =
        status === 2
          ? "file_too_large"
          : status === 3
            ? "unsupported_encoding"
            : status === 4
              ? "capability_unavailable"
              : "path_denied";
      throw new RepositoryBoundaryError(
        code,
        "Repository helper denied the requested file",
      );
    }
    const size = Number(buffer.readBigUInt64BE(56));
    if (
      !Number.isSafeInteger(size) ||
      size > maximumBytes ||
      buffer.byteLength !== HEADER_BYTES + size
    )
      throw new RepositoryBoundaryError(
        "service_unhealthy",
        "Repository helper length was invalid",
      );
    const bytes = buffer.subarray(HEADER_BYTES);
    if (bytes.includes(0))
      throw new RepositoryBoundaryError(
        "unsupported_encoding",
        "Repository file contains a NUL byte",
      );
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new RepositoryBoundaryError(
        "unsupported_encoding",
        "Repository file is not strict UTF-8",
      );
    }
    return Object.freeze({
      path,
      rootIdentity: Object.freeze({
        device: buffer.readBigUInt64BE(24).toString(),
        inode: buffer.readBigUInt64BE(32).toString(),
      }),
      identity: Object.freeze({
        device: buffer.readBigUInt64BE(40).toString(),
        inode: buffer.readBigUInt64BE(48).toString(),
      }),
      bytes: new Uint8Array(bytes),
    });
  } finally {
    buffer.fill(0);
  }
}
