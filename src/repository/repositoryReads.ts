import { spawn } from "node:child_process";
import {
  createHash,
  createHmac,
  timingSafeEqual,
  type Hash,
} from "node:crypto";
import { isAbsolute } from "node:path";
import {
  PHASE2_MAX_TEXT_BYTES,
  relativeConfigPathSchema,
  repositorySearchQuerySchema,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import {
  BoundedPermitPool,
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  assertOperationActive,
  type FileIdentity,
  type SecureFileReader,
} from "../security/repositoryBoundary.js";

const LIST_MAGIC = Buffer.from("HALIST2\0", "ascii");
const LIST_HEADER_BYTES = 48;
const LIST_RECORD_FIXED_BYTES = 60;
const MAX_LIST_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_STDERR_BYTES = 4096;
export const REPOSITORY_MAX_FILES = 2000;
export const REPOSITORY_MAX_TOTAL_BYTES = 16 * 1024 * 1024;
export const REPOSITORY_MAX_LINES_AND_MATCHES = 200_000;
const CURSOR_PAYLOAD_BYTES = 70;
const CURSOR_BYTES = 102;
const ZERO_HASH = Buffer.alloc(32);
const SNAPSHOT_DOMAIN = Buffer.from("HA_REPOSITORY_SNAPSHOT_V1\0", "ascii");
const SNAPSHOT_RECORD = Buffer.from([1]);
const SNAPSHOT_END = Buffer.from([0xff]);

export interface CatalogDirectory {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly mtimeNanoseconds: string;
  readonly ctimeNanoseconds: string;
}
export interface CatalogFile extends CatalogDirectory {
  readonly size: number;
}
export interface RepositoryCatalog {
  readonly rootIdentity: FileIdentity;
  readonly directories: readonly CatalogDirectory[];
  readonly files: readonly CatalogFile[];
}
export interface RepositoryCatalogProvider {
  catalog(context: Phase2OperationContext): Promise<RepositoryCatalog>;
}

export interface NativeOpenat2CatalogOptions {
  readonly helperPath?: string;
  readonly root?: string;
  readonly platform?: NodeJS.Platform;
  readonly maximumConcurrentHelpers?: number;
}

export class NativeOpenat2Catalog implements RepositoryCatalogProvider {
  private readonly helperPath: string | undefined;
  private readonly root: string;
  private readonly platform: NodeJS.Platform;
  private readonly permits: BoundedPermitPool;

  constructor(options: NativeOpenat2CatalogOptions = {}) {
    this.helperPath = options.helperPath;
    this.root = options.root ?? "/homeassistant";
    this.platform = options.platform ?? process.platform;
    this.permits = new BoundedPermitPool(options.maximumConcurrentHelpers ?? 2);
  }

  async catalog(context: Phase2OperationContext): Promise<RepositoryCatalog> {
    assertOperationActive(context);
    if (
      this.platform !== "linux" ||
      !this.helperPath ||
      !isAbsolute(this.helperPath) ||
      !isAbsolute(this.root)
    )
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Authoritative repository listing is not packaged for this platform",
      );
    const release = await this.permits.acquire(context);
    try {
      const first = await runListHelper(this.helperPath, this.root, context);
      const second = await runListHelper(this.helperPath, this.root, context);
      assertOperationActive(context);
      if (!catalogsMatchExactly(first, second))
        throw new RepositoryBoundaryError(
          "service_unhealthy",
          "Repository catalog changed between required passes",
        );
      return first;
    } finally {
      release();
    }
  }
}

export function decodeCatalogOutput(output: Uint8Array): RepositoryCatalog {
  const buffer = Buffer.from(output);
  try {
    if (
      buffer.byteLength < LIST_HEADER_BYTES ||
      !buffer.subarray(0, 8).equals(LIST_MAGIC) ||
      buffer.readUInt32BE(8) !== 1
    )
      throw unhealthy("Repository catalog protocol is invalid");
    const status = buffer.readUInt32BE(12);
    if (status === 4)
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Repository catalog helper is unavailable",
      );
    if (status !== 0)
      throw unhealthy("Repository catalog helper denied output");
    if (buffer.readUInt32BE(44) !== 0)
      throw unhealthy("Repository catalog success header is not canonical");
    const rootIdentity = Object.freeze({
      device: buffer.readBigUInt64BE(16).toString(),
      inode: buffer.readBigUInt64BE(24).toString(),
    });
    const directoryCount = buffer.readUInt32BE(32);
    const fileCount = buffer.readUInt32BE(36);
    const payloadBytes = buffer.readUInt32BE(40);
    if (
      fileCount > REPOSITORY_MAX_FILES ||
      directoryCount > 4096 ||
      payloadBytes !== buffer.byteLength - LIST_HEADER_BYTES
    )
      throw unhealthy("Repository catalog bounds are invalid");
    const directories: CatalogDirectory[] = [];
    const orderedPaths: string[] = [];
    const files: CatalogFile[] = [];
    let offset = LIST_HEADER_BYTES;
    while (offset < buffer.byteLength) {
      if (offset + LIST_RECORD_FIXED_BYTES > buffer.byteLength)
        throw unhealthy("Repository catalog record is truncated");
      const type = buffer[offset];
      if (buffer[offset + 1] !== 0)
        throw unhealthy("Repository catalog record reserved byte is nonzero");
      const pathBytes = buffer.readUInt16BE(offset + 2);
      const end = offset + LIST_RECORD_FIXED_BYTES + pathBytes;
      if (pathBytes < 1 || pathBytes > 512 || end > buffer.byteLength)
        throw unhealthy("Repository catalog path is outside bounds");
      const rawPath = buffer.subarray(offset + LIST_RECORD_FIXED_BYTES, end);
      let path: string;
      try {
        path = new TextDecoder("utf-8", { fatal: true }).decode(rawPath);
      } catch {
        throw new RepositoryBoundaryError(
          "unsupported_encoding",
          "Repository catalog path encoding is invalid",
        );
      }
      if (
        path !== path.normalize("NFC") ||
        !relativeConfigPathSchema.safeParse(path).success
      )
        throw unhealthy("Repository catalog path is invalid");
      const identity = Object.freeze({
        device: buffer.readBigUInt64BE(offset + 4).toString(),
        inode: buffer.readBigUInt64BE(offset + 12).toString(),
      });
      const mtimeNanoseconds = nanoseconds(buffer, offset + 28, offset + 36);
      const ctimeNanoseconds = nanoseconds(buffer, offset + 44, offset + 52);
      orderedPaths.push(path);
      if (type === 1) {
        if (buffer.readBigUInt64BE(offset + 20) !== 0n)
          throw unhealthy("Repository directory size field is not canonical");
        directories.push(
          Object.freeze({
            path,
            identity,
            mtimeNanoseconds,
            ctimeNanoseconds,
          }),
        );
      } else if (type === 2) {
        if (!/.ya?ml$/u.test(path))
          throw unhealthy("Repository catalog returned a non-YAML file");
        const size = Number(buffer.readBigUInt64BE(offset + 20));
        if (
          !Number.isSafeInteger(size) ||
          size < 0 ||
          size > PHASE2_MAX_TEXT_BYTES
        )
          throw unhealthy("Repository catalog file size is invalid");
        files.push(
          Object.freeze({
            path,
            identity,
            size,
            mtimeNanoseconds,
            ctimeNanoseconds,
          }),
        );
      } else throw unhealthy("Repository catalog record type is invalid");
      offset = end;
    }
    if (directories.length !== directoryCount || files.length !== fileCount)
      throw unhealthy("Repository catalog counts are inconsistent");
    assertUniqueSorted(directories, files, orderedPaths);
    return Object.freeze({
      rootIdentity,
      directories: Object.freeze(directories),
      files: Object.freeze(files),
    });
  } finally {
    buffer.fill(0);
  }
}

function nanoseconds(
  buffer: Buffer,
  secondsOffset: number,
  nanosOffset: number,
): string {
  const nanos = buffer.readBigUInt64BE(nanosOffset);
  if (nanos >= 1_000_000_000n)
    throw unhealthy("Repository timestamp is invalid");
  return (
    buffer.readBigUInt64BE(secondsOffset) * 1_000_000_000n +
    nanos
  ).toString();
}

function assertUniqueSorted(
  directories: CatalogDirectory[],
  files: CatalogFile[],
  orderedPaths: string[],
): void {
  if (new Set(orderedPaths).size !== orderedPaths.length)
    throw unhealthy("Repository catalog contains ambiguous paths");
  for (let index = 1; index < orderedPaths.length; index += 1)
    if (compareUtf8(orderedPaths[index - 1]!, orderedPaths[index]!) >= 0)
      throw unhealthy("Repository catalog is not globally sorted");
  if (directories.length + files.length !== orderedPaths.length)
    throw unhealthy("Repository catalog ordering is inconsistent");
}
async function runListHelper(
  helperPath: string,
  root: string,
  context: Phase2OperationContext,
): Promise<RepositoryCatalog> {
  const child = spawn(helperPath, ["--root", root], {
    cwd: root,
    env: {},
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const chunks: Buffer[] = [];
  let outputBytes = 0;
  let stderrBytes = 0;
  let settled = false;
  const terminate = () => {
    if (!settled) child.kill("SIGKILL");
  };
  const timer = setTimeout(
    terminate,
    Math.max(0, context.deadlineAt - Date.now()),
  );
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
        outputBytes += chunk.byteLength;
        if (outputBytes > MAX_LIST_OUTPUT_BYTES) {
          chunk.fill(0);
          terminate();
        } else chunks.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderrBytes += chunk.byteLength;
        chunk.fill(0);
        if (stderrBytes > MAX_STDERR_BYTES) terminate();
      });
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    settled = true;
    assertOperationActive(context);
    if (exit.code !== 0 || exit.signal || outputBytes > MAX_LIST_OUTPUT_BYTES)
      throw new RepositoryBoundaryError(
        "capability_unavailable",
        "Repository catalog helper failed safely",
      );
    combined = Buffer.concat(chunks);
    return decodeCatalogOutput(combined);
  } catch (error) {
    assertOperationActive(context);
    throw error instanceof RepositoryBoundaryError
      ? error
      : unhealthy("Repository catalog helper failed safely");
  } finally {
    settled = true;
    clearTimeout(timer);
    context.signal.removeEventListener("abort", terminate);
    combined?.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

export function catalogsMatchExactly(
  first: RepositoryCatalog,
  second: RepositoryCatalog,
): boolean {
  return canonicalCatalog(first) === canonicalCatalog(second);
}

function canonicalCatalog(catalog: RepositoryCatalog): string {
  return JSON.stringify(catalog);
}

export type RepositoryCursorOperation = "list" | "search" | "resource-list";
function cursorOperationByte(operation: RepositoryCursorOperation): number {
  if (operation === "list") return 1;
  if (operation === "search") return 2;
  return 3;
}
export interface DecodedRepositoryCursor {
  readonly offset: number;
  readonly querySha256: string;
  readonly snapshotSha256: string;
}

export class RepositoryCursorCodec {
  private readonly key: Buffer;
  private closed = false;
  constructor(key: Uint8Array) {
    if (key.byteLength < 32)
      throw new TypeError("Repository cursor key must be at least 32 bytes");
    this.key = Buffer.from(key);
  }
  close(): void {
    this.key.fill(0);
    this.closed = true;
  }
  encode(
    operation: RepositoryCursorOperation,
    offset: number,
    querySha256: string,
    snapshotSha256: string,
  ): string {
    if (this.closed) throw invalidInput("Repository cursor key is closed");
    if (!Number.isInteger(offset) || offset < 0 || offset > 0xffffffff)
      throw unhealthy("Repository cursor offset is invalid");
    let payload: Buffer | undefined;
    let queryDigest: Buffer | undefined;
    let snapshotDigest: Buffer | undefined;
    let mac: Buffer | undefined;
    let combined: Buffer | undefined;
    try {
      payload = Buffer.alloc(CURSOR_PAYLOAD_BYTES);
      queryDigest = operation === "list" ? undefined : hashBuffer(querySha256);
      snapshotDigest = hashBuffer(snapshotSha256);
      payload[0] = 1;
      payload[1] = cursorOperationByte(operation);
      payload.writeUInt32BE(offset, 2);
      (queryDigest ?? ZERO_HASH).copy(payload, 6);
      snapshotDigest.copy(payload, 38);
      mac = createHmac("sha256", this.key).update(payload).digest();
      combined = Buffer.concat([payload, mac]);
      const encoded = combined.toString("base64url");
      if (encoded.length !== 136)
        throw unhealthy("Repository cursor encoding failed");
      return encoded;
    } finally {
      combined?.fill(0);
      mac?.fill(0);
      snapshotDigest?.fill(0);
      queryDigest?.fill(0);
      payload?.fill(0);
    }
  }
  decode(
    encoded: string,
    operation: RepositoryCursorOperation,
    querySha256: string,
  ): DecodedRepositoryCursor {
    if (this.closed) throw invalidInput("Repository cursor key is closed");
    if (!/^[A-Za-z0-9_-]{136}$/u.test(encoded))
      throw invalidInput("Repository cursor structure is invalid");
    let bytes: Buffer | undefined;
    let expectedMac: Buffer | undefined;
    let expectedQuery: Buffer | undefined;
    try {
      bytes = Buffer.from(encoded, "base64url");
      if (
        bytes.byteLength !== CURSOR_BYTES ||
        bytes.toString("base64url") !== encoded
      )
        throw invalidInput("Repository cursor encoding is invalid");
      const payload = bytes.subarray(0, CURSOR_PAYLOAD_BYTES);
      expectedMac = createHmac("sha256", this.key).update(payload).digest();
      if (
        !timingSafeEqual(expectedMac, bytes.subarray(CURSOR_PAYLOAD_BYTES)) ||
        payload[0] !== 1 ||
        payload[1] !== cursorOperationByte(operation)
      )
        throw invalidInput("Repository cursor authentication failed");
      const query = payload.subarray(6, 38);
      expectedQuery =
        operation === "list" ? undefined : hashBuffer(querySha256);
      if (!timingSafeEqual(query, expectedQuery ?? ZERO_HASH))
        throw invalidInput("Repository cursor query is invalid");
      return Object.freeze({
        offset: payload.readUInt32BE(2),
        querySha256: query.toString("hex"),
        snapshotSha256: payload.subarray(38, 70).toString("hex"),
      });
    } finally {
      expectedQuery?.fill(0);
      expectedMac?.fill(0);
      bytes?.fill(0);
    }
  }
}
export interface RepositoryFileSummary {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}
export interface RepositorySearchResult {
  readonly path: string;
  readonly line: number;
  readonly snippet: string;
}
export interface RepositoryPage<T> {
  readonly items: readonly T[];
  readonly nextCursor: string | null;
  readonly snapshotSha256: string;
}

export class RepositoryReadService {
  constructor(
    private readonly catalogs: RepositoryCatalogProvider,
    private readonly reader: SecureFileReader,
    private readonly protectedRegistry: ProtectedIdentityRegistry,
    private readonly cursors: RepositoryCursorCodec,
  ) {}

  async list(
    input: { readonly cursor?: string; readonly limit: number },
    context: Phase2OperationContext,
  ): Promise<RepositoryPage<RepositoryFileSummary>> {
    return this.sanitize(async () => {
      assertLimit(input.limit);
      const decoded = input.cursor
        ? this.cursors.decode(input.cursor, "list", "0".repeat(64))
        : undefined;
      const index = await this.buildIndex(context);
      this.validateCursor(decoded, index.snapshotSha256, index.files.length);
      const offset = decoded?.offset ?? 0;
      const items = index.files.slice(offset, offset + input.limit);
      await this.protectedRegistry.assertFresh(context);
      return Object.freeze({
        items: Object.freeze(items),
        nextCursor:
          offset + items.length < index.files.length
            ? this.cursors.encode(
                "list",
                offset + items.length,
                "0".repeat(64),
                index.snapshotSha256,
              )
            : null,
        snapshotSha256: index.snapshotSha256,
      });
    });
  }

  async read(
    path: string,
    context: Phase2OperationContext,
  ): Promise<RepositoryFileSummary & { readonly content: string }> {
    return this.sanitize(async () => {
      if (!relativeConfigPathSchema.safeParse(path).success)
        throw new RepositoryBoundaryError(
          "path_denied",
          "Repository path is denied",
        );
      const catalog = await this.catalogs.catalog(context);
      const entry = catalog.files.find((file) => file.path === path);
      if (
        !entry ||
        this.protectedRegistry.isProtected(entry.path, entry.identity)
      )
        throw new RepositoryBoundaryError(
          "path_denied",
          "Repository file is unavailable",
        );
      await this.protectedRegistry.assertFresh(context);
      const read = await this.reader.read(path, context);
      try {
        validateRead(
          entry,
          catalog.rootIdentity,
          read.identity,
          read.rootIdentity,
          read.bytes.byteLength,
        );
        const sha256 = digest(read.bytes);
        const content = new TextDecoder("utf-8", { fatal: true }).decode(
          read.bytes,
        );
        const redacted = this.protectedRegistry.redactWholeText(
          content,
          context,
        );
        await this.protectedRegistry.assertFresh(context);
        return Object.freeze({
          path,
          sha256,
          bytes: read.bytes.byteLength,
          content: redacted,
        });
      } finally {
        read.bytes.fill(0);
      }
    });
  }

  async search(
    input: {
      readonly query: string;
      readonly cursor?: string;
      readonly limit: number;
    },
    context: Phase2OperationContext,
  ): Promise<RepositoryPage<RepositorySearchResult>> {
    return this.sanitize(async () => {
      assertLimit(input.limit);
      if (!repositorySearchQuerySchema.safeParse(input.query).success)
        throw invalidInput("Repository search query is invalid");
      const querySha256 = digestOwnedText(input.query);
      if (
        this.protectedRegistry.redactWholeText(input.query, context, 512) !==
        input.query
      )
        throw new RepositoryBoundaryError(
          "protected_resource",
          "Search query is protected",
        );
      const decoded = input.cursor
        ? this.cursors.decode(input.cursor, "search", querySha256)
        : undefined;
      const offset = decoded?.offset ?? 0;
      const scanned = await this.buildIndex(
        context,
        input.query,
        offset,
        input.limit,
      );
      this.validateCursor(decoded, scanned.snapshotSha256, scanned.matchCount);
      await this.protectedRegistry.assertFresh(context);
      return Object.freeze({
        items: Object.freeze(scanned.matches),
        nextCursor:
          offset + scanned.matches.length < scanned.matchCount
            ? this.cursors.encode(
                "search",
                offset + scanned.matches.length,
                querySha256,
                scanned.snapshotSha256,
              )
            : null,
        snapshotSha256: scanned.snapshotSha256,
      });
    });
  }

  private async buildIndex(
    context: Phase2OperationContext,
    query?: string,
    offset = 0,
    limit = 0,
  ): Promise<{
    files: RepositoryFileSummary[];
    snapshotSha256: string;
    matches: RepositorySearchResult[];
    matchCount: number;
  }> {
    await this.protectedRegistry.assertFresh(context);
    const catalog = await this.catalogs.catalog(context);
    if (catalog.files.length > REPOSITORY_MAX_FILES)
      throw unhealthy("Repository file count exceeded its boundary");
    let totalBytes = 0;
    let work = 0;
    const literalSearch =
      query === undefined
        ? undefined
        : new BoundedLiteralSearch(query, context);
    let matchCount = 0;
    const files: RepositoryFileSummary[] = [];
    const matches: RepositorySearchResult[] = [];
    const snapshot = createHash("sha256");
    snapshot.update(SNAPSHOT_DOMAIN);
    const entries = [...catalog.files].sort((a, b) =>
      compareUtf8(a.path, b.path),
    );
    if (new Set(entries.map((entry) => entry.path)).size !== entries.length)
      throw unhealthy("Repository catalog contains ambiguous paths");
    for (const entry of entries) {
      if ((work++ & 255) === 0) assertOperationActive(context);
      if (this.protectedRegistry.isProtected(entry.path, entry.identity))
        continue;
      totalBytes += entry.size;
      if (totalBytes > REPOSITORY_MAX_TOTAL_BYTES)
        throw unhealthy("Repository aggregate bytes exceeded its boundary");
      const read = await this.reader.read(entry.path, context);
      try {
        validateRead(
          entry,
          catalog.rootIdentity,
          read.identity,
          read.rootIdentity,
          read.bytes.byteLength,
        );
        const sha256 = digest(read.bytes);
        files.push(
          Object.freeze({
            path: entry.path,
            sha256,
            bytes: read.bytes.byteLength,
          }),
        );
        updateSnapshotFile(snapshot, entry, sha256);
        if (literalSearch) {
          const content = new TextDecoder("utf-8", { fatal: true }).decode(
            read.bytes,
          );
          const lines = content.split(/\r?\n/u);
          for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
            literalSearch.charge();
            const line = lines[lineIndex]!;
            if (literalSearch.find(line) < 0) continue;
            const redacted = this.protectedRegistry.redactWholeText(
              line,
              context,
            );
            const surviving = literalSearch.find(redacted);
            if (surviving < 0) continue;
            literalSearch.charge();
            matchCount += 1;
            if (matchCount > offset && matches.length < limit + 1)
              matches.push(
                Object.freeze({
                  path: entry.path,
                  line: lineIndex + 1,
                  snippet: clipSnippet(redacted, surviving),
                }),
              );
          }
        }
      } finally {
        read.bytes.fill(0);
      }
    }
    files.sort((a, b) => compareUtf8(a.path, b.path));
    finishSnapshot(snapshot, files.length);
    const snapshotSha256 = snapshot.digest("hex");
    return {
      files,
      snapshotSha256,
      matches: matches.slice(0, limit),
      matchCount,
    };
  }

  private validateCursor(
    cursor: DecodedRepositoryCursor | undefined,
    snapshotSha256: string,
    serviceBound: number,
  ): void {
    if (
      cursor &&
      (cursor.snapshotSha256 !== snapshotSha256 || cursor.offset > serviceBound)
    )
      throw staleSource("Repository cursor is stale or outside service bounds");
  }

  private async sanitize<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      throw error instanceof RepositoryBoundaryError
        ? error
        : unhealthy("Repository read service failed safely");
    }
  }
}

function assertLimit(limit: number): void {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500)
    throw invalidInput("Repository page limit is invalid");
}

function validateRead(
  entry: CatalogFile,
  catalogRootIdentity: FileIdentity,
  identity: FileIdentity,
  readRootIdentity: FileIdentity,
  size: number,
): void {
  if (
    catalogRootIdentity.device !== readRootIdentity.device ||
    catalogRootIdentity.inode !== readRootIdentity.inode ||
    entry.identity.device !== identity.device ||
    entry.identity.inode !== identity.inode ||
    entry.size !== size
  )
    throw unhealthy("Repository root or file changed after cataloging");
}

function updateSnapshotFile(
  snapshot: Hash,
  entry: CatalogFile,
  contentSha256: string,
): void {
  snapshot.update(SNAPSHOT_RECORD);
  updateSnapshotField(snapshot, entry.path);
  updateSnapshotField(snapshot, entry.identity.device);
  updateSnapshotField(snapshot, entry.identity.inode);
  const contentDigest = hashBuffer(contentSha256);
  try {
    snapshot.update(contentDigest);
  } finally {
    contentDigest.fill(0);
  }
}

function updateSnapshotField(snapshot: Hash, value: string): void {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  try {
    length.writeUInt32BE(bytes.byteLength);
    snapshot.update(length);
    snapshot.update(bytes);
  } finally {
    length.fill(0);
    bytes.fill(0);
  }
}

function finishSnapshot(snapshot: Hash, fileCount: number): void {
  const count = Buffer.alloc(4);
  try {
    count.writeUInt32BE(fileCount);
    snapshot.update(SNAPSHOT_END);
    snapshot.update(count);
  } finally {
    count.fill(0);
  }
}

class BoundedLiteralSearch {
  private readonly prefix: Uint32Array;
  private work = 0;

  constructor(
    private readonly query: string,
    private readonly context: Phase2OperationContext,
  ) {
    this.prefix = new Uint32Array(query.length);
    let matched = 0;
    for (let index = 1; index < query.length; index += 1) {
      let equal = this.equal(query, index, query, matched);
      while (!equal && matched > 0) {
        matched = this.prefix[matched - 1]!;
        equal = this.equal(query, index, query, matched);
      }
      if (equal) matched += 1;
      this.prefix[index] = matched;
    }
  }

  charge(): void {
    if ((this.work & 255) === 0) assertOperationActive(this.context);
    this.work += 1;
    if (this.work > REPOSITORY_MAX_LINES_AND_MATCHES)
      throw unhealthy("Repository search work exceeded its boundary");
  }

  find(text: string): number {
    let matched = 0;
    for (let index = 0; index < text.length; index += 1) {
      let equal = this.equal(text, index, this.query, matched);
      while (!equal && matched > 0) {
        matched = this.prefix[matched - 1]!;
        equal = this.equal(text, index, this.query, matched);
      }
      if (!equal) continue;
      matched += 1;
      if (matched === this.query.length) return index - this.query.length + 1;
    }
    return -1;
  }

  private equal(
    left: string,
    leftIndex: number,
    right: string,
    rightIndex: number,
  ): boolean {
    this.charge();
    return left.charCodeAt(leftIndex) === right.charCodeAt(rightIndex);
  }
}
function clipSnippet(line: string, matchOffset: number): string {
  const before = Array.from(line.slice(0, matchOffset)).length;
  const scalars = Array.from(line);
  const start = Math.max(0, Math.min(before - 500, scalars.length - 1000));
  return scalars.slice(start, start + 1000).join("");
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}
function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function digestOwnedText(value: string): string {
  const bytes = Buffer.from(value, "utf8");
  try {
    return digest(bytes);
  } finally {
    bytes.fill(0);
  }
}
function hashBuffer(hex: string): Buffer {
  if (!/^[a-f0-9]{64}$/u.test(hex))
    throw unhealthy("Repository digest is invalid");
  return Buffer.from(hex, "hex");
}
function invalidInput(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("invalid_input", message);
}
function staleSource(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("stale_source", message);
}
function unhealthy(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("service_unhealthy", message);
}
