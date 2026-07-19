import { createHash } from "node:crypto";
import { setImmediate as yieldImmediate } from "node:timers/promises";
import {
  Composer,
  LineCounter,
  Parser,
  isAlias,
  isCollection,
  isMap,
  isPair,
  isScalar,
  type Alias,
  type Document,
  type Node,
  type Pair,
  type ScalarTag,
} from "yaml";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../phase2Contracts.js";

const PARSER_CHUNK_CODE_UNITS = 4096;
const MAX_DEPTH = 64;
const MAX_NODES = 100_000;
const MAX_REFERENCES = 100;
const MAX_ANCHOR_FANOUT = 100;
const MAX_REFERENCE_BYTES = 512;
const MAX_AGGREGATE_REFERENCE_BYTES = 32 * 1024;
const MAX_METADATA_BYTES = 32 * 1024;

export const yamlGateErrorCodes = [
  "file_too_large",
  "unsupported_encoding",
  "invalid_line_endings",
  "invalid_directive",
  "multiple_documents",
  "yaml_syntax",
  "yaml_warning",
  "tag_denied",
  "tagged_value_invalid",
  "key_invalid",
  "duplicate_key",
  "merge_key_denied",
  "reference_limit_exceeded",
  "node_limit_exceeded",
  "depth_limit_exceeded",
  "alias_limit_exceeded",
  "duplicate_anchor",
  "unresolved_alias",
  "alias_cycle",
  "metadata_too_large",
  "deadline_exceeded",
  "operation_cancelled",
  "internal_failure",
] as const;

export type YamlGateErrorCode = (typeof yamlGateErrorCodes)[number];

export class YamlGateError extends Error {
  readonly code: YamlGateErrorCode;
  readonly line: number;
  readonly column: number;

  constructor(code: YamlGateErrorCode, line = 1, column = 1) {
    super(code);
    this.name = "YamlGateError";
    this.code = code;
    this.line = line;
    this.column = column;
  }
}

export type YamlReferenceMetadata =
  | Readonly<{
      tag: Exclude<AllowedTag, "!secret">;
      path: readonly number[];
      value: string;
    }>
  | Readonly<{
      tag: "!secret";
      path: readonly number[];
      valueSha256: string;
      byteLength: number;
    }>;

export interface StrictYamlMetadata {
  readonly sha256: string;
  readonly empty: boolean;
  readonly explicitEmpty: boolean;
  readonly lineEndings: "none" | "lf" | "crlf";
  readonly documentCount: 0 | 1;
  readonly nodeCount: number;
  readonly expandedNodeCount: number;
  readonly maximumDepth: number;
  readonly aliasReferences: number;
  readonly references: readonly YamlReferenceMetadata[];
}

export interface YamlSourceRange {
  readonly startByte: number;
  readonly endByte: number;
}

export type ProjectedYamlNode =
  | Readonly<{
      kind: "map";
      entries: readonly ProjectedYamlMapEntry[];
      anchored: boolean;
      sourceRange?: YamlSourceRange | undefined;
    }>
  | Readonly<{
      kind: "sequence";
      items: readonly ProjectedYamlNode[];
      anchored: boolean;
      sourceRange?: YamlSourceRange | undefined;
    }>
  | Readonly<{
      kind: "scalar";
      scalarType: "string" | "number" | "boolean" | "null";
      identity?: string | undefined;
      anchored: boolean;
      sourceRange?: YamlSourceRange | undefined;
    }>
  | Readonly<{
      kind: "include";
      tag:
        | "!include"
        | "!include_dir_list"
        | "!include_dir_merge_list"
        | "!include_dir_named"
        | "!include_dir_merge_named";
      value: string;
      sourceRange?: YamlSourceRange | undefined;
    }>
  | Readonly<{
      kind: "secret";
      sourceRange: YamlSourceRange;
    }>
  | Readonly<{
      kind: "input";
      sourceRange?: YamlSourceRange | undefined;
    }>
  | Readonly<{
      kind: "alias";
      sourceRange?: YamlSourceRange | undefined;
    }>;

export interface ProjectedYamlMapEntry {
  readonly keyType: "string" | "number" | "boolean" | "null";
  readonly key?: string | undefined;
  readonly value: ProjectedYamlNode | null;
  readonly sourceRange?: YamlSourceRange | undefined;
}

export interface StrictYamlProjection {
  readonly metadata: StrictYamlMetadata;
  readonly root: ProjectedYamlNode | null;
  readonly retainedNodeCount: number;
  readonly retainedStringBytes: number;
}
const allowedTags = [
  "!include",
  "!include_dir_list",
  "!include_dir_merge_list",
  "!include_dir_named",
  "!include_dir_merge_named",
  "!secret",
  "!input",
] as const;
type AllowedTag = (typeof allowedTags)[number];
const allowedTagSet = new Set<string>(allowedTags);

const customTags: ScalarTag[] = allowedTags.map((tag) => ({
  tag,
  identify: () => false,
  resolve: (value: string) => value,
}));

const composerOptions = {
  version: "1.2" as const,
  schema: "core",
  strict: true,
  uniqueKeys: true,
  merge: false,
  resolveKnownTags: false,
  prettyErrors: false,
  logLevel: "warn" as const,
  customTags,
};

interface GateClock {
  readonly deadline: number;
  readonly signal: AbortSignal;
}

export async function validateStrictYaml(
  input: Uint8Array,
  context: Phase2OperationContext,
): Promise<StrictYamlMetadata> {
  return (await validateYamlPrimitive(input, context, false)).metadata;
}

export async function validateAndProjectYaml(
  input: Uint8Array,
  context: Phase2OperationContext,
): Promise<StrictYamlProjection> {
  const result = await validateYamlPrimitive(input, context, true);
  if (!result.projection) throw new YamlGateError("internal_failure");
  return result.projection;
}

async function validateYamlPrimitive(
  input: Uint8Array,
  context: Phase2OperationContext,
  project: boolean,
): Promise<{
  readonly metadata: StrictYamlMetadata;
  readonly projection?: StrictYamlProjection;
}> {
  if (!(input instanceof Uint8Array))
    throw new YamlGateError("unsupported_encoding");
  if (input.byteLength > PHASE2_MAX_TEXT_BYTES)
    throw new YamlGateError("file_too_large");
  const snapshot = Buffer.from(input);
  try {
    const clock: GateClock = {
      deadline:
        performance.now() + Math.max(0, context.deadlineAt - Date.now()),
      signal: context.signal,
    };
    checkOperation(clock);
    const sha256 = createHash("sha256").update(snapshot).digest("hex");
    const text = decodeAndPreflight(snapshot);
    const lineEndings = detectLineEndings(text);
    const parsed = await parseIncrementally(text, clock);
    checkOperation(clock);
    const metadata = validateDocument(parsed, sha256, lineEndings, clock);
    checkOperation(clock);
    if (
      Buffer.byteLength(JSON.stringify(metadata), "utf8") > MAX_METADATA_BYTES
    )
      throw new YamlGateError("metadata_too_large");
    const frozenMetadata = deepFreeze(metadata);
    checkOperation(clock);
    if (!project) return Object.freeze({ metadata: frozenMetadata });
    const projectionWork = new ProjectionWork(clock);
    const projectionState = new ProjectionState(text, projectionWork);
    const root = parsed.documents[0]?.contents
      ? projectionState.project(parsed.documents[0].contents)
      : null;
    checkOperation(clock);
    const projection = deepFreezeProjection(
      {
        metadata: frozenMetadata,
        root,
        retainedNodeCount: projectionState.nodes,
        retainedStringBytes: projectionState.stringBytes,
      },
      projectionWork,
    );
    checkOperation(clock);
    return Object.freeze({ metadata: frozenMetadata, projection });
  } catch (error) {
    if (error instanceof YamlGateError) throw error;
    throw new YamlGateError("internal_failure");
  } finally {
    snapshot.fill(0);
  }
}
function decodeAndPreflight(snapshot: Uint8Array): string {
  if (
    snapshot.byteLength >= 3 &&
    snapshot[0] === 0xef &&
    snapshot[1] === 0xbb &&
    snapshot[2] === 0xbf
  )
    throw new YamlGateError("unsupported_encoding");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(snapshot);
  } catch {
    throw new YamlGateError("unsupported_encoding");
  }
  if (text.includes("\u0000") || text.includes("\ufeff"))
    throw new YamlGateError("unsupported_encoding");
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) === 0x0d && text.charCodeAt(index + 1) !== 0x0a)
      throw atOffset("invalid_line_endings", text, index);
  }
  const hasLf = /(^|[^\r])\n/u.test(text);
  const hasCrlf = text.includes("\r\n");
  if (hasLf && hasCrlf) throw new YamlGateError("invalid_line_endings");
  const directive = /^(?:%YAML|%TAG)(?:[ \t]|$)/mu.exec(text);
  if (directive) throw atOffset("invalid_directive", text, directive.index);
  return text;
}

function detectLineEndings(text: string): StrictYamlMetadata["lineEndings"] {
  if (text.includes("\r\n")) return "crlf";
  if (text.includes("\n")) return "lf";
  return "none";
}

interface ParsedStream {
  readonly documents: readonly Document.Parsed[];
  readonly explicitDocument: boolean;
  readonly lineCounter: LineCounter;
}

async function parseIncrementally(
  text: string,
  clock: GateClock,
): Promise<ParsedStream> {
  const lineCounter = new LineCounter();
  const parser = new Parser(lineCounter.addNewLine);
  const composer = new Composer({ ...composerOptions, lineCounter });
  const documents: Document.Parsed[] = [];
  let explicitDocument = false;

  const consume = (
    tokens: Iterable<
      ReturnType<Parser["parse"]> extends Generator<infer T> ? T : never
    >,
  ) => {
    for (const token of tokens) {
      if (token.type === "error")
        throw located("yaml_syntax", lineCounter, token.offset);
      if (token.type === "directive")
        throw located("invalid_directive", lineCounter, token.offset);
      if (
        token.type === "document" &&
        token.start.some((part) => part.type === "doc-start")
      )
        explicitDocument = true;
      for (const document of composer.next(token)) {
        rejectDocumentDiagnostics(document, lineCounter);
        documents.push(document);
        if (documents.length > 1) throw new YamlGateError("multiple_documents");
      }
    }
  };

  for (let start = 0; start < text.length; ) {
    checkOperation(clock);
    let end = Math.min(start + PARSER_CHUNK_CODE_UNITS, text.length);
    if (end < text.length && isHighSurrogate(text.charCodeAt(end - 1)))
      end -= 1;
    consume(parser.parse(text.slice(start, end), end < text.length));
    checkOperation(clock);
    start = end;
    await yieldImmediate();
    checkOperation(clock);
  }
  consume(parser.end());
  for (const document of composer.end(false, text.length)) {
    rejectDocumentDiagnostics(document, lineCounter);
    documents.push(document);
    if (documents.length > 1) throw new YamlGateError("multiple_documents");
  }
  const streamInfo = composer.streamInfo();
  rejectDiagnostics(streamInfo.errors, streamInfo.warnings, lineCounter);
  return { documents, explicitDocument, lineCounter };
}

function rejectDocumentDiagnostics(
  document: Document.Parsed,
  lineCounter: LineCounter,
): void {
  rejectDiagnostics(document.errors, document.warnings, lineCounter);
}

function rejectDiagnostics(
  errors: readonly { pos: [number, number] }[],
  warnings: readonly { pos: [number, number] }[],
  lineCounter: LineCounter,
): void {
  const error = errors[0];
  if (error) throw located("yaml_syntax", lineCounter, error.pos[0]);
  const warning = warnings[0];
  if (warning) throw located("yaml_warning", lineCounter, warning.pos[0]);
}

function validateDocument(
  stream: ParsedStream,
  sha256: string,
  lineEndings: StrictYamlMetadata["lineEndings"],
  clock: GateClock,
): StrictYamlMetadata {
  const document = stream.documents[0];
  if (!document) {
    return {
      sha256,
      empty: true,
      explicitEmpty: false,
      lineEndings,
      documentCount: 0,
      nodeCount: 0,
      expandedNodeCount: 0,
      maximumDepth: 0,
      aliasReferences: 0,
      references: [],
    };
  }
  if (document.errors.length || document.warnings.length)
    rejectDocumentDiagnostics(document, stream.lineCounter);

  const state = new ValidationState(document, stream.lineCounter, clock);
  state.countStructuralDocument();
  checkOperation(clock);
  state.countExpandedDocument();
  checkOperation(clock);
  const emptyContents =
    document.contents === null ||
    (isScalar(document.contents) &&
      document.contents.value === null &&
      document.contents.source === "");
  return {
    sha256,
    empty: emptyContents,
    explicitEmpty: emptyContents && stream.explicitDocument,
    lineEndings,
    documentCount: 1,
    nodeCount: state.structuralNodes,
    expandedNodeCount: state.expandedNodes,
    maximumDepth: state.maximumDepth,
    aliasReferences: state.aliasReferences,
    references: state.references,
  };
}

class ValidationState {
  structuralNodes = 0;
  expandedNodes = 0;
  maximumDepth = 0;
  aliasReferences = 0;
  readonly references: YamlReferenceMetadata[] = [];
  private referenceBytes = 0;
  private readonly anchors = new Map<string, Node>();
  private readonly aliases: { alias: Alias; path: number[] }[] = [];
  private readonly anchorFanout = new Map<Node, number>();
  private workUnits = 0;

  constructor(
    private readonly document: Document.Parsed,
    private readonly lineCounter: LineCounter,
    private readonly clock: GateClock,
  ) {}

  countStructuralDocument(): void {
    this.bumpStructural(0);
    if (this.document.contents)
      this.visitStructural(this.document.contents, 1, []);
    for (const { alias } of this.aliases) {
      this.pollOperation();
      const target = alias.resolve(this.document);
      if (!target) throw this.errorAt("unresolved_alias", alias);
      const fanout = (this.anchorFanout.get(target) ?? 0) + 1;
      this.anchorFanout.set(target, fanout);
      if (fanout > MAX_ANCHOR_FANOUT)
        throw this.errorAt("alias_limit_exceeded", alias);
    }
  }

  countExpandedDocument(): void {
    this.bumpExpanded();
    if (this.document.contents)
      this.visitExpanded(this.document.contents, new Set<Node>());
  }

  private visitStructural(
    value: Node | Pair,
    depth: number,
    path: number[],
  ): void {
    this.bumpStructural(depth);
    if (isPair(value)) {
      this.validateKey(value.key);
      if (value.key)
        this.visitStructural(value.key as Node, depth + 1, [...path, 0]);
      if (value.value)
        this.visitStructural(value.value as Node, depth + 1, [...path, 1]);
      return;
    }
    this.registerAnchor(value);
    this.validateTag(value, path);
    if (isAlias(value)) {
      this.aliasReferences += 1;
      if (this.aliasReferences > MAX_REFERENCES)
        throw this.errorAt("alias_limit_exceeded", value);
      this.aliases.push({ alias: value, path });
      return;
    }
    if (isMap(value)) this.validateMapKeys(value.items);
    if (isCollection(value)) {
      for (let index = 0; index < value.items.length; index += 1) {
        const item = value.items[index];
        if (
          isPair(item) ||
          isScalar(item) ||
          isCollection(item) ||
          isAlias(item)
        )
          this.visitStructural(item, depth + 1, [...path, index]);
      }
    }
  }

  private visitExpanded(value: Node | Pair, stack: Set<Node>): void {
    this.bumpExpanded();
    if (isPair(value)) {
      if (value.key) this.visitExpanded(value.key as Node, stack);
      if (value.value) this.visitExpanded(value.value as Node, stack);
      return;
    }
    if (isAlias(value)) {
      const target = value.resolve(this.document);
      if (!target) throw this.errorAt("unresolved_alias", value);
      if (stack.has(target)) throw this.errorAt("alias_cycle", value);
      const nextStack = new Set(stack);
      nextStack.add(target);
      this.visitExpanded(target, nextStack);
      return;
    }
    const nextStack = new Set(stack);
    if (value.anchor) nextStack.add(value);
    if (isCollection(value)) {
      for (const item of value.items) {
        if (
          isPair(item) ||
          isScalar(item) ||
          isCollection(item) ||
          isAlias(item)
        )
          this.visitExpanded(item, nextStack);
      }
    }
  }

  private validateMapKeys(items: Pair[]): void {
    const seen = new Set<string>();
    for (const pair of items) {
      this.pollOperation();
      const key = pair.key;
      if (!isScalar(key)) throw this.errorAt("key_invalid", pair);
      const identity = keyIdentity(key);
      if (key.value === "<<") throw this.errorAt("merge_key_denied", key);
      if (seen.has(identity)) throw this.errorAt("duplicate_key", key);
      seen.add(identity);
    }
  }

  private validateKey(value: unknown): void {
    if (!isScalar(value) || value.tag || value.anchor)
      throw this.errorAt("key_invalid", value);
    const primitive = value.value;
    if (
      primitive !== null &&
      typeof primitive !== "string" &&
      typeof primitive !== "boolean" &&
      typeof primitive !== "number"
    )
      throw this.errorAt("key_invalid", value);
    if (typeof primitive === "number" && !Number.isFinite(primitive))
      throw this.errorAt("key_invalid", value);
  }

  private validateTag(value: Node, path: number[]): void {
    this.pollOperation();
    if (!value.tag) return;
    if (!allowedTagSet.has(value.tag)) throw this.errorAt("tag_denied", value);
    if (!isScalar(value) || typeof value.value !== "string")
      throw this.errorAt("tagged_value_invalid", value);
    const bytes = Buffer.byteLength(value.value, "utf8");
    if (bytes > MAX_REFERENCE_BYTES)
      throw this.errorAt("reference_limit_exceeded", value);
    this.referenceBytes += bytes;
    if (
      this.references.length >= MAX_REFERENCES ||
      this.referenceBytes > MAX_AGGREGATE_REFERENCE_BYTES
    )
      throw this.errorAt("reference_limit_exceeded", value);
    const tag = value.tag as AllowedTag;
    const frozenPath = Object.freeze([...path]);
    if (tag === "!secret") {
      this.references.push(
        Object.freeze({
          tag,
          path: frozenPath,
          valueSha256: createHash("sha256").update(value.value).digest("hex"),
          byteLength: bytes,
        }),
      );
    } else {
      this.references.push(
        Object.freeze({ tag, path: frozenPath, value: value.value }),
      );
    }
  }

  private registerAnchor(value: Node): void {
    if (!value.anchor) return;
    if (this.anchors.has(value.anchor))
      throw this.errorAt("duplicate_anchor", value);
    this.anchors.set(value.anchor, value);
  }

  private bumpStructural(depth: number): void {
    this.pollOperation();
    this.structuralNodes += 1;
    if (this.structuralNodes > MAX_NODES)
      throw new YamlGateError("node_limit_exceeded");
    this.bumpDepth(depth);
  }

  private bumpExpanded(): void {
    this.pollOperation();
    this.expandedNodes += 1;
    if (this.expandedNodes > MAX_NODES)
      throw new YamlGateError("node_limit_exceeded");
  }

  private bumpDepth(depth: number): void {
    this.maximumDepth = Math.max(this.maximumDepth, depth);
    if (depth > MAX_DEPTH) throw new YamlGateError("depth_limit_exceeded");
  }

  private pollOperation(): void {
    this.workUnits += 1;
    if (this.workUnits % 256 === 0) checkOperation(this.clock);
  }

  private errorAt(code: YamlGateErrorCode, value: unknown): YamlGateError {
    const range =
      typeof value === "object" && value !== null && "range" in value
        ? (value as { range?: readonly number[] }).range
        : undefined;
    return located(code, this.lineCounter, range?.[0] ?? 0);
  }
}

const projectionIdentityKeys = new Set(["id", "name", "domain"]);

class ProjectionWork {
  private units = 0;

  constructor(private readonly clock: GateClock) {}

  poll(): void {
    if ((this.units & 255) === 0) checkOperation(this.clock);
    this.units += 1;
  }
}

class ProjectionState {
  nodes = 0;
  stringBytes = 0;
  private readonly byteOffsets: Uint32Array;

  constructor(
    text: string,
    private readonly work: ProjectionWork,
  ) {
    this.byteOffsets = buildByteOffsets(text, work);
  }

  project(node: Node, parentKey?: string): ProjectedYamlNode {
    this.bump();
    const sourceRange = this.range(node);
    if (isAlias(node)) return Object.freeze({ kind: "alias", sourceRange });
    if (node.tag === "!secret") {
      if (!sourceRange) throw new YamlGateError("internal_failure");
      return Object.freeze({ kind: "secret", sourceRange });
    }
    if (node.tag === "!input")
      return Object.freeze({ kind: "input", sourceRange });
    if (node.tag && node.tag.startsWith("!include")) {
      if (!isScalar(node) || typeof node.value !== "string")
        throw new YamlGateError("internal_failure");
      this.addString(node.value);
      return Object.freeze({
        kind: "include",
        tag: node.tag as
          | "!include"
          | "!include_dir_list"
          | "!include_dir_merge_list"
          | "!include_dir_named"
          | "!include_dir_merge_named",
        value: node.value,
        sourceRange,
      });
    }
    if (isMap(node)) {
      const entries = node.items.map((pair) => {
        this.bump();
        const primitive = isScalar(pair.key) ? pair.key.value : undefined;
        const keyType =
          primitive === null
            ? "null"
            : typeof primitive === "string"
              ? "string"
              : typeof primitive === "number"
                ? "number"
                : "boolean";
        const key = typeof primitive === "string" ? primitive : undefined;
        if (key !== undefined) this.addString(key);
        return Object.freeze({
          keyType,
          key,
          value: pair.value ? this.project(pair.value as Node, key) : null,
          sourceRange: this.range(pair),
        });
      });
      return Object.freeze({
        kind: "map",
        entries: Object.freeze(entries),
        anchored: Boolean(node.anchor),
        sourceRange,
      });
    }
    if (isCollection(node)) {
      const items = node.items.map((item) =>
        item && !isPair(item)
          ? this.project(item as Node)
          : Object.freeze({
              kind: "scalar" as const,
              scalarType: "null" as const,
              anchored: false,
            }),
      );
      return Object.freeze({
        kind: "sequence",
        items: Object.freeze(items),
        anchored: Boolean(node.anchor),
        sourceRange,
      });
    }
    if (!isScalar(node)) throw new YamlGateError("internal_failure");
    const scalarType =
      node.value === null
        ? "null"
        : typeof node.value === "string"
          ? "string"
          : typeof node.value === "number"
            ? "number"
            : "boolean";
    const identity =
      scalarType === "string" &&
      parentKey !== undefined &&
      projectionIdentityKeys.has(parentKey)
        ? String(node.value)
        : undefined;
    if (identity !== undefined) this.addString(identity);
    return Object.freeze({
      kind: "scalar",
      scalarType,
      identity,
      anchored: Boolean(node.anchor),
      sourceRange,
    });
  }

  private bump(): void {
    this.nodes += 1;
    this.work.poll();
  }

  private addString(value: string): void {
    this.stringBytes += Buffer.byteLength(value, "utf8");
  }

  private range(value: unknown): YamlSourceRange | undefined {
    const range =
      typeof value === "object" && value !== null && "range" in value
        ? (value as { range?: readonly number[] }).range
        : undefined;
    if (!range || range.length < 2) return undefined;
    const start = range[0] ?? 0;
    const end = range[1] ?? start;
    return Object.freeze({
      startByte: this.byteOffsets[start] ?? 0,
      endByte: this.byteOffsets[end] ?? this.byteOffsets.at(-1) ?? 0,
    });
  }
}

function buildByteOffsets(text: string, work: ProjectionWork): Uint32Array {
  const offsets = new Uint32Array(text.length + 1);
  let bytes = 0;
  for (let index = 0; index < text.length; ) {
    work.poll();
    const point = text.codePointAt(index);
    if (point === undefined) break;
    const width = point > 0xffff ? 2 : 1;
    bytes += Buffer.byteLength(String.fromCodePoint(point), "utf8");
    for (let step = 1; step <= width; step += 1) offsets[index + step] = bytes;
    index += width;
  }
  return offsets;
}

function deepFreezeProjection(
  projection: StrictYamlProjection,
  work: ProjectionWork,
): StrictYamlProjection {
  const freezeNode = (node: ProjectedYamlNode | null): void => {
    work.poll();
    if (!node) return;
    if (node.kind === "map") {
      for (const entry of node.entries) {
        work.poll();
        freezeNode(entry.value);
        Object.freeze(entry);
      }
      Object.freeze(node.entries);
    } else if (node.kind === "sequence") {
      for (const item of node.items) {
        work.poll();
        freezeNode(item);
      }
      Object.freeze(node.items);
    }
    Object.freeze(node);
    work.poll();
  };
  freezeNode(projection.root);
  return Object.freeze(projection);
}
function keyIdentity(scalar: { value: unknown }): string {
  const value = scalar.value;
  if (value === null) return "null:";
  if (typeof value === "string") return `string:${value}`;
  if (typeof value === "boolean") return `boolean:${value ? "true" : "false"}`;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new YamlGateError("key_invalid");
    return `number:${Object.is(value, -0) ? "0" : String(value)}`;
  }
  throw new YamlGateError("key_invalid");
}

function checkOperation(clock: GateClock): void {
  if (clock.signal.aborted) throw new YamlGateError("operation_cancelled");
  if (performance.now() >= clock.deadline)
    throw new YamlGateError("deadline_exceeded");
}

function located(
  code: YamlGateErrorCode,
  counter: LineCounter,
  offset: number,
): YamlGateError {
  const position = counter.linePos(Math.max(0, offset));
  return new YamlGateError(code, position.line || 1, position.col || 1);
}

function atOffset(
  code: YamlGateErrorCode,
  text: string,
  offset: number,
): YamlGateError {
  const counter = new LineCounter();
  counter.addNewLine(0);
  for (const match of text.matchAll(/\n/gu))
    counter.addNewLine(match.index + 1);
  return located(code, counter, offset);
}

function isHighSurrogate(value: number): boolean {
  return value >= 0xd800 && value <= 0xdbff;
}

function deepFreeze(metadata: StrictYamlMetadata): StrictYamlMetadata {
  Object.freeze(metadata.references);
  return Object.freeze(metadata);
}
