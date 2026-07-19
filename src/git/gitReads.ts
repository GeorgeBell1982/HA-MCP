import {
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptionsWithoutStdio,
} from "node:child_process";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import {
  relativeConfigPathSchema,
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
import {
  validateAndProjectYaml,
  type ProjectedYamlNode,
  type YamlSourceRange,
} from "../yaml/strictYamlGate.js";
import type {
  RepositoryCatalogProvider,
  RepositoryCatalog,
} from "../repository/repositoryReads.js";

const REQUEST_MAGIC = Buffer.from("HAGIT1\0", "ascii");
const RESPONSE_MAGIC = Buffer.from("HAGITR1\0", "ascii");
const RESPONSE_HEADER_BYTES = 128;
const MAX_BROKER_OUTPUT = 4 * 1024 * 1024;
const MAX_STDERR = 4096;
const MAX_STATUS = 500;
export const GIT_MAX_SIDE_BYTES = 512 * 1024;
export const GIT_MAX_RAW_BYTES = 2 * 1024 * 1024;
export const GIT_MAX_PATCH_BYTES = 1024 * 1024;
export const GIT_MAX_PUBLIC_BYTES = 512 * 1024;
export const GIT_MAX_DIFF_WORK = 200_000;

export class GitWorkPoller {
  private work = 0;
  constructor(private readonly context: Phase2OperationContext) {}
  charge(units = 1): void {
    for (let index = 0; index < units; index += 1) {
      if ((this.work & 255) === 0) assertOperationActive(this.context);
      this.work += 1;
      if (this.work > GIT_MAX_DIFF_WORK)
        throw unhealthy("Git diff work limit exceeded");
    }
  }
  finish(): void {
    assertOperationActive(this.context);
  }
}
export type GitBrokerOperation =
  | "status"
  | "object-format"
  | "index"
  | "tree"
  | "objects";

export interface GitBrokerRequest {
  readonly operation: GitBrokerOperation;
  readonly objectIds?: readonly string[];
}

export interface GitBrokerResponse {
  readonly rootIdentity: FileIdentity;
  readonly gitIdentity: FileIdentity;
  readonly headDigest: string;
  readonly indexDigest: string;
  readonly output: Uint8Array;
}

export interface GitBroker {
  execute(
    request: GitBrokerRequest,
    context: Phase2OperationContext,
  ): Promise<GitBrokerResponse>;
}

const operationCodes: Record<GitBrokerOperation, number> = {
  status: 1,
  "object-format": 2,
  index: 3,
  tree: 4,
  objects: 5,
};

export function encodeGitBrokerRequest(request: GitBrokerRequest): Buffer {
  const ids = request.objectIds ?? [];
  if (request.operation !== "objects" && ids.length !== 0)
    throw invalid("Object IDs are not valid for this broker operation");
  if (ids.length > 200) throw invalid("Too many Git object IDs");
  const width = ids.length === 0 ? 0 : ids[0]!.length;
  if (width !== 0 && width !== 40 && width !== 64)
    throw invalid("Git object ID width is invalid");
  if (ids.some((id) => id.length !== width || !/^[a-f0-9]+$/u.test(id)))
    throw invalid("Git object ID is invalid");
  const payload = Buffer.from(ids.join("\n"), "ascii");
  const output = Buffer.alloc(16 + payload.length);
  REQUEST_MAGIC.copy(output, 0);
  output.writeUInt8(operationCodes[request.operation], 7);
  output.writeUInt32BE(payload.length, 8);
  output.writeUInt32BE(0, 12);
  payload.copy(output, 16);
  return output;
}

export function decodeGitBrokerResponse(bytes: Uint8Array): GitBrokerResponse {
  const value = Buffer.from(bytes);
  try {
    if (
      value.length < RESPONSE_HEADER_BYTES ||
      !value.subarray(0, 8).equals(RESPONSE_MAGIC) ||
      value.readUInt32BE(8) !== 1 ||
      value.readUInt32BE(16) !== 0 ||
      value.readUInt32BE(20) !== 0 ||
      value.readUInt32BE(124) !== 0
    )
      throw unhealthy("Git broker protocol is invalid");
    const status = value.readUInt32BE(12);
    const payloadBytes = value.readUInt32BE(120);
    if (
      payloadBytes !== value.length - RESPONSE_HEADER_BYTES ||
      payloadBytes > MAX_BROKER_OUTPUT
    )
      throw unhealthy("Git broker response bounds are invalid");
    if (status === 4) {
      if (
        payloadBytes !== 0 ||
        value.subarray(24, 120).some((byte) => byte !== 0)
      )
        throw unhealthy("Unavailable Git broker response is not canonical");
      throw unavailable();
    }
    if (status !== 0) throw unhealthy("Git broker denied the repository state");
    const hex = (offset: number) =>
      value.subarray(offset, offset + 32).toString("hex");
    return Object.freeze({
      rootIdentity: Object.freeze({
        device: value.readBigUInt64BE(24).toString(),
        inode: value.readBigUInt64BE(32).toString(),
      }),
      gitIdentity: Object.freeze({
        device: value.readBigUInt64BE(40).toString(),
        inode: value.readBigUInt64BE(48).toString(),
      }),
      headDigest: hex(56),
      indexDigest: hex(88),
      output: Buffer.from(value.subarray(RESPONSE_HEADER_BYTES)),
    });
  } finally {
    value.fill(0);
    bytes.fill(0);
  }
}

export interface NativeGitBrokerOptions {
  readonly brokerPath?: string;
  readonly gitPath?: string;
  readonly runtimeLoader?: string;
  readonly root?: string;
  readonly platform?: NodeJS.Platform;
  readonly runtimeInputs?: readonly string[];
  readonly maximumConcurrent?: number;
}

export function nativeGitBrokerInvocation(
  brokerPath: string,
  gitPath: string,
  root: string,
  runtimeLoader: string,
  runtimeInputs: readonly string[] = [],
): Readonly<{
  file: string;
  args: readonly string[];
  options: SpawnOptionsWithoutStdio;
}> {
  if (
    ![brokerPath, gitPath, root, runtimeLoader, ...runtimeInputs].every(
      isAbsolute,
    ) ||
    runtimeInputs.length > 16 ||
    new Set([runtimeLoader, ...runtimeInputs]).size !== runtimeInputs.length + 1
  )
    throw unavailable();
  const args = [
    "--protocol-v1",
    "--git",
    gitPath,
    "--root",
    root,
    "--runtime-loader",
    runtimeLoader,
  ];
  for (const runtimeInput of runtimeInputs) {
    args.push("--runtime-input", runtimeInput);
  }
  return Object.freeze({
    file: brokerPath,
    args: Object.freeze(args),
    options: Object.freeze({
      cwd: root,
      detached: true,
      windowsHide: true,
      env: Object.freeze({}),
    }),
  });
}

export class NativeGitBroker implements GitBroker {
  private readonly permits: BoundedPermitPool;
  constructor(private readonly options: NativeGitBrokerOptions = {}) {
    this.permits = new BoundedPermitPool(options.maximumConcurrent ?? 1);
  }
  async execute(
    request: GitBrokerRequest,
    context: Phase2OperationContext,
  ): Promise<GitBrokerResponse> {
    assertOperationActive(context);
    if (
      (this.options.platform ?? process.platform) !== "linux" ||
      !this.options.brokerPath ||
      !this.options.gitPath ||
      !this.options.runtimeLoader
    )
      throw unavailable();
    const invocation = nativeGitBrokerInvocation(
      this.options.brokerPath,
      this.options.gitPath,
      this.options.root ?? "/homeassistant",
      this.options.runtimeLoader,
      this.options.runtimeInputs,
    );
    const release = await this.permits.acquire(context);
    try {
      return decodeGitBrokerResponse(
        await runBroker(invocation, encodeGitBrokerRequest(request), context),
      );
    } finally {
      release();
    }
  }
}

export interface GitStatusEntry {
  readonly path: string;
  readonly index: string;
  readonly worktree: string;
  readonly unsupported?: "rename" | "unmerged" | "submodule" | "type-change";
  readonly relatedPath?: string;
}
export interface GitStatus {
  readonly branch: string | null;
  readonly unborn: boolean;
  readonly entries: readonly GitStatusEntry[];
}

export interface GitDiffResult {
  readonly patch: string;
  readonly diffSha256: string;
  readonly truncated: boolean;
  readonly warnings: readonly string[];
  readonly snapshotSha256: string;
}

export interface GitDiffInput {
  readonly scope: "worktree" | "index" | "both";
  readonly paths?: readonly string[];
}

export class GitReadService {
  constructor(
    private readonly catalogs: RepositoryCatalogProvider,
    private readonly reader: SecureFileReader,
    private readonly protectedRegistry: ProtectedIdentityRegistry,
    private readonly broker: GitBroker,
  ) {}

  async status(context: Phase2OperationContext): Promise<GitStatus> {
    return this.sanitize(async () => {
      const poller = new GitWorkPoller(context);
      await this.protectedRegistry.assertFresh(context);
      const catalog = await this.catalogs.catalog(context);
      const response = await this.broker.execute(
        { operation: "status" },
        context,
      );
      let status: GitStatus;
      try {
        assertBrokerRoot(catalog, response);
        status = parseGitStatus(response.output, poller);
      } finally {
        response.output.fill(0);
      }
      for (const entry of status.entries) {
        poller.charge();
        if (entry.unsupported)
          throw unhealthy("Git status contains unsupported records");
      }
      await this.protectedRegistry.assertFresh(context);
      return status;
    });
  }

  async diff(
    input: GitDiffInput,
    context: Phase2OperationContext,
  ): Promise<GitDiffResult> {
    return this.sanitize(async () => {
      const poller = new GitWorkPoller(context);
      const paths = validateDiffPaths(input.paths, poller);
      await this.protectedRegistry.assertFresh(context);
      const catalog = await this.catalogs.catalog(context);
      const files = new Map<string, RepositoryCatalog["files"][number]>();
      for (const entry of catalog.files) {
        poller.charge();
        files.set(entry.path, entry);
      }
      if (paths)
        for (const path of paths) {
          const file = files.get(path);
          if (!file) throw denied("Requested Git diff path is unavailable");
          if (this.protectedRegistry.isProtected(path, file.identity))
            throw new RepositoryBoundaryError(
              "protected_resource",
              "Protected Git diff path is unavailable",
            );
        }
      const statusResponse = await this.broker.execute(
        { operation: "status" },
        context,
      );
      let status: GitStatus;
      try {
        assertBrokerRoot(catalog, statusResponse);
        status = parseGitStatus(statusResponse.output, poller);
      } finally {
        statusResponse.output.fill(0);
      }
      const planned = planDiffPaths(
        status,
        paths,
        files,
        this.protectedRegistry,
        poller,
      );
      const formatResponse = await this.broker.execute(
        { operation: "object-format" },
        context,
      );
      let objectFormat: "sha1" | "sha256";
      let index: ReadonlyMap<string, GitIndexEntry>;
      let tree: ReadonlyMap<string, GitIndexEntry>;
      try {
        const indexResponse = await this.broker.execute(
          { operation: "index" },
          context,
        );
        try {
          const treeResponse = status.unborn
            ? undefined
            : await this.broker.execute({ operation: "tree" }, context);
          try {
            assertSameBroker(statusResponse, formatResponse);
            objectFormat = parseObjectFormat(formatResponse.output, poller);
            assertSameBroker(statusResponse, indexResponse);
            index = parseGitIndex(indexResponse.output, objectFormat, poller);
            if (treeResponse) {
              assertSameBroker(statusResponse, treeResponse);
              tree = parseGitTree(treeResponse.output, objectFormat, poller);
            } else tree = new Map<string, GitIndexEntry>();
          } finally {
            treeResponse?.output.fill(0);
          }
        } finally {
          indexResponse.output.fill(0);
        }
      } finally {
        formatResponse.output.fill(0);
      }
      enforceSideMatrix(
        planned,
        index,
        tree,
        status.unborn,
        paths !== undefined,
        poller,
      );
      const objectIds = new Set<string>();
      for (const path of planned.paths) {
        poller.charge();
        const state = planned.byPath.get(path)!;
        if (
          (input.scope === "index" || input.scope === "both") &&
          state.index !== " " &&
          state.index !== "?"
        ) {
          const head = tree.get(path);
          const staged = index.get(path);
          if (head) objectIds.add(head.objectId);
          if (staged) objectIds.add(staged.objectId);
        }
        if (
          (input.scope === "worktree" || input.scope === "both") &&
          state.worktree !== " " &&
          state.index !== "?"
        ) {
          const staged = index.get(path);
          if (staged) objectIds.add(staged.objectId);
        }
      }
      const orderedObjectIds = [...objectIds].sort((left, right) => {
        poller.charge();
        return left.localeCompare(right);
      });
      const objects = new Map<string, Buffer>();
      try {
        for (let offset = 0; offset < orderedObjectIds.length; offset += 200) {
          poller.charge();
          const batch = orderedObjectIds.slice(offset, offset + 200);
          const objectResponse = await this.broker.execute(
            { operation: "objects", objectIds: batch },
            context,
          );
          let parsed: ReadonlyMap<string, Buffer>;
          try {
            assertSameBroker(statusResponse, objectResponse);
            parsed = parseGitObjects(
              objectResponse.output,
              objectFormat,
              batch,
              poller,
            );
          } finally {
            objectResponse.output.fill(0);
          }
          for (const [objectId, value] of parsed) {
            poller.charge();
            if (objects.has(objectId)) {
              value.fill(0);
              throw unhealthy("Git object is duplicated across batches");
            }
            objects.set(objectId, value);
          }
        }
        let rawBytes = 0;
        for (const value of objects.values()) {
          poller.charge();
          rawBytes += value.byteLength;
        }
        if (rawBytes > GIT_MAX_RAW_BYTES)
          throw unhealthy("Aggregate Git diff input exceeds its boundary");
        const prepared = new Map<string, string>();
        const side = async (key: string, bytes: Uint8Array) => {
          const cached = prepared.get(key);
          if (cached !== undefined) return cached;
          const value = await prepareGitYamlSide(
            bytes,
            this.protectedRegistry,
            context,
          );
          prepared.set(key, value);
          return value;
        };
        let patch = "";
        const work = poller;
        const consumedObjects = new Map<string, string>();
        for (const [objectId, value] of objects) {
          poller.charge();
          consumedObjects.set(objectId, digest(value));
        }
        const currentEvidence = new Map<
          string,
          { identity: FileIdentity; size: number; digest: string }
        >();
        for (const path of planned.paths) {
          const state = planned.byPath.get(path)!;
          const head = tree.get(path);
          const staged = index.get(path);
          if (
            (input.scope === "index" || input.scope === "both") &&
            state.index !== " " &&
            state.index !== "?"
          ) {
            const before = head
              ? await side(
                  `o:${head.objectId}`,
                  requireObject(objects, head.objectId),
                )
              : "";
            const after = staged
              ? await side(
                  `o:${staged.objectId}`,
                  requireObject(objects, staged.objectId),
                )
              : "";
            patch += sectionPatch("staged", path, before, after, work);
          }
          if (
            (input.scope === "worktree" || input.scope === "both") &&
            state.worktree !== " "
          ) {
            if (state.worktree === "D") {
              planned.omitted = true;
              continue;
            }
            const before =
              state.index === "?"
                ? ""
                : staged
                  ? await side(
                      `o:${staged.objectId}`,
                      requireObject(objects, staged.objectId),
                    )
                  : "";
            const file = files.get(path);
            if (!file) {
              planned.omitted = true;
              continue;
            }
            const read = await this.reader.read(path, context);
            try {
              if (
                !sameIdentity(read.rootIdentity, catalog.rootIdentity) ||
                !sameIdentity(read.identity, file.identity) ||
                read.bytes.byteLength !== file.size
              )
                throw stale();
              rawBytes += read.bytes.byteLength;
              if (rawBytes > GIT_MAX_RAW_BYTES)
                throw unhealthy(
                  "Aggregate Git diff input exceeds its boundary",
                );
              const currentDigest = digest(read.bytes);
              const after = await side(
                `c:${path}:${currentDigest}`,
                read.bytes,
              );
              patch += sectionPatch("worktree", path, before, after, work);
              currentEvidence.set(path, {
                identity: file.identity,
                size: file.size,
                digest: currentDigest,
              });
            } finally {
              read.bytes.fill(0);
            }
          }
        }
        if (Buffer.byteLength(patch) > GIT_MAX_PATCH_BYTES)
          throw unhealthy("Complete redacted Git patch exceeds its boundary");
        for (const [path, evidence] of currentEvidence) {
          poller.charge();
          const reread = await this.reader.read(path, context);
          try {
            if (
              !sameIdentity(reread.rootIdentity, catalog.rootIdentity) ||
              !sameIdentity(reread.identity, evidence.identity) ||
              reread.bytes.byteLength !== evidence.size ||
              digest(reread.bytes) !== evidence.digest
            )
              throw stale();
          } finally {
            reread.bytes.fill(0);
          }
        }
        for (let offset = 0; offset < orderedObjectIds.length; offset += 200) {
          poller.charge();
          const batch = orderedObjectIds.slice(offset, offset + 200);
          const repeatedResponse = await this.broker.execute(
            { operation: "objects", objectIds: batch },
            context,
          );
          let repeated: ReadonlyMap<string, Buffer>;
          try {
            assertSameBroker(statusResponse, repeatedResponse);
            repeated = parseGitObjects(
              repeatedResponse.output,
              objectFormat,
              batch,
              poller,
            );
          } finally {
            repeatedResponse.output.fill(0);
          }
          try {
            for (const [objectId, value] of repeated) {
              poller.charge();
              if (digest(value) !== consumedObjects.get(objectId))
                throw stale();
            }
          } finally {
            for (const value of repeated.values()) value.fill(0);
          }
        }
        const diffSha256 = digest(Buffer.from(patch));
        const display = truncateGitPatch(patch, poller);
        const snapshotSha256 = gitSnapshot(
          {
            rootIdentity: statusResponse.rootIdentity,
            gitIdentity: statusResponse.gitIdentity,
            objectFormat,
            headDigest: statusResponse.headDigest,
            indexDigest: statusResponse.indexDigest,
            scope: input.scope,
            paths,
            currentEvidence,
            consumedObjects,
          },
          poller,
        );
        const finalStatus = await this.broker.execute(
          { operation: "status" },
          context,
        );
        try {
          assertSameBroker(statusResponse, finalStatus);
        } finally {
          finalStatus.output.fill(0);
        }
        await this.protectedRegistry.assertFresh(context);
        return Object.freeze({
          patch: display.patch,
          diffSha256,
          truncated: display.truncated,
          warnings: Object.freeze(
            planned.omitted
              ? ["Unsupported repository changes were omitted"]
              : [],
          ),
          snapshotSha256,
        });
      } finally {
        for (const value of objects.values()) value.fill(0);
      }
    });
  }

  private async sanitize<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof RepositoryBoundaryError) throw error;
      throw unhealthy("Git repository read failed safely");
    }
  }
}
export function parseGitStatus(
  bytes: Uint8Array,
  poller?: GitWorkPoller,
): GitStatus {
  try {
    const text = fatalUtf8(bytes, "Git status encoding is invalid");
    if (!text.endsWith("\0")) throw unhealthy("Git status framing is invalid");
    let branch: string | null | undefined;
    let oidState: "born" | "unborn" | undefined;
    const entries: GitStatusEntry[] = [];
    const records = text.slice(0, -1).split("\0");
    for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
      poller?.charge();
      const record = records[recordIndex]!;
      if (record.startsWith("# branch.oid ")) {
        if (oidState !== undefined)
          throw unhealthy("Git branch oid header is duplicated");
        const oid = record.slice(13);
        if (oid === "(initial)") oidState = "unborn";
        else if (/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(oid))
          oidState = "born";
        else throw unhealthy("Git branch oid header is invalid");
        continue;
      }
      if (record.startsWith("# branch.head ")) {
        if (branch !== undefined)
          throw unhealthy("Git branch head header is duplicated");
        const name = record.slice(14);
        branch = name === "(detached)" ? null : validBranch(name);
        continue;
      }
      if (record.startsWith("# "))
        throw unhealthy("Git status header is unsupported");
      if (record.startsWith("? ")) {
        entries.push(statusEntry(record.slice(2), "?", "?"));
        continue;
      }
      if (record.startsWith("1 ")) {
        const match =
          /^1 ([.MADT]{2}) (N\.\.\.|S[C.][M.][U.]) (000000|100644|100755|120000|160000) (000000|100644|100755|120000|160000) (000000|100644|100755|120000|160000) ([a-f0-9]+) ([a-f0-9]+) (.+)$/u.exec(
            record,
          );
        if (!match) throw unhealthy("Git status record is malformed");
        entries.push(type1StatusEntry(match));
        continue;
      }
      if (record.startsWith("2 ")) {
        const fields = record.split(" ");
        if (fields.length < 10 || recordIndex + 1 >= records.length)
          throw unhealthy("Git rename record is malformed");
        const prefix = fields.slice(0, 9).join(" ") + " ";
        const target = validPath(record.slice(prefix.length));
        const source = validPath(records[++recordIndex]!);
        poller?.charge();
        entries.push(
          statusEntry(target, fields[1]![0]!, fields[1]![1]!, "rename", source),
        );
        entries.push(statusEntry(source, "D", ".", "rename", target));
        continue;
      }
      if (record.startsWith("u ")) {
        const fields = record.split(" ");
        if (fields.length < 11)
          throw unhealthy("Git unmerged record is malformed");
        const prefix = fields.slice(0, 10).join(" ") + " ";
        entries.push(
          statusEntry(
            record.slice(prefix.length),
            fields[1]![0]!,
            fields[1]![1]!,
            "unmerged",
          ),
        );
        continue;
      }
      throw unhealthy("Git status record is unsupported");
    }
    if (oidState === undefined || branch === undefined)
      throw unhealthy("Git branch headers are incomplete");
    if (
      (oidState === "unborn" && branch === null) ||
      (oidState === "born" && branch === undefined)
    )
      throw unhealthy("Git branch header state is invalid");
    if (entries.length > MAX_STATUS)
      throw unhealthy("Git status entry limit exceeded");
    entries.sort((left, right) => {
      poller?.charge();
      return Buffer.compare(Buffer.from(left.path), Buffer.from(right.path));
    });
    for (let index = 1; index < entries.length; index += 1) {
      poller?.charge();
      if (entries[index - 1]!.path === entries[index]!.path)
        throw unhealthy("Git status path is duplicated");
    }
    poller?.finish();
    return Object.freeze({
      branch,
      unborn: oidState === "unborn",
      entries: Object.freeze(entries),
    });
  } finally {
    bytes.fill(0);
  }
}

export interface GitIndexEntry {
  readonly path: string;
  readonly mode: string;
  readonly objectId: string;
  readonly supported: boolean;
  readonly stage: number;
  readonly objectType: string;
}
export function parseGitIndex(
  bytes: Uint8Array,
  objectFormat: "sha1" | "sha256",
  poller?: GitWorkPoller,
): ReadonlyMap<string, GitIndexEntry> {
  const width = objectFormat === "sha1" ? 40 : 64;
  const output = new Map<string, GitIndexEntry>();
  try {
    for (const record of nulRecords(bytes, "Git index")) {
      poller?.charge();
      const match = /^(\d{6}) ([a-f0-9]+) ([0-3])\t(.*)$/u.exec(record);
      if (!match || match[2]!.length !== width)
        throw unhealthy("Git index entry is malformed");
      const path = validPath(match[4]!);
      const stage = Number(match[3]);
      const entry = Object.freeze({
        path,
        mode: match[1]!,
        objectId: match[2]!,
        supported: match[1] === "100644" && stage === 0,
        stage,
        objectType: "blob",
      });
      const previous = output.get(path);
      output.set(
        path,
        previous
          ? Object.freeze({
              ...previous,
              supported: false,
              stage: Math.max(previous.stage, stage),
            })
          : entry,
      );
    }
    poller?.finish();
    return output;
  } finally {
    bytes.fill(0);
  }
}

export function parseGitTree(
  bytes: Uint8Array,
  objectFormat: "sha1" | "sha256",
  poller?: GitWorkPoller,
): ReadonlyMap<string, GitIndexEntry> {
  const width = objectFormat === "sha1" ? 40 : 64;
  const output = new Map<string, GitIndexEntry>();
  try {
    for (const record of nulRecords(bytes, "Git tree")) {
      poller?.charge();
      const match = /^(\d{6}) ([a-z]+) ([a-f0-9]+)\t(.*)$/u.exec(record);
      if (!match || match[3]!.length !== width)
        throw unhealthy("Git tree entry is malformed");
      const path = validPath(match[4]!);
      if (output.has(path)) throw unhealthy("Git tree path is duplicated");
      output.set(
        path,
        Object.freeze({
          path,
          mode: match[1]!,
          objectId: match[3]!,
          supported: match[1] === "100644" && match[2] === "blob",
          stage: 0,
          objectType: match[2]!,
        }),
      );
    }
    poller?.finish();
    return output;
  } finally {
    bytes.fill(0);
  }
}

export function parseObjectFormat(
  bytes: Uint8Array,
  poller?: GitWorkPoller,
): "sha1" | "sha256" {
  try {
    poller?.charge();
    const value = fatalUtf8(
      bytes,
      "Git object format encoding is invalid",
    ).trim();
    if (value !== "sha1" && value !== "sha256")
      throw unhealthy("Git object format is unsupported");
    poller?.finish();
    return value;
  } finally {
    bytes.fill(0);
  }
}
type Edit = Readonly<{ type: "equal" | "delete" | "insert"; line: string }>;
export function canonicalUnifiedPatch(
  oldText: string,
  newText: string,
  path: string,
  work: GitWorkPoller | { value: number } = { value: 0 },
): string {
  const oldLines = splitLines(oldText);
  const newLines = splitLines(newText);
  const comparable = (
    value: Readonly<{ lines: readonly string[]; finalNewline: boolean }>,
  ) => {
    const output: string[] = [];
    for (let index = 0; index < value.lines.length; index += 1) {
      charge(work);
      const line = value.lines[index]!;
      output.push(
        index === value.lines.length - 1
          ? `${line}\0${value.finalNewline ? "NL" : "EOF"}`
          : line,
      );
    }
    return output;
  };
  const rawEdits = myers(comparable(oldLines), comparable(newLines), work);
  const edits: Edit[] = [];
  let hasChange = false;
  for (const edit of rawEdits) {
    charge(work);
    const marker = edit.line.lastIndexOf("\0");
    edits.push({
      type: edit.type,
      line: marker >= 0 ? edit.line.slice(0, marker) : edit.line,
    });
    if (edit.type !== "equal") hasChange = true;
  }
  if (!hasChange) return "";

  const changed: number[] = [];
  for (let index = 0; index < edits.length; index += 1) {
    charge(work);
    if (edits[index]!.type !== "equal") changed.push(index);
  }
  const groups: Array<[number, number]> = [];
  for (const index of changed) {
    charge(work);
    const last = groups.at(-1);
    if (!last || index > last[1] + 6)
      groups.push([
        Math.max(0, index - 3),
        Math.min(edits.length - 1, index + 3),
      ]);
    else last[1] = Math.min(edits.length - 1, index + 3);
  }

  let output = `--- a/${path}\n+++ b/${path}\n`;
  let oldBefore = 0;
  let newBefore = 0;
  let cursor = 0;
  for (const [start, end] of groups) {
    charge(work);
    while (cursor < start) {
      charge(work);
      if (edits[cursor]!.type !== "insert") oldBefore += 1;
      if (edits[cursor]!.type !== "delete") newBefore += 1;
      cursor += 1;
    }
    let oldCount = 0;
    let newCount = 0;
    for (let index = start; index <= end; index += 1) {
      charge(work);
      const type = edits[index]!.type;
      if (type !== "insert") oldCount += 1;
      if (type !== "delete") newCount += 1;
    }
    output += `@@ -${oldBefore + 1},${oldCount} +${newBefore + 1},${newCount} @@\n`;
    let oldLine = oldBefore;
    let newLine = newBefore;
    for (let index = start; index <= end; index += 1) {
      charge(work);
      const edit = edits[index]!;
      if (edit.type !== "insert") oldLine += 1;
      if (edit.type !== "delete") newLine += 1;
      output +=
        (edit.type === "equal" ? " " : edit.type === "delete" ? "-" : "+") +
        edit.line +
        "\n";
      const oldMissing =
        edit.type !== "insert" &&
        !oldLines.finalNewline &&
        oldLine === oldLines.lines.length;
      const newMissing =
        edit.type !== "delete" &&
        !newLines.finalNewline &&
        newLine === newLines.lines.length;
      if (oldMissing || newMissing) output += "\\ No newline at end of file\n";
    }
    cursor = end + 1;
    oldBefore += oldCount;
    newBefore += newCount;
  }
  if (Buffer.byteLength(output) > GIT_MAX_PATCH_BYTES)
    throw unhealthy("Complete redacted Git patch exceeds its boundary");
  return output;
}

export function truncateGitPatch(
  value: string,
  poller?: GitWorkPoller,
): Readonly<{ patch: string; truncated: boolean }> {
  if (Buffer.byteLength(value) <= GIT_MAX_PUBLIC_BYTES)
    return Object.freeze({ patch: value, truncated: false });
  const marker = "@@ [REDACTED PATCH TRUNCATED] @@\n";
  const maximum = GIT_MAX_PUBLIC_BYTES - Buffer.byteLength(marker);
  let bytes = 0;
  const lines: string[] = [];
  for (const line of value.split(/(?<=\n)/u)) {
    poller?.charge();
    const size = Buffer.byteLength(line);
    if (bytes + size > maximum) break;
    lines.push(line);
    bytes += size;
  }
  return Object.freeze({ patch: lines.join("") + marker, truncated: true });
}

export async function prepareGitYamlSide(
  bytes: Uint8Array,
  registry: ProtectedIdentityRegistry,
  context: Phase2OperationContext,
): Promise<string> {
  if (bytes.byteLength > GIT_MAX_SIDE_BYTES)
    throw new RepositoryBoundaryError(
      "file_too_large",
      "Git YAML side exceeds its boundary",
    );
  if (bytes.includes(0))
    throw new RepositoryBoundaryError(
      "unsupported_encoding",
      "Git YAML side contains NUL",
    );
  const owned = Buffer.from(bytes);
  try {
    const projection = await validateAndProjectYaml(owned, context);
    const ranges: YamlSourceRange[] = [];
    collectSecretRanges(projection.root, ranges, context);
    for (const range of ranges)
      owned.fill(0x20, range.startByte, range.endByte);
    const text = fatalUtf8(owned, "Git YAML side encoding is invalid").replace(
      /\r\n/gu,
      "\n",
    );
    return registry.redactWholeText(text, context, GIT_MAX_SIDE_BYTES);
  } finally {
    owned.fill(0);
  }
}

export function encodeGitObjects(
  objects: ReadonlyMap<string, Uint8Array>,
): Buffer {
  const chunks: Buffer[] = [];
  for (const [objectId, value] of objects) {
    const header = Buffer.from(`${objectId} ${value.byteLength}\n`, "ascii");
    chunks.push(header, Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

export function parseGitObjects(
  bytes: Uint8Array,
  objectFormat: "sha1" | "sha256",
  expected: readonly string[],
  poller?: GitWorkPoller,
): ReadonlyMap<string, Buffer> {
  const width = objectFormat === "sha1" ? 40 : 64;
  const input = Buffer.from(bytes);
  const output = new Map<string, Buffer>();
  let offset = 0;
  let total = 0;
  try {
    while (offset < input.length) {
      poller?.charge();
      const lineEnd = input.indexOf(0x0a, offset);
      if (lineEnd < 0 || lineEnd - offset > 80)
        throw unhealthy("Git object framing is invalid");
      const header = input.subarray(offset, lineEnd).toString("ascii");
      const match = /^([a-f0-9]+) (\d+)$/u.exec(header);
      if (!match || match[1]!.length !== width)
        throw unhealthy("Git object header is invalid");
      const size = Number(match[2]);
      if (
        !Number.isSafeInteger(size) ||
        size < 0 ||
        size > GIT_MAX_SIDE_BYTES ||
        lineEnd + 1 + size > input.length
      )
        throw unhealthy("Git object size is outside bounds");
      const objectId = match[1]!;
      if (output.has(objectId)) throw unhealthy("Git object is duplicated");
      const value = Buffer.from(
        input.subarray(lineEnd + 1, lineEnd + 1 + size),
      );
      output.set(objectId, value);
      total += size;
      if (total > GIT_MAX_RAW_BYTES)
        throw unhealthy("Aggregate Git object input exceeds its boundary");
      offset = lineEnd + 1 + size;
    }
    if (
      expected.length !== output.size ||
      expected.some((id) => !output.has(id))
    )
      throw unhealthy("Git object response is incomplete");
    poller?.finish();
    return output;
  } catch (error) {
    for (const value of output.values()) value.fill(0);
    throw error;
  } finally {
    input.fill(0);
    bytes.fill(0);
  }
}
interface PlannedDiff {
  paths: string[];
  readonly byPath: ReadonlyMap<string, GitStatusEntry>;
  omitted: boolean;
}
function validateDiffPaths(
  paths: readonly string[] | undefined,
  poller: GitWorkPoller,
): readonly string[] | undefined {
  if (paths === undefined) return undefined;
  if (paths.length < 1 || paths.length > 100)
    throw invalid("Git diff paths are outside bounds");
  const output = [...paths];
  for (const path of output) {
    poller.charge();
    if (
      !relativeConfigPathSchema.safeParse(path).success ||
      !/\.ya?ml$/u.test(path)
    )
      throw invalid("Git diff path is invalid");
  }
  output.sort((a, b) => {
    poller.charge();
    return Buffer.compare(Buffer.from(a), Buffer.from(b));
  });
  for (let index = 1; index < output.length; index += 1) {
    poller.charge();
    if (output[index - 1] === output[index])
      throw invalid("Git diff path is duplicated");
  }
  return Object.freeze(output);
}
function planDiffPaths(
  status: GitStatus,
  requested: readonly string[] | undefined,
  files: ReadonlyMap<string, RepositoryCatalog["files"][number]>,
  registry: ProtectedIdentityRegistry,
  poller: GitWorkPoller,
): PlannedDiff {
  const byPath = new Map<string, GitStatusEntry>();
  for (const entry of status.entries) {
    poller.charge();
    byPath.set(entry.path, entry);
  }
  const paths: string[] = [];
  let omitted = false;
  const candidates = requested ?? [...byPath.keys()];
  for (const path of candidates) {
    poller.charge();
    const state = byPath.get(path);
    const file = files.get(path);
    if (!state) continue;
    if (
      !file ||
      !/\.ya?ml$/u.test(path) ||
      state.index === "D" ||
      state.worktree === "D" ||
      "RU".includes(state.index) ||
      "RU".includes(state.worktree)
    ) {
      if (requested) throw denied("Requested Git diff path is unsupported");
      omitted = true;
      continue;
    }
    if (registry.isProtected(path, file.identity)) {
      if (requested)
        throw new RepositoryBoundaryError(
          "protected_resource",
          "Protected Git diff path is unavailable",
        );
      omitted = true;
      continue;
    }
    paths.push(path);
  }
  paths.sort((a, b) => {
    poller.charge();
    return Buffer.compare(Buffer.from(a), Buffer.from(b));
  });
  return { paths, byPath, omitted };
}
function enforceSideMatrix(
  planned: PlannedDiff,
  index: ReadonlyMap<string, GitIndexEntry>,
  tree: ReadonlyMap<string, GitIndexEntry>,
  unborn: boolean,
  explicit: boolean,
  poller: GitWorkPoller,
): void {
  const eligible: string[] = [];
  for (const path of planned.paths) {
    poller.charge();
    const state = planned.byPath.get(path)!;
    const staged = index.get(path);
    const head = tree.get(path);
    let supported = !state.unsupported;
    if (staged && !staged.supported) supported = false;
    if (head && !head.supported) supported = false;
    if (state.index === "A") supported &&= Boolean(staged) && !head;
    else if (state.index === "M")
      supported &&= Boolean(staged) && Boolean(head);
    else if (state.index === "D" || ![" ", "?"].includes(state.index))
      supported = false;
    if (state.worktree === "M") supported &&= Boolean(staged);
    else if (state.worktree === "D" || ![" ", "?"].includes(state.worktree))
      supported = false;
    if (state.index === "?" || state.worktree === "?")
      supported &&= !staged && (unborn || !head);
    if (!supported) {
      if (explicit)
        throw denied(
          "Requested Git diff path has unsupported repository state",
        );
      planned.omitted = true;
      continue;
    }
    eligible.push(path);
  }
  planned.paths = eligible;
}
function requireObject(
  objects: ReadonlyMap<string, Buffer>,
  objectId: string,
): Buffer {
  const value = objects.get(objectId);
  if (!value) throw unhealthy("Required Git object is unavailable");
  return value;
}
function sectionPatch(
  kind: "staged" | "worktree",
  path: string,
  before: string,
  after: string,
  work: GitWorkPoller | { value: number },
): string {
  const patch = canonicalUnifiedPatch(before, after, path, work);
  return patch ? `### ${kind}: ${path}\n${patch}` : "";
}
interface GitSnapshotInput {
  readonly rootIdentity: FileIdentity;
  readonly gitIdentity: FileIdentity;
  readonly objectFormat: "sha1" | "sha256";
  readonly headDigest: string;
  readonly indexDigest: string;
  readonly scope: GitDiffInput["scope"];
  readonly paths: readonly string[] | undefined;
  readonly currentEvidence: ReadonlyMap<
    string,
    { identity: FileIdentity; size: number; digest: string }
  >;
  readonly consumedObjects: ReadonlyMap<string, string>;
}

function gitSnapshot(input: GitSnapshotInput, poller: GitWorkPoller): string {
  const hash = createHash("sha256");
  hash.update("HA_GIT_SNAPSHOT_V2\0");
  const frame = (label: string, value: string) => {
    poller.charge();
    const labelBytes = Buffer.from(label);
    const valueBytes = Buffer.from(value);
    const lengths = Buffer.alloc(8);
    lengths.writeUInt32BE(labelBytes.length, 0);
    lengths.writeUInt32BE(valueBytes.length, 4);
    hash.update(lengths).update(labelBytes).update(valueBytes);
    lengths.fill(0);
  };
  frame("root.device", input.rootIdentity.device);
  frame("root.inode", input.rootIdentity.inode);
  frame("git.device", input.gitIdentity.device);
  frame("git.inode", input.gitIdentity.inode);
  frame("object-format", input.objectFormat);
  frame("head.sha256", input.headDigest);
  frame("index.sha256", input.indexDigest);
  frame("scope", input.scope);
  const filterHash = createHash("sha256");
  if (input.paths)
    for (const path of input.paths) {
      poller.charge();
      const bytes = Buffer.from(path);
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      filterHash.update(length).update(bytes);
      length.fill(0);
    }
  else filterHash.update("*");
  frame("filter.sha256", filterHash.digest("hex"));
  const current = [...input.currentEvidence].sort(([left], [right]) => {
    poller.charge();
    return Buffer.compare(Buffer.from(left), Buffer.from(right));
  });
  for (const [path, evidence] of current) {
    frame("current.path", path);
    frame("current.device", evidence.identity.device);
    frame("current.inode", evidence.identity.inode);
    frame("current.size", String(evidence.size));
    frame("current.sha256", evidence.digest);
  }
  const objects = [...input.consumedObjects].sort(([left], [right]) => {
    poller.charge();
    return left.localeCompare(right);
  });
  for (const [objectId, contentDigest] of objects) {
    frame("object.id", objectId);
    frame("object.sha256", contentDigest);
  }
  poller.finish();
  return hash.digest("hex");
}
function assertBrokerRoot(
  catalog: RepositoryCatalog,
  response: GitBrokerResponse,
): void {
  if (!sameIdentity(catalog.rootIdentity, response.rootIdentity)) throw stale();
}
function assertSameBroker(
  left: GitBrokerResponse,
  right: GitBrokerResponse,
): void {
  if (
    !sameIdentity(left.rootIdentity, right.rootIdentity) ||
    !sameIdentity(left.gitIdentity, right.gitIdentity) ||
    left.headDigest !== right.headDigest ||
    left.indexDigest !== right.indexDigest
  )
    throw stale();
}
function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}
function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
function denied(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("path_denied", message);
}
function stale(): RepositoryBoundaryError {
  return new RepositoryBoundaryError(
    "stale_source",
    "Git repository changed during inspection",
  );
}
function collectSecretRanges(
  node: ProjectedYamlNode | null,
  ranges: YamlSourceRange[],
  context: Phase2OperationContext,
): void {
  if (!node) return;
  assertOperationActive(context);
  if (node.kind === "secret") ranges.push(node.sourceRange);
  else if (node.kind === "map")
    for (const entry of node.entries)
      collectSecretRanges(entry.value, ranges, context);
  else if (node.kind === "sequence")
    for (const item of node.items) collectSecretRanges(item, ranges, context);
}
function splitLines(value: string) {
  const finalNewline = value.endsWith("\n");
  const lines = value.split("\n");
  if (finalNewline) lines.pop();
  return { lines, finalNewline };
}
function myers(
  a: readonly string[],
  b: readonly string[],
  work: GitWorkPoller | { value: number },
): Edit[] {
  const n = a.length,
    m = b.length,
    max = n + m,
    v = new Map<number, number>([[1, 0]]),
    trace: Array<Map<number, number>> = [];
  for (let d = 0; d <= max; d += 1) {
    const snapshot = new Map<number, number>();
    for (const [key, value] of v) {
      charge(work);
      snapshot.set(key, value);
    }
    trace.push(snapshot);
    for (let k = -d; k <= d; k += 2) {
      charge(work);
      let x =
        k === -d || (k !== d && (v.get(k - 1) ?? -1) < (v.get(k + 1) ?? -1))
          ? (v.get(k + 1) ?? 0)
          : (v.get(k - 1) ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        charge(work);
        x += 1;
        y += 1;
      }
      v.set(k, x);
      if (x >= n && y >= m) return backtrack(trace, a, b, d, work);
    }
  }
  throw unhealthy("Git diff failed safely");
}
function backtrack(
  trace: Array<Map<number, number>>,
  a: readonly string[],
  b: readonly string[],
  depth: number,
  work: GitWorkPoller | { value: number },
): Edit[] {
  let x = a.length,
    y = b.length;
  const out: Edit[] = [];
  for (let d = depth; d > 0; d -= 1) {
    charge(work);
    const v = trace[d]!,
      k = x - y,
      prevK =
        k === -d || (k !== d && (v.get(k - 1) ?? -1) < (v.get(k + 1) ?? -1))
          ? k + 1
          : k - 1,
      prevX = v.get(prevK) ?? 0,
      prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      charge(work);
      out.push({ type: "equal", line: a[--x]! });
      y -= 1;
    }
    charge(work);
    if (x === prevX) out.push({ type: "insert", line: b[--y]! });
    else out.push({ type: "delete", line: a[--x]! });
  }
  while (x > 0 && y > 0) {
    charge(work);
    out.push({ type: "equal", line: a[--x]! });
    y -= 1;
  }
  while (x > 0) {
    charge(work);
    out.push({ type: "delete", line: a[--x]! });
  }
  while (y > 0) {
    charge(work);
    out.push({ type: "insert", line: b[--y]! });
  }
  const ordered: Edit[] = [];
  for (let index = out.length - 1; index >= 0; index -= 1) {
    charge(work);
    ordered.push(out[index]!);
  }
  return ordered;
}
function charge(work: GitWorkPoller | { value: number }) {
  if (work instanceof GitWorkPoller) {
    work.charge();
    return;
  }
  work.value += 1;
  if (work.value > GIT_MAX_DIFF_WORK)
    throw unhealthy("Git diff work limit exceeded");
}
function nulRecords(bytes: Uint8Array, label: string) {
  const text = fatalUtf8(bytes, `${label} encoding is invalid`);
  if (text === "") return [];
  if (!text.endsWith("\0")) throw unhealthy(`${label} framing is invalid`);
  return text.slice(0, -1).split("\0");
}
function fatalUtf8(bytes: Uint8Array, message: string) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new RepositoryBoundaryError("unsupported_encoding", message);
  }
}
function validPath(path: string) {
  if (
    !relativeConfigPathSchema.safeParse(path).success ||
    path !== path.normalize("NFC")
  )
    throw unhealthy("Git path is invalid");
  return path;
}
function validBranch(value: string) {
  if (!value || value !== value.normalize("NFC") || /[\p{Cc}]/u.test(value))
    throw unhealthy("Git branch is invalid");
  return value;
}
function type1StatusEntry(match: RegExpExecArray): GitStatusEntry {
  const xy = match[1]!;
  const submodule = match[2]!;
  const modes = [match[3]!, match[4]!, match[5]!] as const;
  const objectIds = [match[6]!, match[7]!] as const;
  const width = objectIds[0].length;
  const zeroMode = (mode: string) => mode === "000000";
  const zeroObject = (objectId: string) => /^0+$/u.test(objectId);
  if (
    (width !== 40 && width !== 64) ||
    objectIds[1].length !== width ||
    zeroMode(modes[0]) !== zeroObject(objectIds[0]) ||
    zeroMode(modes[1]) !== zeroObject(objectIds[1]) ||
    xy === ".."
  )
    throw unhealthy("Git status record semantics are invalid");
  const index = xy[0]!;
  const worktree = xy[1]!;
  const indexModesValid =
    index === "A"
      ? zeroMode(modes[0]) && !zeroMode(modes[1])
      : index === "D"
        ? !zeroMode(modes[0]) &&
          zeroMode(modes[1]) &&
          worktree === "." &&
          zeroMode(modes[2])
        : !zeroMode(modes[0]) && !zeroMode(modes[1]);
  const worktreeModesValid =
    index === "D"
      ? true
      : worktree === "D"
        ? !zeroMode(modes[1]) && zeroMode(modes[2])
        : !zeroMode(modes[1]) && !zeroMode(modes[2]);
  if (!indexModesValid || !worktreeModesValid)
    throw unhealthy("Git status record modes are inconsistent");
  const unsupported =
    submodule !== "N..."
      ? "submodule"
      : xy.includes("T") ||
          modes.some((mode) => mode !== "000000" && mode !== "100644")
        ? "type-change"
        : undefined;
  return statusEntry(match[8]!, index, worktree, unsupported);
}
function statusEntry(
  path: string,
  index: string,
  worktree: string,
  unsupported?: GitStatusEntry["unsupported"],
  relatedPath?: string,
): GitStatusEntry {
  if (!/^[.MADRCUT?!]$/u.test(index) || !/^[.MADRCUT?!]$/u.test(worktree))
    throw unhealthy("Git status XY is invalid");
  return Object.freeze({
    path: validPath(path),
    index: index === "." ? " " : index,
    worktree: worktree === "." ? " " : worktree,
    ...(unsupported ? { unsupported } : {}),
    ...(relatedPath ? { relatedPath } : {}),
  });
}
function invalid(message: string) {
  return new RepositoryBoundaryError("invalid_input", message);
}
function unhealthy(message: string) {
  return new RepositoryBoundaryError("service_unhealthy", message);
}
function unavailable() {
  return new RepositoryBoundaryError(
    "capability_unavailable",
    "Confined Git broker is unavailable",
  );
}
export type GitBrokerSpawn = (
  file: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio & { stdio: ["pipe", "pipe", "pipe"] },
) => ChildProcessWithoutNullStreams;

export async function runBroker(
  invocation: ReturnType<typeof nativeGitBrokerInvocation>,
  input: Buffer,
  context: Phase2OperationContext,
  spawnProcess: GitBrokerSpawn = spawn,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawnProcess(invocation.file, [...invocation.args], {
        ...invocation.options,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      input.fill(0);
      reject(unavailable());
      return;
    }
    const output: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let pendingError: Error | undefined;
    let killRequested = false;
    let closed = false;
    const kill = () => {
      if (killRequested) return;
      killRequested = true;
      try {
        if (child.pid === undefined) throw new Error("missing pid");
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const failAndKill = (error: Error) => {
      pendingError ??= error;
      kill();
    };
    const abort = () =>
      failAndKill(
        context.signal.aborted
          ? new RepositoryBoundaryError(
              "operation_cancelled",
              "Operation was cancelled",
            )
          : new RepositoryBoundaryError(
              "deadline_exceeded",
              "Operation deadline expired",
            ),
      );
    const timer = setInterval(() => {
      if (context.signal.aborted || Date.now() >= context.deadlineAt) abort();
    }, 10);
    context.signal.addEventListener("abort", abort, { once: true });
    const cleanup = () => {
      clearInterval(timer);
      context.signal.removeEventListener("abort", abort);
      input.fill(0);
    };
    child.stdout.on("data", (chunk: Buffer) => {
      const owned = Buffer.from(chunk);
      stdoutBytes += owned.length;
      if (stdoutBytes > MAX_BROKER_OUTPUT + RESPONSE_HEADER_BYTES) {
        owned.fill(0);
        failAndKill(unhealthy("Git broker output exceeded its boundary"));
      } else output.push(owned);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const owned = Buffer.from(chunk);
      stderrBytes += owned.length;
      owned.fill(0);
      if (stderrBytes > MAX_STDERR)
        failAndKill(unhealthy("Git broker diagnostics exceeded its boundary"));
    });
    child.stdout.on("error", () =>
      failAndKill(unhealthy("Git broker output failed safely")),
    );
    child.stderr.on("error", () =>
      failAndKill(unhealthy("Git broker diagnostics failed safely")),
    );
    child.stdin.on("error", () =>
      failAndKill(unhealthy("Git broker input failed safely")),
    );
    child.on("error", () => failAndKill(unavailable()));
    child.on("close", (code) => {
      if (closed) return;
      closed = true;
      cleanup();
      if (!pendingError && code !== 0)
        pendingError = unhealthy("Git broker failed safely");
      if (pendingError) {
        for (const chunk of output) chunk.fill(0);
        reject(pendingError);
        return;
      }
      const result = Buffer.concat(output);
      for (const chunk of output) chunk.fill(0);
      resolve(result);
    });
    child.stdin.end(input, () => input.fill(0));
    if (context.signal.aborted || Date.now() >= context.deadlineAt) abort();
  });
}
