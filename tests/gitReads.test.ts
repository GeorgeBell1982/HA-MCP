import { createHash, randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import {
  GIT_MAX_DIFF_WORK,
  GitReadService,
  GitWorkPoller,
  NativeGitBroker,
  canonicalUnifiedPatch,
  decodeGitBrokerResponse,
  encodeGitBrokerRequest,
  encodeGitObjects,
  nativeGitBrokerInvocation,
  parseGitIndex,
  parseGitObjects,
  parseGitStatus,
  parseGitTree,
  parseObjectFormat,
  prepareGitYamlSide,
  runBroker,
  truncateGitPatch,
  type GitBroker,
  type GitBrokerRequest,
  type GitBrokerResponse,
  type GitBrokerSpawn,
} from "../src/git/gitReads.js";
import type {
  RepositoryCatalog,
  RepositoryCatalogProvider,
} from "../src/repository/repositoryReads.js";
import {
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
  type SecureFileReader,
} from "../src/security/repositoryBoundary.js";

const identity = (inode: string): FileIdentity => ({ device: "1", inode });
const operation = (
  signal = new AbortController().signal,
): Phase2OperationContext => ({
  requestId: randomUUID(),
  operationId: randomUUID(),
  deadlineAt: Date.now() + 30_000,
  signal,
});
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

function response(output: Uint8Array = new Uint8Array()): GitBrokerResponse {
  return {
    rootIdentity: identity("root"),
    gitIdentity: identity("git"),
    headDigest: "1".repeat(64),
    indexDigest: "2".repeat(64),
    output,
  };
}

class FakeBroker implements GitBroker {
  readonly requests: GitBrokerRequest[] = [];
  constructor(
    readonly outputs: Partial<
      Record<GitBrokerRequest["operation"], Uint8Array>
    >,
  ) {}
  async execute(request: GitBrokerRequest): Promise<GitBrokerResponse> {
    this.requests.push(request);
    const output = this.outputs[request.operation];
    return response(output ? Buffer.from(output) : new Uint8Array());
  }
}

class Reader implements SecureFileReader {
  rootIdentity = identity("root");
  readonly reads: string[] = [];
  constructor(
    readonly values: Map<string, { bytes: Buffer; identity: FileIdentity }>,
  ) {}
  async read(path: string): Promise<SecureFileRead> {
    this.reads.push(path);
    const value = this.values.get(path);
    if (!value) throw new RepositoryBoundaryError("path_denied", "missing");
    return {
      path,
      identity: value.identity,
      rootIdentity: this.rootIdentity,
      bytes: Buffer.from(value.bytes),
    };
  }
}

class Catalogs implements RepositoryCatalogProvider {
  constructor(readonly value: RepositoryCatalog) {}
  async catalog() {
    return this.value;
  }
}

async function fixture(current = "value: new\n") {
  const currentBytes = Buffer.from(current);
  const secretBytes = Buffer.from("protected: supersecretvalue\n");
  const reader = new Reader(
    new Map([
      [
        "configuration.yaml",
        { bytes: currentBytes, identity: identity("config") },
      ],
      ["secrets.yaml", { bytes: secretBytes, identity: identity("secret") }],
    ]),
  );
  const registry = new ProtectedIdentityRegistry(reader);
  await registry.initialize(
    ["secrets.yaml"],
    { loadExactValues: async () => ["supersecretvalue"] },
    operation(),
  );
  const catalog: RepositoryCatalog = {
    rootIdentity: identity("root"),
    directories: [],
    files: [
      {
        path: "configuration.yaml",
        identity: identity("config"),
        size: currentBytes.length,
        mtimeNanoseconds: "1",
        ctimeNanoseconds: "1",
      },
      {
        path: "secrets.yaml",
        identity: identity("secret"),
        size: secretBytes.length,
        mtimeNanoseconds: "1",
        ctimeNanoseconds: "1",
      },
    ],
  };
  return { reader, registry, catalogs: new Catalogs(catalog) };
}

describe("Slice F confined Git reads", () => {
  it("fails closed off Linux or without absolute packaged paths and exposes an empty inherited environment", async () => {
    await expect(
      new NativeGitBroker({ platform: "win32" }).execute(
        { operation: "status" },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "capability_unavailable" });
    expect(() =>
      nativeGitBrokerInvocation(
        "relative",
        "/usr/bin/git",
        "/homeassistant",
        "/lib/ld-musl-x86_64.so.1",
      ),
    ).toThrowError(RepositoryBoundaryError);
    const invocation = nativeGitBrokerInvocation(
      "/app/git-broker",
      "/usr/bin/git",
      "/homeassistant",
      "/lib/ld-musl-x86_64.so.1",
      ["/usr/lib/libpcre2-8.so.0.14.0", "/usr/lib/libz.so.1.3.2"],
    );
    await expect(
      new NativeGitBroker({
        platform: "linux",
        brokerPath: "/app/git-broker",
        gitPath: "/usr/bin/git",
      }).execute({ operation: "status" }, operation()),
    ).rejects.toMatchObject({ code: "capability_unavailable" });
    expect(() =>
      nativeGitBrokerInvocation(
        "/app/git-broker",
        "/usr/bin/git",
        "/homeassistant",
        "relative-loader",
      ),
    ).toThrowError(RepositoryBoundaryError);
    expect(() =>
      nativeGitBrokerInvocation(
        "/app/git-broker",
        "/usr/bin/git",
        "/homeassistant",
        "/lib/ld-musl-x86_64.so.1",
        ["/lib/ld-musl-x86_64.so.1"],
      ),
    ).toThrowError(RepositoryBoundaryError);
    expect(() =>
      nativeGitBrokerInvocation(
        "/app/git-broker",
        "/usr/bin/git",
        "/homeassistant",
        "/lib/ld-musl-x86_64.so.1",
        Array.from({ length: 17 }, (_, index) => `/usr/lib/lib${index}.so`),
      ),
    ).toThrowError(RepositoryBoundaryError);
    expect(invocation).toMatchObject({
      file: "/app/git-broker",
      args: [
        "--protocol-v1",
        "--git",
        "/usr/bin/git",
        "--root",
        "/homeassistant",
        "--runtime-loader",
        "/lib/ld-musl-x86_64.so.1",
        "--runtime-input",
        "/usr/lib/libpcre2-8.so.0.14.0",
        "--runtime-input",
        "/usr/lib/libz.so.1.3.2",
      ],
      options: {
        cwd: "/homeassistant",
        detached: true,
        windowsHide: true,
        env: {},
      },
    });
  });

  it("encodes only enumerated canonical broker requests", () => {
    const status = encodeGitBrokerRequest({ operation: "status" });
    expect(status.subarray(0, 7).toString("ascii")).toBe("HAGIT1\0");
    expect(status[7]).toBe(1);
    expect(status.readUInt32BE(8)).toBe(0);
    const ids = ["a".repeat(40), "b".repeat(40)];
    const objects = encodeGitBrokerRequest({
      operation: "objects",
      objectIds: ids,
    });
    expect(objects.subarray(16).toString("ascii")).toBe(ids.join("\n"));
    expect(() =>
      encodeGitBrokerRequest({ operation: "status", objectIds: ids }),
    ).toThrowError(RepositoryBoundaryError);
    expect(() =>
      encodeGitBrokerRequest({ operation: "objects", objectIds: ["../bad"] }),
    ).toThrowError(RepositoryBoundaryError);
  });

  it("decodes strict bounded identity responses and rejects reserved/status/framing drift", () => {
    const value = Buffer.alloc(131);
    Buffer.from("HAGITR1\0").copy(value);
    value.writeUInt32BE(1, 8);
    value.writeBigUInt64BE(1n, 24);
    value.writeBigUInt64BE(2n, 32);
    value.writeBigUInt64BE(1n, 40);
    value.writeBigUInt64BE(3n, 48);
    value.fill(0x11, 56, 88);
    value.fill(0x22, 88, 104);
    value.writeUInt32BE(3, 120);
    value.write("ok\n", 128);
    expect(decodeGitBrokerResponse(value)).toMatchObject({
      rootIdentity: { device: "1", inode: "2" },
      gitIdentity: { device: "1", inode: "3" },
      output: Buffer.from("ok\n"),
    });
    const reserved = Buffer.from(value);
    reserved.writeUInt32BE(1, 124);
    expect(() => decodeGitBrokerResponse(reserved)).toThrowError(
      RepositoryBoundaryError,
    );
    const unavailable = Buffer.from(value);
    unavailable.writeUInt32BE(4, 12);
    expect(() => decodeGitBrokerResponse(unavailable)).toThrowError(
      RepositoryBoundaryError,
    );
  });

  it("parses clean, detached, unborn, tracked and untracked status in UTF-8 order", () => {
    const oid = "a".repeat(40);
    const value = [
      `# branch.oid ${oid}`,
      "# branch.head main",
      `1 .M N... 100644 100644 100644 ${oid} ${oid} z.yaml`,
      "? a.yaml",
      "",
    ].join("\0");
    expect(parseGitStatus(Buffer.from(value))).toEqual({
      branch: "main",
      unborn: false,
      entries: [
        { path: "a.yaml", index: "?", worktree: "?" },
        { path: "z.yaml", index: " ", worktree: "M" },
      ],
    });
    expect(
      parseGitStatus(
        Buffer.from("# branch.oid (initial)\0# branch.head new\0"),
      ),
    ).toMatchObject({ branch: "new", unborn: true });
    expect(
      parseGitStatus(
        Buffer.from(`# branch.oid ${oid}\0# branch.head (detached)\0`),
      ),
    ).toMatchObject({ branch: null, unborn: false });
  });

  it("strictly rejects malformed type-1 status records and wipes their input", () => {
    const oid = "a".repeat(40);
    const prefix = `# branch.oid ${oid}\0# branch.head main\0`;
    for (const record of [
      `1 R. N... 100644 100644 100644 ${oid} ${oid} renamed.yaml`,
      `1 .M N... 100664 100644 100644 ${oid} ${oid} bad-mode.yaml`,
      `1 .M N... 100644 100644 100644 ${oid.toUpperCase()} ${oid} uppercase.yaml`,
      `1 .M N... 100644 100644 100644 ${oid} ${"b".repeat(64)} mixed.yaml`,
      `1 .M N... 000000 100644 100644 ${oid} ${oid} zero-mode.yaml`,
      `1 D. N... 100644 000000 100644 ${oid} ${"0".repeat(40)} deleted.yaml`,
    ]) {
      const encoded = Buffer.from(`${prefix}${record}\0`);
      expect(() => parseGitStatus(encoded)).toThrowError(
        RepositoryBoundaryError,
      );
      expect(encoded.every((value) => value === 0)).toBe(true);
    }
    for (const mode of ["120000", "160000"]) {
      const parsed = parseGitStatus(
        Buffer.from(
          `${prefix}1 .M N... ${mode} ${mode} ${mode} ${oid} ${oid} special.yaml\0`,
        ),
      );
      expect(parsed.entries).toEqual([
        expect.objectContaining({
          path: "special.yaml",
          unsupported: "type-change",
        }),
      ]);
    }
  });
  it("rejects rename, unmerged, submodule, malformed/duplicate/control paths and status N+1", () => {
    for (const record of [
      "2 R. N... bad",
      "u UU N... bad",
      `1 .M S.M. 100644 100644 100644 ${"a".repeat(40)} ${"a".repeat(40)} bad.yaml`,
      "! ignored.yaml",
      "? ../bad.yaml",
    ])
      expect(() => parseGitStatus(Buffer.from(`${record}\0`))).toThrowError(
        RepositoryBoundaryError,
      );
    const tooMany =
      Array.from({ length: 501 }, (_, index) => `? p${index}.yaml`).join("\0") +
      "\0";
    expect(() => parseGitStatus(Buffer.from(tooMany))).toThrowError(
      RepositoryBoundaryError,
    );
    const invalidUtf8 = Buffer.from([0xff, 0]);
    expect(() => parseGitStatus(invalidUtf8)).toThrowError(
      RepositoryBoundaryError,
    );
    expect(invalidUtf8.every((value) => value === 0)).toBe(true);
  });

  it("strictly parses SHA-1/SHA-256 stage-zero regular blobs and object batches", () => {
    const sha1 = "a".repeat(40),
      sha256 = "b".repeat(64);
    expect(
      parseGitIndex(Buffer.from(`100644 ${sha1} 0\ta.yaml\0`), "sha1").get(
        "a.yaml",
      )?.objectId,
    ).toBe(sha1);
    expect(
      parseGitTree(
        Buffer.from(`100644 blob ${sha256}\ta.yaml\0`),
        "sha256",
      ).get("a.yaml")?.objectId,
    ).toBe(sha256);
    expect(parseObjectFormat(Buffer.from("sha256\n"))).toBe("sha256");
    for (const unsupported of [
      `120000 ${sha1} 0\ta.yaml\0`,
      `160000 ${sha1} 0\ta.yaml\0`,
      `100644 ${sha1} 2\ta.yaml\0`,
    ]) {
      expect(
        parseGitIndex(Buffer.from(unsupported), "sha1").get("a.yaml")
          ?.supported,
      ).toBe(false);
    }
    expect(
      parseGitTree(Buffer.from(`120000 blob ${sha1}\ta.yaml\0`), "sha1").get(
        "a.yaml",
      )?.supported,
    ).toBe(false);
    const encoded = encodeGitObjects(
      new Map([[sha1, Buffer.from("value: old\n")]]),
    );
    expect(parseGitObjects(encoded, "sha1", [sha1]).get(sha1)?.toString()).toBe(
      "value: old\n",
    );
    expect(() =>
      parseGitObjects(encoded, "sha1", ["c".repeat(40)]),
    ).toThrowError(RepositoryBoundaryError);
  });

  it("builds deterministic staged/worktree canonical patches with context and no-final-newline markers", () => {
    const oldText = "a\nb\nc\nd\ne\nf\ng\n";
    const newText = "a\nb\nc\nchanged\ne\nf\ng\n";
    const patch = canonicalUnifiedPatch(oldText, newText, "config.yaml");
    expect(patch).toContain("--- a/config.yaml\n+++ b/config.yaml\n");
    expect(patch).toContain("-d\n+changed\n");
    expect(canonicalUnifiedPatch("same\n", "same\n", "config.yaml")).toBe("");
    expect(canonicalUnifiedPatch("old", "new", "config.yaml")).toContain(
      "\\ No newline at end of file",
    );
    expect(canonicalUnifiedPatch("old", "new\n", "config.yaml")).toContain(
      "-old\n\\ No newline at end of file\n+new\n",
    );
    expect(canonicalUnifiedPatch("old\n", "new", "config.yaml")).toContain(
      "-old\n+new\n\\ No newline at end of file\n",
    );
    expect(() =>
      canonicalUnifiedPatch(
        "",
        Array.from({ length: GIT_MAX_DIFF_WORK + 1 }, (_, i) => String(i)).join(
          "\n",
        ),
        "x.yaml",
      ),
    ).toThrowError(RepositoryBoundaryError);
  });

  it("truncates only complete post-redaction lines with a fixed marker", () => {
    const result = truncateGitPatch(("x".repeat(1000) + "\n").repeat(600));
    expect(result.truncated).toBe(true);
    expect(result.patch.endsWith("@@ [REDACTED PATCH TRUNCATED] @@\n")).toBe(
      true,
    );
    expect(Buffer.byteLength(result.patch)).toBeLessThanOrEqual(512 * 1024);
  });

  it("validates YAML once, masks secret names, redacts exact values and rejects NUL/invalid YAML", async () => {
    const { registry } = await fixture();
    const value = await prepareGitYamlSide(
      Buffer.from("token: !secret SECRET_NAME\nvalue: supersecretvalue\n"),
      registry,
      operation(),
    );
    expect(value).not.toContain("SECRET_NAME");
    expect(value).not.toContain("supersecretvalue");
    expect(value).toContain("[REDACTED]");
    await expect(
      prepareGitYamlSide(Buffer.from([0]), registry, operation()),
    ).rejects.toMatchObject({ code: "unsupported_encoding" });
    await expect(
      prepareGitYamlSide(Buffer.from("a: ["), registry, operation()),
    ).rejects.toBeTruthy();
  });

  it("orchestrates fixed plumbing only and returns a complete redacted worktree digest", async () => {
    const oid = "a".repeat(40);
    const oldBytes = Buffer.from("value: old\n");
    const { reader, registry, catalogs } = await fixture();
    const status = Buffer.from(
      [
        `# branch.oid ${oid}`,
        "# branch.head main",
        `1 .M N... 100644 100644 100644 ${oid} ${oid} configuration.yaml`,
        "",
      ].join("\0"),
    );
    const broker = new FakeBroker({
      status,
      "object-format": Buffer.from("sha1\n"),
      index: Buffer.from(`100644 ${oid} 0\tconfiguration.yaml\0`),
      tree: Buffer.from(`100644 blob ${oid}\tconfiguration.yaml\0`),
      objects: encodeGitObjects(new Map([[oid, oldBytes]])),
    });
    const service = new GitReadService(catalogs, reader, registry, broker);
    const result = await service.diff(
      { scope: "worktree", paths: ["configuration.yaml"] },
      operation(),
    );
    expect(result.patch).toContain("### worktree: configuration.yaml");
    expect(result.patch).toContain("-value: old\n+value: new\n");
    expect(result.diffSha256).toBe(sha(Buffer.from(result.patch)));
    expect(result.truncated).toBe(false);
    expect(broker.requests.map((request) => request.operation)).toEqual([
      "status",
      "object-format",
      "index",
      "tree",
      "objects",
      "objects",
      "status",
    ]);
    expect(
      broker.requests.some((request) => String(request).includes("git diff")),
    ).toBe(false);
  });

  it("wipes already-acquired index/tree responses when format or index parsing fails", async () => {
    for (const failure of ["format", "index"] as const) {
      const { reader, registry, catalogs } = await fixture();
      const oid = "a".repeat(40);
      const status = Buffer.from(
        [
          `# branch.oid ${oid}`,
          "# branch.head main",
          `1 .M N... 100644 100644 100644 ${oid} ${oid} configuration.yaml`,
          "",
        ].join("\0"),
      );
      const format = Buffer.from(failure === "format" ? "bad\n" : "sha1\n");
      const index = Buffer.from(
        failure === "index"
          ? "bad-index"
          : `100644 ${oid} 0\tconfiguration.yaml\0`,
      );
      const tree = Buffer.from(`100644 blob ${oid}\tconfiguration.yaml\0`);
      const buffers = { status, "object-format": format, index, tree };
      const broker: GitBroker = {
        async execute(request) {
          const output = buffers[request.operation as keyof typeof buffers];
          return response(output ?? Buffer.alloc(0));
        },
      };
      await expect(
        new GitReadService(catalogs, reader, registry, broker).diff(
          { scope: "worktree", paths: ["configuration.yaml"] },
          operation(),
        ),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
      for (const buffer of [format, index, tree])
        expect(buffer.every((value) => value === 0)).toBe(true);
    }
  });

  it("wipes acquired raw responses when the next index or tree broker call rejects", async () => {
    for (const rejection of ["index", "tree"] as const) {
      const { reader, registry, catalogs } = await fixture();
      const oid = "a".repeat(40);
      const status = Buffer.from(
        [
          `# branch.oid ${oid}`,
          "# branch.head main",
          `1 .M N... 100644 100644 100644 ${oid} ${oid} configuration.yaml`,
          "",
        ].join("\0"),
      );
      const formatCanary = Buffer.from("sha1\n");
      const indexCanary = Buffer.from(`100644 ${oid} 0\tconfiguration.yaml\0`);
      const broker: GitBroker = {
        async execute(request) {
          if (request.operation === "status") return response(status);
          if (request.operation === "object-format")
            return response(formatCanary);
          if (request.operation === "index") {
            if (rejection === "index") throw new Error("index rejected");
            return response(indexCanary);
          }
          if (request.operation === "tree") throw new Error("tree rejected");
          throw new Error("unexpected operation");
        },
      };
      await expect(
        new GitReadService(catalogs, reader, registry, broker).diff(
          { scope: "worktree", paths: ["configuration.yaml"] },
          operation(),
        ),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
      expect(formatCanary.every((value) => value === 0)).toBe(true);
      if (rejection === "tree")
        expect(indexCanary.every((value) => value === 0)).toBe(true);
    }
  });
  it("denies explicit protected/missing/non-YAML/duplicate paths before object retrieval and generically omits unsupported unscoped paths", async () => {
    const { reader, registry, catalogs } = await fixture();
    const broker = new FakeBroker({ status: Buffer.from("? secrets.yaml\0") });
    const service = new GitReadService(catalogs, reader, registry, broker);
    await expect(
      service.diff({ scope: "worktree", paths: ["secrets.yaml"] }, operation()),
    ).rejects.toMatchObject({ code: "protected_resource" });
    expect(broker.requests).toHaveLength(0);
    await expect(
      service.diff({ scope: "worktree", paths: ["missing.yaml"] }, operation()),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      service.diff({ scope: "worktree", paths: [] }, operation()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(
      service.diff(
        {
          scope: "worktree",
          paths: ["configuration.yaml", "configuration.yaml"],
        },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("returns protected status metadata without content and keeps untracked files out of index plumbing", async () => {
    const { reader, registry, catalogs } = await fixture("fresh: true\n");
    const status = Buffer.from(
      "# branch.oid (initial)\0# branch.head new\0? configuration.yaml\0? secrets.yaml\0",
    );
    const broker = new FakeBroker({
      status,
      "object-format": Buffer.from("sha1\n"),
      index: new Uint8Array(),
      tree: new Uint8Array(),
    });
    const service = new GitReadService(catalogs, reader, registry, broker);
    await expect(service.status(operation())).resolves.toMatchObject({
      branch: "new",
      unborn: true,
      entries: [
        { path: "configuration.yaml", index: "?", worktree: "?" },
        { path: "secrets.yaml", index: "?", worktree: "?" },
      ],
    });
    broker.requests.length = 0;
    const diff = await service.diff(
      { scope: "both", paths: ["configuration.yaml"] },
      operation(),
    );
    expect(diff.patch).toContain("### worktree: configuration.yaml");
    expect(diff.patch).not.toContain("### staged:");
    expect(
      broker.requests.some((request) => request.operation === "objects"),
    ).toBe(false);
    expect(diff.patch).not.toContain("secrets.yaml");
  });

  it("discards output when broker identity drifts and honors pre-cancelled operations", async () => {
    const { reader, registry, catalogs } = await fixture();
    let calls = 0;
    const drifting: GitBroker = {
      async execute() {
        calls += 1;
        return {
          ...response(
            Buffer.from("# branch.oid (initial)\0# branch.head main\0"),
          ),
          gitIdentity: identity(calls > 1 ? "changed" : "git"),
        };
      },
    };
    const service = new GitReadService(catalogs, reader, registry, drifting);
    await expect(
      service.diff({ scope: "both" }, operation()),
    ).rejects.toMatchObject({ code: "stale_source" });
    const controller = new AbortController();
    controller.abort();
    await expect(
      service.status(operation(controller.signal)),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
  });
  it("preserves unsupported status records for planner policy and wipes parser inputs", () => {
    const oid = "a".repeat(40);
    const encoded = Buffer.from(
      [
        `# branch.oid ${oid}`,
        "# branch.head main",
        `2 R. N... 100644 100644 100644 ${oid} ${oid} R100 new.yaml`,
        "old.yaml",
        `u UU N... 100644 100644 100644 100644 ${oid} ${oid} ${oid} conflict.yaml`,
        "",
      ].join("\0"),
    );
    const parsed = parseGitStatus(encoded);
    expect(encoded.every((value) => value === 0)).toBe(true);
    expect(parsed.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "new.yaml", unsupported: "rename" }),
        expect.objectContaining({ path: "old.yaml", unsupported: "rename" }),
        expect.objectContaining({
          path: "conflict.yaml",
          unsupported: "unmerged",
        }),
      ]),
    );
    for (const malformed of [
      `# branch.oid ${oid}\0`,
      `# branch.head main\0`,
      `# branch.oid ${oid}\0# branch.oid ${oid}\0# branch.head main\0`,
      `# branch.oid ${oid}\0# branch.head main\0# branch.upstream origin/main\0`,
    ])
      expect(() => parseGitStatus(Buffer.from(malformed))).toThrowError(
        RepositoryBoundaryError,
      );
  });

  it("polls cancellation during large parser work", () => {
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks > 1;
      },
      addEventListener() {},
      removeEventListener() {},
    } as unknown as AbortSignal;
    const context = { ...operation(), signal };
    const poller = new GitWorkPoller(context);
    const oid = "a".repeat(40);
    const status =
      `# branch.oid ${oid}\0# branch.head main\0` +
      Array.from({ length: 300 }, (_, index) => `? p${index}.yaml`).join("\0") +
      "\0";
    expect(() => parseGitStatus(Buffer.from(status), poller)).toThrowError(
      RepositoryBoundaryError,
    );
    expect(checks).toBeGreaterThan(1);
  });
  it("rejects current-file and object-content freshness drift", async () => {
    const oid = "a".repeat(40);
    const status = Buffer.from(
      [
        `# branch.oid ${oid}`,
        "# branch.head main",
        `1 .M N... 100644 100644 100644 ${oid} ${oid} configuration.yaml`,
        "",
      ].join("\0"),
    );
    const first = await fixture();
    let reads = 0;
    const driftingReader: SecureFileReader = {
      async read(path) {
        const result = await first.reader.read(path);
        if (path === "configuration.yaml" && ++reads > 1)
          return { ...result, bytes: Buffer.from("value: bad\n") };
        return result;
      },
    };
    const stable = new FakeBroker({
      status,
      "object-format": Buffer.from("sha1\n"),
      index: Buffer.from(`100644 ${oid} 0\tconfiguration.yaml\0`),
      tree: Buffer.from(`100644 blob ${oid}\tconfiguration.yaml\0`),
      objects: encodeGitObjects(new Map([[oid, Buffer.from("value: old\n")]])),
    });
    await expect(
      new GitReadService(
        first.catalogs,
        driftingReader,
        first.registry,
        stable,
      ).diff({ scope: "worktree", paths: ["configuration.yaml"] }, operation()),
    ).rejects.toMatchObject({ code: "stale_source" });

    const second = await fixture();
    let objectCalls = 0;
    const driftingObjects: GitBroker = {
      async execute(request) {
        if (request.operation === "objects") {
          objectCalls += 1;
          return response(
            encodeGitObjects(
              new Map([
                [
                  oid,
                  Buffer.from(
                    objectCalls === 1 ? "value: old\n" : "value: bad\n",
                  ),
                ],
              ]),
            ),
          );
        }
        const outputs: Partial<
          Record<GitBrokerRequest["operation"], Uint8Array>
        > = {
          status,
          "object-format": Buffer.from("sha1\n"),
          index: Buffer.from(`100644 ${oid} 0\tconfiguration.yaml\0`),
          tree: Buffer.from(`100644 blob ${oid}\tconfiguration.yaml\0`),
        };
        return response(Buffer.from(outputs[request.operation] ?? []));
      },
    };
    await expect(
      new GitReadService(
        second.catalogs,
        second.reader,
        second.registry,
        driftingObjects,
      ).diff({ scope: "worktree", paths: ["configuration.yaml"] }, operation()),
    ).rejects.toMatchObject({ code: "stale_source" });
    expect(objectCalls).toBe(2);
  });
  it("batches more than 200 Git objects deterministically for acquisition and freshness", async () => {
    const count = 201;
    const values = new Map<string, { bytes: Buffer; identity: FileIdentity }>();
    const files: RepositoryCatalog["files"][number][] = [];
    const statusRecords = [
      `# branch.oid ${"f".repeat(40)}`,
      "# branch.head main",
    ];
    const indexRecords: string[] = [];
    const treeRecords: string[] = [];
    const objects = new Map<string, Buffer>();
    for (let item = 0; item < count; item += 1) {
      const path = `p${String(item).padStart(3, "0")}.yaml`;
      const oid = (item + 1).toString(16).padStart(40, "0");
      const bytes = Buffer.from("value: new\n");
      values.set(path, { bytes, identity: identity(`file-${item}`) });
      files.push({
        path,
        identity: identity(`file-${item}`),
        size: bytes.length,
        mtimeNanoseconds: "1",
        ctimeNanoseconds: "1",
      });
      statusRecords.push(
        `1 .M N... 100644 100644 100644 ${oid} ${oid} ${path}`,
      );
      indexRecords.push(`100644 ${oid} 0\t${path}\0`);
      treeRecords.push(`100644 blob ${oid}\t${path}\0`);
      objects.set(oid, Buffer.from("value: old\n"));
    }
    const secretBytes = Buffer.from("secret: value\n");
    values.set("secrets.yaml", {
      bytes: secretBytes,
      identity: identity("secret"),
    });
    files.push({
      path: "secrets.yaml",
      identity: identity("secret"),
      size: secretBytes.length,
      mtimeNanoseconds: "1",
      ctimeNanoseconds: "1",
    });
    const reader = new Reader(values);
    const registry = new ProtectedIdentityRegistry(reader);
    await registry.initialize(
      ["secrets.yaml"],
      { loadExactValues: async () => [] },
      operation(),
    );
    const catalogs = new Catalogs({
      rootIdentity: identity("root"),
      directories: [],
      files,
    });
    const objectBatchSizes: number[] = [];
    const broker: GitBroker = {
      async execute(request) {
        if (request.operation === "objects") {
          const ids = request.objectIds ?? [];
          objectBatchSizes.push(ids.length);
          return response(
            encodeGitObjects(
              new Map(ids.map((oid) => [oid, objects.get(oid)!])),
            ),
          );
        }
        const outputs: Partial<
          Record<GitBrokerRequest["operation"], Uint8Array>
        > = {
          status: Buffer.from(statusRecords.concat("").join("\0")),
          "object-format": Buffer.from("sha1\n"),
          index: Buffer.from(indexRecords.join("")),
          tree: Buffer.from(treeRecords.join("")),
        };
        return response(Buffer.from(outputs[request.operation] ?? []));
      },
    };
    const result = await new GitReadService(
      catalogs,
      reader,
      registry,
      broker,
    ).diff({ scope: "worktree" }, operation());
    expect(result.patch).toContain("p000.yaml");
    expect(result.patch).toContain("p200.yaml");
    expect(objectBatchSizes).toEqual([200, 1, 200, 1]);
  });
  it("waits for broker close, wipes input, and enforces stdout/stderr/cancellation boundaries", async () => {
    const invocation = nativeGitBrokerInvocation(
      "/app/git-broker",
      "/usr/bin/git",
      "/homeassistant",
      "/lib/ld-musl-x86_64.so.1",
    );
    const makeChild = () => {
      const stdin = new PassThrough();
      const stdout = new PassThrough();
      const stderr = new PassThrough();
      const kill = vi.fn(() => true);
      const child = Object.assign(new EventEmitter(), {
        stdin,
        stdout,
        stderr,
        pid: undefined,
        kill,
      }) as unknown as ReturnType<GitBrokerSpawn>;
      const spawn: GitBrokerSpawn = () => child;
      return { child, stdin, stdout, stderr, kill, spawn };
    };

    const successful = makeChild();
    const input = Buffer.from("sensitive request");
    const pending = runBroker(invocation, input, operation(), successful.spawn);
    let settled = false;
    void pending.finally(() => {
      settled = true;
    });
    successful.child.emit("exit", 0);
    successful.stdout.write("ok");
    await Promise.resolve();
    expect(settled).toBe(false);
    successful.child.emit("close", 0);
    await expect(pending).resolves.toEqual(Buffer.from("ok"));
    expect(input.every((value) => value === 0)).toBe(true);

    const exact = makeChild();
    const exactPending = runBroker(
      invocation,
      Buffer.from("x"),
      operation(),
      exact.spawn,
    );
    exact.stdout.write(Buffer.alloc(4 * 1024 * 1024 + 128));
    exact.child.emit("close", 0);
    await expect(exactPending).resolves.toHaveLength(4 * 1024 * 1024 + 128);

    const overflow = makeChild();
    const overflowPending = runBroker(
      invocation,
      Buffer.from("x"),
      operation(),
      overflow.spawn,
    );
    overflow.stdout.write(Buffer.alloc(4 * 1024 * 1024 + 129));
    expect(overflow.kill).toHaveBeenCalledTimes(1);
    overflow.child.emit("close", null);
    await expect(overflowPending).rejects.toMatchObject({
      code: "service_unhealthy",
    });

    const diagnostics = makeChild();
    const diagnosticPending = runBroker(
      invocation,
      Buffer.from("x"),
      operation(),
      diagnostics.spawn,
    );
    diagnostics.stderr.write(Buffer.alloc(4097));
    expect(diagnostics.kill).toHaveBeenCalledTimes(1);
    diagnostics.child.emit("close", null);
    await expect(diagnosticPending).rejects.toMatchObject({
      code: "service_unhealthy",
    });

    const cancelled = makeChild();
    const controller = new AbortController();
    const cancelledPending = runBroker(
      invocation,
      Buffer.from("x"),
      operation(controller.signal),
      cancelled.spawn,
    );
    controller.abort();
    expect(cancelled.kill).toHaveBeenCalledTimes(1);
    cancelled.child.emit("close", null);
    await expect(cancelledPending).rejects.toMatchObject({
      code: "operation_cancelled",
    });
  });
  it("source-contracts root/.git pinning, exact isolation, fixed plumbing, and no git diff", async () => {
    const source = await readFile(
      new URL("../src/git/native/git-broker.c", import.meta.url),
      "utf8",
    );
    for (const token of [
      "SYS_openat2",
      "RESOLVE_BENEATH",
      "RESOLVE_NO_SYMLINKS",
      "RESOLVE_NO_MAGICLINKS",
      "RESOLVE_NO_XDEV",
      "PR_SET_NO_NEW_PRIVS",
      "SYS_landlock_restrict_self",
      "SECCOMP_MODE_FILTER",
      "RLIMIT_CPU",
      "RLIMIT_AS",
      "RLIMIT_NPROC",
      "clearenv",
      "GIT_CONFIG_NOSYSTEM",
      "GIT_TERMINAL_PROMPT",
      "GIT_OPTIONAL_LOCKS",
      "GIT_NO_LAZY_FETCH",
      "GIT_LITERAL_PATHSPECS",
      "--porcelain=v2",
      "--no-renames",
      "ls-files",
      "ls-tree",
      "cat-file",
      "fchdir",
      "/proc/self/fd",
      "SYS_execveat",
      "seccomp_data, args[0]",
      "seccomp_data, args[4]",
      "PR_SET_PDEATHSIG",
      "poll(streams,2,-1)",
      "--runtime-loader",
      "--runtime-input",
      "same_file_snapshot",
      "no_promisor_packs",
      "F_DUPFD_CLOEXEC",
      "--batch-check=%(objectname) %(objecttype) %(objectsize)",
      'section_base_is(section,"receive")',
      'section_base_is(section,"uploadpack")',
      'section_base_is(section,"protocol")',
      'section_base_is(section,"alias")',
      'section_base_is(section,"gpg")',
      "info/alternates",
      "info/http-alternates",
      "refs/replace",
      ".promisor",
    ])
      expect(source).toContain(token);
    expect(source).toContain(`strcmp(argv[6],"--runtime-loader")`);
    expect(source).toContain(
      `loader_fd=open(argv[7],O_PATH|O_CLOEXEC|O_NOFOLLOW)`,
    );
    expect(source).toContain(
      `runtime_inputs[i]=open(argv[9+i*2],O_PATH|O_CLOEXEC|O_NOFOLLOW)`,
    );
    expect(source).toContain("!S_ISREG(loader_metadata.st_mode)");
    expect(source).toContain("!S_ISREG(input_metadata[i].st_mode)");
    expect(source).toContain(
      "same_identity(&loader_metadata,&input_metadata[i])",
    );
    expect(source).toContain(
      "same_identity(&input_metadata[j],&input_metadata[i])",
    );
    expect(source).toContain(
      "add_landlock_path(ruleset,loader_fd,LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE)",
    );
    expect(source).toContain(
      "add_landlock_path(ruleset,runtime_inputs[index],LANDLOCK_ACCESS_FS_READ_FILE)",
    );
    expect(source).toContain(
      'null_fd=open("/dev/null",O_RDWR|O_CLOEXEC|O_NOFOLLOW)',
    );
    expect(source).toContain(
      "add_landlock_path(ruleset,null_fd,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_WRITE_FILE)",
    );
    expect(source.match(/LANDLOCK_ACCESS_FS_WRITE_FILE/gu)).toHaveLength(2);
    expect(source).not.toContain(
      "add_landlock_path(ruleset,runtime_inputs[index],LANDLOCK_ACCESS_FS_EXECUTE",
    );
    expect(source).toContain(
      "static int run_git(int runtime_fd,int root_fd,int git_fd,int null_fd",
    );
    expect(source).toContain("fcntl(fd,F_GETFD)");
    expect(source).toContain("fcntl(fd,F_SETFD,flags&~FD_CLOEXEC)");
    expect(source.match(/clear_cloexec_for_child\(/gu)).toHaveLength(4);
    expect(
      source.match(/run_git\(runtime_fd,root_fd,git_fd,null_fd,/gu),
    ).toHaveLength(3);
    expect(source).not.toContain("clear_cloexec_for_child(loader_fd)");
    expect(source).not.toContain("clear_cloexec_for_child(runtime_inputs");
    const inheritAt = source.indexOf(
      "if(clear_cloexec_for_child(root_fd)||clear_cloexec_for_child(git_fd)||clear_cloexec_for_child(null_fd))",
    );
    expect(inheritAt).toBeGreaterThan(source.indexOf("if(child==0)"));
    expect(inheritAt).toBeLessThan(
      source.indexOf("install_seccomp_isolation(execute_fd)", inheritAt),
    );
    const checkAt = source.indexOf('check_argv[check_used++]="--batch-check');
    const contentAt = source.indexOf(
      "run_git(runtime_fd,root_fd,git_fd,null_fd,git_argv",
      checkAt,
    );
    expect(checkAt).toBeGreaterThan(0);
    expect(contentAt).toBeGreaterThan(checkAt);
    expect(
      source.match(/absent_beneath\(objects_fd,"info\/alternates"/gu),
    ).toHaveLength(2);
    expect(
      source.match(/absent_beneath\(objects_fd,"info\/http-alternates"/gu),
    ).toHaveLength(2);
    expect(source).not.toMatch(/git_argv\[used\+\+\]\s*=\s*"diff"/u);
    expect(source).not.toContain("setpgid(");
    expect(source).not.toContain("system(");
    expect(source).not.toContain("popen(");
  });
});
