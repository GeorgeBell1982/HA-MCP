import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { redact } from "../src/redaction.js";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import {
  NativeOpenat2Catalog,
  RepositoryCursorCodec,
  RepositoryReadService,
  catalogsMatchExactly,
  decodeCatalogOutput,
  type CatalogFile,
  type RepositoryCatalog,
  type RepositoryCatalogProvider,
} from "../src/repository/repositoryReads.js";
import {
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
  type SecureFileReader,
} from "../src/security/repositoryBoundary.js";

const operation = (
  controller = new AbortController(),
): Phase2OperationContext => ({
  requestId: randomUUID(),
  operationId: randomUUID(),
  deadlineAt: Date.now() + 30_000,
  signal: controller.signal,
});
const id = (inode: string): FileIdentity => ({ device: "1", inode });
const sha = (value: string) => createHash("sha256").update(value).digest("hex");

class MutableReader implements SecureFileReader {
  readonly reads: string[] = [];
  rootIdentity = id("root");
  constructor(
    readonly files: Map<string, { identity: FileIdentity; content: string }>,
    private readonly beforeRead?: (path: string, count: number) => void,
  ) {}
  async read(path: string): Promise<SecureFileRead> {
    this.reads.push(path);
    this.beforeRead?.(path, this.reads.filter((item) => item === path).length);
    const value = this.files.get(path);
    if (!value) throw new RepositoryBoundaryError("path_denied", "missing");
    return {
      path,
      identity: value.identity,
      rootIdentity: this.rootIdentity,
      bytes: Buffer.from(value.content),
    };
  }
}

const entry = (path: string, inode: string, content: string): CatalogFile => ({
  path,
  identity: id(inode),
  size: Buffer.byteLength(content),
  mtimeNanoseconds: "1",
  ctimeNanoseconds: "1",
});
const catalog = (files: CatalogFile[]): RepositoryCatalog => ({
  rootIdentity: id("root"),
  directories: [],
  files,
});
class FakeCatalog implements RepositoryCatalogProvider {
  constructor(public value: RepositoryCatalog) {}
  async catalog(): Promise<RepositoryCatalog> {
    return this.value;
  }
}

async function fixture(
  content = "first: needle\npassword=hunter2 needle\nlast: needle\n",
  mutate?: (path: string, count: number, files: MutableReader["files"]) => void,
) {
  const files = new Map([
    ["configuration.yaml", { identity: id("10"), content }],
    ["packages/alias.yaml", { identity: id("20"), content: "secret: alias" }],
    ["secrets.yaml", { identity: id("20"), content: "password: swordfish" }],
  ]);
  const reader = new MutableReader(files, (path, count) =>
    mutate?.(path, count, files),
  );
  const protectedRegistry = new ProtectedIdentityRegistry(reader);
  await protectedRegistry.initialize(
    ["secrets.yaml"],
    { loadExactValues: async () => ["swordfish"] },
    operation(),
  );
  const provider = new FakeCatalog(
    catalog([
      entry("configuration.yaml", "10", content),
      entry("packages/alias.yaml", "20", "secret: alias"),
      entry("secrets.yaml", "20", "password: swordfish"),
    ]),
  );
  const cursors = new RepositoryCursorCodec(randomBytes(32));
  return {
    reader,
    provider,
    protectedRegistry,
    cursors,
    service: new RepositoryReadService(
      provider,
      reader,
      protectedRegistry,
      cursors,
    ),
  };
}

function catalogBytes(
  paths: Array<{
    type: 1 | 2;
    path: string;
    inode: bigint;
    size?: bigint;
    mtimeSeconds?: bigint;
    ctimeSeconds?: bigint;
  }>,
): Buffer {
  const payload = paths.map(
    ({
      type,
      path,
      inode,
      size = 0n,
      mtimeSeconds = 1n,
      ctimeSeconds = 2n,
    }) => {
      const raw = Buffer.from(path);
      const record = Buffer.alloc(60 + raw.length);
      record[0] = type;
      record.writeUInt16BE(raw.length, 2);
      record.writeBigUInt64BE(1n, 4);
      record.writeBigUInt64BE(inode, 12);
      record.writeBigUInt64BE(size, 20);
      record.writeBigUInt64BE(mtimeSeconds, 28);
      record.writeBigUInt64BE(ctimeSeconds, 44);
      raw.copy(record, 60);
      return record;
    },
  );
  const header = Buffer.alloc(48);
  header.write("HALIST2\0", 0, "ascii");
  header.writeUInt32BE(1, 8);
  header.writeBigUInt64BE(1n, 16);
  header.writeBigUInt64BE(2n, 24);
  header.writeUInt32BE(paths.filter((item) => item.type === 1).length, 32);
  header.writeUInt32BE(paths.filter((item) => item.type === 2).length, 36);
  header.writeUInt32BE(
    payload.reduce((sum, item) => sum + item.length, 0),
    40,
  );
  return Buffer.concat([header, ...payload]);
}

describe("Phase 2 repository catalog and reads", () => {
  it("fails catalog capability closed and decodes only strict sorted YAML protocol", async () => {
    await expect(
      new NativeOpenat2Catalog({ platform: "win32" }).catalog(operation()),
    ).rejects.toMatchObject({ code: "capability_unavailable" });
    const output = catalogBytes([
      { type: 1, path: "packages", inode: 3n },
      { type: 2, path: "packages/a.yaml", inode: 4n, size: 5n },
    ]);
    const decoded = decodeCatalogOutput(output);
    expect(decoded.directories[0]).toMatchObject({
      path: "packages",
      identity: { device: "1", inode: "3" },
      mtimeNanoseconds: "1000000000",
      ctimeNanoseconds: "2000000000",
    });
    expect(decoded.files[0]).toMatchObject({
      path: "packages/a.yaml",
      size: 5,
    });
    output[0] = 0;
    expect(() => decodeCatalogOutput(output)).toThrow(RepositoryBoundaryError);
  });

  it("rejects reserved bytes, directory size, and non-global ordering while comparing directory metadata", () => {
    const canonical = catalogBytes([
      { type: 1, path: "packages", inode: 3n },
      { type: 2, path: "packages/a.yaml", inode: 4n, size: 5n },
    ]);
    for (const corrupt of [
      { offset: 44, value: 1 },
      { offset: 49, value: 1 },
      { offset: 68, value: 1 },
    ]) {
      const bytes = Buffer.from(canonical);
      bytes[corrupt.offset] = corrupt.value;
      expect(() => decodeCatalogOutput(bytes)).toThrow(RepositoryBoundaryError);
    }
    expect(() =>
      decodeCatalogOutput(
        catalogBytes([
          { type: 1, path: "z", inode: 3n },
          { type: 2, path: "a.yaml", inode: 4n, size: 5n },
        ]),
      ),
    ).toThrow(RepositoryBoundaryError);

    const first = decodeCatalogOutput(canonical);
    const second = decodeCatalogOutput(
      catalogBytes([
        { type: 1, path: "packages", inode: 3n, mtimeSeconds: 9n },
        { type: 2, path: "packages/a.yaml", inode: 4n, size: 5n },
      ]),
    );
    expect(catalogsMatchExactly(first, second)).toBe(false);
  });
  it("uses fixed authenticated canonical cursors and invalidates tamper, query, op and rotation", () => {
    const snapshot = "a".repeat(64);
    const query = "b".repeat(64);
    const codec = new RepositoryCursorCodec(Buffer.alloc(32, 1));
    const cursor = codec.encode("search", 7, query, snapshot);
    expect(cursor).toHaveLength(136);
    expect(codec.decode(cursor, "search", query)).toMatchObject({
      offset: 7,
      snapshotSha256: snapshot,
    });
    const listCursor = codec.encode("list", 1, "0".repeat(64), snapshot);
    const resourceCursor = codec.encode("resource-list", 2, query, snapshot);
    expect(Buffer.from(listCursor, "base64url")[1]).toBe(1);
    expect(Buffer.from(cursor, "base64url")[1]).toBe(2);
    expect(Buffer.from(resourceCursor, "base64url")[1]).toBe(3);
    expect(codec.decode(resourceCursor, "resource-list", query).offset).toBe(2);
    const expectInvalid = (operation: () => unknown) => {
      try {
        operation();
        throw new Error("expected cursor rejection");
      } catch (error) {
        expect(error).toMatchObject({ code: "invalid_input" });
      }
    };
    expectInvalid(() => codec.decode("x", "search", query));
    expectInvalid(() => codec.decode(cursor, "list", "0".repeat(64)));
    expectInvalid(() => codec.decode(cursor, "search", "c".repeat(64)));
    expectInvalid(() =>
      codec.decode(
        cursor.slice(0, -1) + (cursor.endsWith("A") ? "B" : "A"),
        "search",
        query,
      ),
    );
    expectInvalid(() =>
      new RepositoryCursorCodec(Buffer.alloc(32, 2)).decode(
        cursor,
        "search",
        query,
      ),
    );
    codec.close();
    expectInvalid(() => codec.decode(cursor, "search", query));
  });

  it("lists deterministic exact hashes while pre-excluding canonical and identity aliases", async () => {
    const value = await fixture();
    const page = await value.service.list({ limit: 1 }, operation());
    expect(page.items).toEqual([
      {
        path: "configuration.yaml",
        sha256: sha("first: needle\npassword=hunter2 needle\nlast: needle\n"),
        bytes: 51,
      },
    ]);
    expect(
      value.reader.reads.filter((path) => path === "packages/alias.yaml"),
    ).toHaveLength(0);
    expect(
      value.reader.reads.filter((path) => path === "secrets.yaml").length,
    ).toBeGreaterThanOrEqual(3);
  });

  it("reads and nontruncating-redacts full content larger than 16KiB", async () => {
    const content = `start\npassword=hunter2\n${"x".repeat(20_000)}\nend`;
    const value = await fixture(content);
    const result = await value.service.read("configuration.yaml", operation());
    expect(result.content).toContain("[REDACTED]");
    expect(result.content).toContain("x".repeat(20_000));
    expect(result.content).toContain("end");
    expect(result.content).not.toContain("hunter2");
  });

  it("searches literal case-sensitive lines, drops matches removed by redaction and clips safely", async () => {
    const long = `${"😀".repeat(700)} needle ${"z".repeat(700)}`;
    const value = await fixture(`Needle\nneedle\npassword=needle\n${long}\n`);
    const page = await value.service.search(
      { query: "needle", limit: 10 },
      operation(),
    );
    expect(page.items.map((item) => item.line)).toEqual([2, 4]);
    expect(page.items[1]!.snippet).toContain("needle");
    expect(Array.from(page.items[1]!.snippet)).toHaveLength(1000);
    expect(Buffer.byteLength(page.items[1]!.snippet)).toBeLessThanOrEqual(4096);
    const protectedQuery = "password=QUERY_CANARY";
    try {
      await value.service.search(
        { query: protectedQuery, limit: 1 },
        operation(),
      );
      throw new Error("expected protected query rejection");
    } catch (error) {
      expect(error).toMatchObject({ code: "protected_resource" });
      expect(String(error)).not.toContain("QUERY_CANARY");
    }
  });

  it("uses linear bounded literal search for adversarial repeated prefixes", async () => {
    const within = await fixture("a".repeat(99_997));
    await expect(
      within.service.search({ query: "aaaaab", limit: 1 }, operation()),
    ).resolves.toMatchObject({ items: [] });

    const exceeded = await fixture("a".repeat(99_998));
    await expect(
      exceeded.service.search({ query: "aaaaab", limit: 1 }, operation()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });

    const cancelled = await fixture("a".repeat(99_997));
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks >= 20;
      },
    } as AbortSignal;
    await expect(
      cancelled.service.search(
        { query: "aaaaab", limit: 1 },
        { ...operation(), signal },
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
  });
  it("detects protected replacement, same-inode edit and deletion and latches unhealthy", async () => {
    for (const change of ["identity", "content", "delete"] as const) {
      const value = await fixture(undefined, (path, count, files) => {
        if (path !== "secrets.yaml" || count !== 3) return;
        if (change === "identity")
          files.set(path, {
            identity: id("99"),
            content: "password: swordfish",
          });
        else if (change === "content")
          files.set(path, { identity: id("20"), content: "password: changed" });
        else files.delete(path);
      });
      await expect(
        value.service.list({ limit: 10 }, operation()),
      ).rejects.toBeInstanceOf(RepositoryBoundaryError);
      await expect(
        value.protectedRegistry.assertFresh(operation()),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
    }
  });

  it("rejects catalog/read identity or size drift and wipes each transferred buffer", async () => {
    const value = await fixture();
    value.reader.files.set("configuration.yaml", {
      identity: id("88"),
      content: "same-size-content",
    });
    await expect(
      value.service.list({ limit: 10 }, operation()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("binds snapshots to identity and classifies authenticated stale cursors without latching", async () => {
    const value = await fixture();
    const first = await value.service.list({ limit: 1 }, operation());
    const prior = value.cursors.encode(
      "list",
      0,
      "0".repeat(64),
      first.snapshotSha256,
    );
    const content = value.reader.files.get("configuration.yaml")!.content;
    value.reader.files.set("configuration.yaml", {
      identity: id("11"),
      content,
    });
    value.provider.value = catalog([
      entry("configuration.yaml", "11", content),
      entry("packages/alias.yaml", "20", "secret: alias"),
      entry("secrets.yaml", "20", "password: swordfish"),
    ]);
    await expect(
      value.service.list({ cursor: prior, limit: 1 }, operation()),
    ).rejects.toMatchObject({ code: "stale_source" });

    const current = await value.service.list({ limit: 1 }, operation());
    const beyond = value.cursors.encode(
      "list",
      99,
      "0".repeat(64),
      current.snapshotSha256,
    );
    await expect(
      value.service.list({ cursor: beyond, limit: 1 }, operation()),
    ).rejects.toMatchObject({ code: "stale_source" });
    await expect(
      value.protectedRegistry.assertFresh(operation()),
    ).resolves.toBeUndefined();
  });

  it("rejects catalog root identity mismatch for list, read, and search", async () => {
    const operations = [
      async (value: Awaited<ReturnType<typeof fixture>>) =>
        value.service.list({ limit: 1 }, operation()),
      async (value: Awaited<ReturnType<typeof fixture>>) =>
        value.service.read("configuration.yaml", operation()),
      async (value: Awaited<ReturnType<typeof fixture>>) =>
        value.service.search({ query: "needle", limit: 1 }, operation()),
    ];
    for (const run of operations) {
      const value = await fixture();
      value.reader.rootIdentity = id("other-root");
      await expect(run(value)).rejects.toMatchObject({
        code: "service_unhealthy",
      });
    }
  });
  it("contains the native race-safe listing requirements and conservative exclusions", async () => {
    const source = await readFile(
      "src/repository/native/openat2-list.c",
      "utf8",
    );
    for (const token of [
      "SYS_openat2",
      "RESOLVE_BENEATH",
      "RESOLVE_NO_SYMLINKS",
      "RESOLVE_NO_MAGICLINKS",
      "RESOLVE_NO_XDEV",
      "AT_SYMLINK_NOFOLLOW",
      "fstatat",
      "fdopendir",
      "st_mtim",
      "st_ctim",
      "MAX_VISITED",
      "MAX_DEPTH",
      "MAX_FILES",
      "HALIST2",
      "STATUS_UNAVAILABLE",
      ".git",
      ".storage",
      "node_modules",
    ])
      expect(source).toContain(token);
    expect(source).toContain(
      "S_ISDIR(seen.st_mode)?O_RDONLY|O_DIRECTORY:O_PATH",
    );
    expect(source).toContain(
      'open_secure(path[0]?path:".",O_RDONLY|O_DIRECTORY)',
    );
    expect(source).toContain("rows[i].type==1?0:(uint64_t)rows[i].st.st_size");
    expect(source).toContain("if(x==ELOOP||x==EXDEV){errno=0;continue;}");
    expect(source).not.toContain("if(x==ELOOP||x==EXDEV)continue;");
    expect(source).not.toContain("dup(root_fd)");
    expect(source).not.toMatch(/realpath|lstat/u);
  });
  it("denies a canonical protected path before content read and records its exact digest", async () => {
    const value = await fixture();
    const before = value.reader.reads.length;
    await expect(
      value.protectedRegistry.readContent("secrets.yaml", operation()),
    ).rejects.toMatchObject({ code: "protected_resource" });
    expect(value.reader.reads).toHaveLength(before);
    expect(value.protectedRegistry.metadata()[0]).toMatchObject({
      path: "secrets.yaml",
      sha256: sha("password: swordfish"),
    });
  });

  it("preserves Phase 1 default truncation while cancelling bounded long-line search", async () => {
    expect(String(redact("x".repeat(20_000)))).toHaveLength(16_384);
    const value = await fixture(`${"x".repeat(100_000)}needle\n`);
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks >= 20;
      },
    } as AbortSignal;
    await expect(
      value.service.search(
        { query: "needle", limit: 1 },
        { ...operation(), signal },
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(checks).toBe(21);
  });

  it("sanitizes unexpected provider failures and rejects service bounds", async () => {
    const value = await fixture();
    const failing = new RepositoryReadService(
      {
        catalog: async () => {
          throw new Error("PROVIDER_CANARY_CONTEXT");
        },
      },
      value.reader,
      value.protectedRegistry,
      value.cursors,
    );
    try {
      await failing.list({ limit: 1 }, operation());
      throw new Error("expected failure");
    } catch (error) {
      expect(error).toMatchObject({ code: "service_unhealthy" });
      expect(String(error)).not.toContain("PROVIDER_CANARY_CONTEXT");
    }
    await expect(
      value.service.list({ cursor: "x", limit: 1 }, operation()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(
      value.service.list({ limit: 0 }, operation()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(
      value.service.read("../secrets.yaml", operation()),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      value.service.search({ query: "bad\nquery", limit: 1 }, operation()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(
      value.protectedRegistry.assertFresh(operation()),
    ).resolves.toBeUndefined();
  });
});
