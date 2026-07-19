import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import type { Phase2OperationContext } from "../src/phase2Contracts.js";
import {
  BoundedPermitPool,
  decodeHelperOutput,
  ExactSecretRedactor,
  NativeOpenat2Reader,
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
  type SecureFileReader,
} from "../src/security/repositoryBoundary.js";

const context = (
  controller = new AbortController(),
  deadlineAt = Date.now() + 10_000,
): Phase2OperationContext => ({
  requestId: randomUUID(),
  operationId: randomUUID(),
  deadlineAt,
  signal: controller.signal,
});

const abortDuringSubscriptionSignal = (): AbortSignal => {
  let aborted = false;
  return {
    get aborted() {
      return aborted;
    },
    reason: undefined,
    onabort: null,
    throwIfAborted: () => undefined,
    addEventListener: () => {
      aborted = true;
    },
    removeEventListener: () => undefined,
    dispatchEvent: () => true,
  } as AbortSignal;
};

const identity = (inode: string): FileIdentity => ({ device: "11", inode });

function expectBoundaryError(
  action: () => unknown,
  code: RepositoryBoundaryError["code"],
): void {
  try {
    action();
    throw new Error("Expected repository boundary error");
  } catch (error) {
    expect(error).toBeInstanceOf(RepositoryBoundaryError);
    if (error instanceof RepositoryBoundaryError) expect(error.code).toBe(code);
  }
}

class FakeReader implements SecureFileReader {
  readonly reads: string[] = [];
  constructor(
    private readonly files: ReadonlyMap<
      string,
      { readonly identity: FileIdentity; readonly content: string }
    >,
  ) {}
  async read(path: string): Promise<SecureFileRead> {
    this.reads.push(path);
    const file = this.files.get(path);
    if (!file)
      throw new RepositoryBoundaryError("path_denied", "Denied fixture");
    return {
      path,
      identity: file.identity,
      rootIdentity: identity("1"),
      bytes: new TextEncoder().encode(file.content),
    };
  }
}

describe("Phase 2 repository security boundary", () => {
  it("fails closed on Windows and while the native helper is not packaged", async () => {
    await expect(
      new NativeOpenat2Reader({ platform: "win32" }).read(
        "configuration.yaml",
        context(),
      ),
    ).rejects.toMatchObject({ code: "capability_unavailable" });
    await expect(
      new NativeOpenat2Reader({ platform: "linux" }).read(
        "configuration.yaml",
        context(),
      ),
    ).rejects.toMatchObject({ code: "capability_unavailable" });
  });

  it("validates the bounded native protocol and strict UTF-8", () => {
    const content = Buffer.from("hello\n");
    const output = Buffer.alloc(64 + content.length);
    output.write("HAREAD2\0", 0, "ascii");
    output.writeUInt32BE(1, 8);
    output.writeBigUInt64BE(11n, 24);
    output.writeBigUInt64BE(1n, 32);
    output.writeBigUInt64BE(11n, 40);
    output.writeBigUInt64BE(2n, 48);
    output.writeBigUInt64BE(BigInt(content.length), 56);
    content.copy(output, 64);
    expect(decodeHelperOutput(output, "configuration.yaml", 100)).toMatchObject(
      {
        identity: { device: "11", inode: "2" },
        rootIdentity: { device: "11", inode: "1" },
      },
    );
    expect(() =>
      decodeHelperOutput(output.subarray(0, -1), "configuration.yaml", 100),
    ).toThrow(RepositoryBoundaryError);
    const invalid = Buffer.from(output);
    invalid[64] = 0xff;
    expectBoundaryError(
      () => decodeHelperOutput(invalid, "configuration.yaml", 100),
      "unsupported_encoding",
    );
  });

  it("keeps protected source content unavailable through hard-link identity aliases", async () => {
    const protectedIdentity = identity("22");
    const reader = new FakeReader(
      new Map([
        [
          "secrets.yaml",
          { identity: protectedIdentity, content: "password: swordfish" },
        ],
        [
          "packages/alias.yaml",
          { identity: protectedIdentity, content: "password: swordfish" },
        ],
        [
          "configuration.yaml",
          { identity: identity("23"), content: "homeassistant: {}" },
        ],
      ]),
    );
    const registry = new ProtectedIdentityRegistry(reader);
    await expect(
      registry.readContent("configuration.yaml", context()),
    ).rejects.toMatchObject({
      code: "capability_unavailable",
    });
    await registry.initialize(
      ["secrets.yaml"],
      { loadExactValues: async () => ["swordfish"] },
      context(),
    );
    await expect(
      registry.readContent("packages/alias.yaml", context()),
    ).rejects.toMatchObject({
      code: "protected_resource",
    });
    expect(
      new TextDecoder().decode(
        (await registry.readContent("configuration.yaml", context())).bytes,
      ),
    ).toBe("homeassistant: {}");
  });

  it("redacts exact values and heuristic shapes from all response-like string leaves and keys", async () => {
    const reader = new FakeReader(
      new Map([
        ["secrets.yaml", { identity: identity("30"), content: "internal" }],
      ]),
    );
    const registry = new ProtectedIdentityRegistry(reader);
    await registry.initialize(
      ["secrets.yaml"],
      { loadExactValues: async () => ["exact-canary", "git-canary"] },
      context(),
    );
    const value = {
      "exact-canary": "response exact-canary",
      error: new Error("exact-canary").message,
      snippets: ["line exact-canary"],
      diff: "- git-canary\n+ password=hunter2",
      diagnostics: { output: "Bearer token-canary" },
      git: "commit git-canary",
      nested: {
        PaSsWoRd: "patternless-password-canary",
        API_KEY: { deeplyNested: "patternless-key-canary" },
      },
    };
    const serialized = JSON.stringify(registry.redact(value, context()));
    for (const canary of [
      "exact-canary",
      "git-canary",
      "hunter2",
      "token-canary",
      "patternless-password-canary",
      "patternless-key-canary",
    ])
      expect(serialized).not.toContain(canary);
  });

  it("bounds redaction and propagates cancellation/deadline", () => {
    const controller = new AbortController();
    controller.abort();
    const redactor = new ExactSecretRedactor(["canary"]);
    expectBoundaryError(
      () => redactor.redact("canary", context(controller)),
      "operation_cancelled",
    );
    expectBoundaryError(
      () => redactor.redact("canary", context(undefined, Date.now() - 1)),
      "deadline_exceeded",
    );
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expectBoundaryError(
      () => redactor.redact(cyclic, context()),
      "service_unhealthy",
    );
    expectBoundaryError(
      () => redactor.redact("x".repeat(512 * 1_024 + 1), context()),
      "service_unhealthy",
    );
    expectBoundaryError(
      () =>
        redactor.redact(
          Array.from({ length: 65 }, () => "x".repeat(16_384)),
          context(),
        ),
      "service_unhealthy",
    );
    const expansionRedactor = new ExactSecretRedactor([
      "[",
      "R",
      "E",
      "D",
      "A",
      "C",
      "T",
      "]",
    ]);
    expectBoundaryError(
      () => expansionRedactor.redact("[".repeat(512 * 1_024), context()),
      "service_unhealthy",
    );
  });

  it("latches unhealthy after protected identity registration failure", async () => {
    const registry = new ProtectedIdentityRegistry(new FakeReader(new Map()));
    await expect(
      registry.initialize(
        ["secrets.yaml"],
        { loadExactValues: async () => ["never"] },
        context(),
      ),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expect(
      registry.initialize(
        ["secrets.yaml"],
        { loadExactValues: async () => ["never"] },
        context(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("hands permits past cancelled and timed-out waiters without exceeding queue bounds", async () => {
    const pool = new BoundedPermitPool(1, 1);
    const releaseFirst = await pool.acquire(context());
    const cancelledController = new AbortController();
    const cancelled = pool.acquire(context(cancelledController));
    cancelledController.abort();
    await expect(cancelled).rejects.toMatchObject({
      code: "operation_cancelled",
    });

    const waitingController = new AbortController();
    const waiting = pool.acquire(context(waitingController));
    await expect(pool.acquire(context())).rejects.toMatchObject({
      code: "service_unhealthy",
    });
    releaseFirst();
    const releaseSecond = await waiting;
    releaseSecond();

    const releaseThird = await pool.acquire(context());
    const timedOut = pool.acquire(context(undefined, Date.now() + 5));
    await expect(timedOut).rejects.toMatchObject({ code: "deadline_exceeded" });
    releaseThird();
    const releaseAfterTimeout = await pool.acquire(context());
    releaseAfterTimeout();
  });

  it("closes abort races while subscribing permit and helper listeners", async () => {
    const pool = new BoundedPermitPool(1);
    const release = await pool.acquire(context());
    await expect(
      pool.acquire({ ...context(), signal: abortDuringSubscriptionSignal() }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    release();

    const reader = new NativeOpenat2Reader({
      platform: "linux",
      helperPath: process.execPath,
      root: process.cwd(),
    });
    await expect(
      reader.read("configuration.yaml", {
        ...context(),
        signal: abortDuringSubscriptionSignal(),
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
  });

  it("rejects malformed, oversized, and NUL-bearing helper output", () => {
    const output = Buffer.alloc(65);
    output.write("HAREAD2\0", 0, "ascii");
    output.writeUInt32BE(1, 8);
    output.writeBigUInt64BE(11n, 24);
    output.writeBigUInt64BE(1n, 32);
    output.writeBigUInt64BE(11n, 40);
    output.writeBigUInt64BE(2n, 48);
    output.writeBigUInt64BE(1n, 56);
    output[64] = 0;
    expectBoundaryError(
      () => decodeHelperOutput(output, "configuration.yaml", 1),
      "unsupported_encoding",
    );
    output.writeBigUInt64BE(2n, 56);
    expectBoundaryError(
      () => decodeHelperOutput(output, "configuration.yaml", 1),
      "service_unhealthy",
    );
    output.writeUInt32BE(99, 8);
    expectBoundaryError(
      () => decodeHelperOutput(output, "configuration.yaml", 1),
      "service_unhealthy",
    );
    output.writeUInt32BE(1, 8);
    output.writeUInt32BE(4, 12);
    expectBoundaryError(
      () => decodeHelperOutput(output.subarray(0, 64), "configuration.yaml", 1),
      "capability_unavailable",
    );
  });

  it("bounds protected source registration and rejects duplicate identities", async () => {
    const duplicatePathRegistry = new ProtectedIdentityRegistry(
      new FakeReader(
        new Map([
          ["secrets.yaml", { identity: identity("40"), content: "secret" }],
        ]),
      ),
    );
    await expect(
      duplicatePathRegistry.initialize(
        ["secrets.yaml", "secrets.yaml"],
        { loadExactValues: async () => ["secret"] },
        context(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });

    const duplicateIdentity = identity("41");
    const aliasRegistry = new ProtectedIdentityRegistry(
      new FakeReader(
        new Map([
          ["secrets.yaml", { identity: duplicateIdentity, content: "one" }],
          ["alias.yaml", { identity: duplicateIdentity, content: "one" }],
        ]),
      ),
    );
    await expect(
      aliasRegistry.initialize(
        ["secrets.yaml", "alias.yaml"],
        { loadExactValues: async () => ["one"] },
        context(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
    const tooMany = Array.from({ length: 65 }, (_, index) =>
      index === 0 ? "secrets.yaml" : "protected-" + index + ".yaml",
    );
    await expect(
      new ProtectedIdentityRegistry(new FakeReader(new Map())).initialize(
        tooMany,
        { loadExactValues: async () => [] },
        context(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("zeroes secure bytes when cancellation prevents ownership transfer", async () => {
    let abortPath: string | undefined;
    let activeController: AbortController | undefined;
    let captured: Uint8Array | undefined;
    const reader: SecureFileReader = {
      read: async (path) => {
        captured = new TextEncoder().encode("content:" + path);
        if (path === abortPath) activeController?.abort();
        return {
          path,
          identity: identity(path === "secrets.yaml" ? "50" : "51"),
          rootIdentity: identity("1"),
          bytes: captured,
        };
      },
    };
    const registry = new ProtectedIdentityRegistry(reader);
    await registry.initialize(
      ["secrets.yaml"],
      { loadExactValues: async () => ["secret-value"] },
      context(),
    );

    activeController = new AbortController();
    abortPath = "configuration.yaml";
    await expect(
      registry.readContent("configuration.yaml", context(activeController)),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect([...captured!].every((byte) => byte === 0)).toBe(true);

    activeController = new AbortController();
    abortPath = "alias.yaml";
    await expect(
      registry.registerMetadataPath("alias.yaml", context(activeController)),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect([...captured!].every((byte) => byte === 0)).toBe(true);
  });
  it("defines an openat2-only helper with beneath, no-link and no-mount resolution", async () => {
    const source = await readFile("src/security/native/openat2-read.c", "utf8");
    for (const flag of [
      "RESOLVE_BENEATH",
      "RESOLVE_NO_SYMLINKS",
      "RESOLVE_NO_MAGICLINKS",
      "RESOLVE_NO_XDEV",
    ])
      expect(source).toContain(flag);
    expect(source).toContain("SYS_openat2");
    expect(source).toContain("valid_relative_path");
    expect(source).toContain("(value != 0 && value <= 0x1f)");
    expect(source).toContain("if (value == '/' || value == 0)");
    expect(source).toContain("length == 0");
    expect(source).toContain("segment[0] == '.'");
    expect(source).toContain("segment[1] == '.'");
    expect(source).toContain("st_mtim");
    expect(source).toContain("st_ctim");
    expect(source).toContain("STATUS_UNAVAILABLE");
    expect(source).toContain("volatile unsigned char");
    expect(source).toContain("wipe_free(content, size)");
    expect(source).toContain("secure_wipe(&extra, sizeof(extra))");
    expect(source).not.toMatch(/realpath|lstat/u);

    const typescriptSource = await readFile(
      "src/security/repositoryBoundary.ts",
      "utf8",
    );
    expect(typescriptSource).toContain("combined?.fill(0)");
    expect(typescriptSource).toContain(
      "for (const chunk of stdout) chunk.fill(0)",
    );
    expect(typescriptSource).toContain("buffer.fill(0)");
  });
});
