import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../src/phase2Contracts.js";
import {
  ProtectedPhase3SourceAdapter,
  type Phase3SourceBoundary,
} from "../src/phase3/sourceAdapter.js";
import type {
  Phase3OperationContext,
  Phase3SourcePort,
} from "../src/phase3/applyCoordinator.js";
import type { Phase3PostEffectSourceDigestPort } from "../src/phase3/verificationAdapter.js";
import type { RepositoryCatalogProvider } from "../src/repository/repositoryReads.js";
import {
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
} from "../src/security/repositoryBoundary.js";

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const rootIdentity = identity("root");
const fileIdentity = identity("file");
const protectedIdentity = identity("protected");
const defaultPath = "automations/source.yaml";
const rawSecret = "TOP-SECRET-BYTES";

describe("Phase 3E protected source adapter", () => {
  it("reads bytes and digests successfully without parsing text", async () => {
    const bytes = Uint8Array.from([0xff, 0x00, 0x61]);
    const { adapter, boundary, catalog } = fixture({ bytes });

    const result = await adapter.read(defaultPath, phase3Context());
    expect(result).toEqual({ bytes, sha256: digest(bytes) });
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(boundary.events).toEqual([
      "fresh",
      "catalog",
      "protected",
      "read",
      "fresh",
    ]);
    expect(catalog.calls).toHaveLength(1);
    expect(boundary.reads).toBe(1);
    expect(boundary.readBuffers.every(isZeroed)).toBe(true);

    await expect(adapter.readDigest(defaultPath)).resolves.toBe(digest(bytes));
    expect(boundary.reads).toBe(2);
  });

  it.each([
    ["empty", 0, true],
    ["limit", PHASE2_MAX_TEXT_BYTES, true],
    ["limit plus one", PHASE2_MAX_TEXT_BYTES + 1, false],
  ] as const)(
    "handles %s byte source content",
    async (_case, size, allowed) => {
      const bytes = new Uint8Array(size);
      bytes.fill(0x61);
      for (const method of ["read", "readDigest"] as const) {
        const { adapter, boundary } = fixture({ bytes });
        const operation = invoke(adapter, method);
        if (allowed) {
          if (method === "read")
            await expect(operation).resolves.toMatchObject({
              sha256: digest(bytes),
            });
          else await expect(operation).resolves.toBe(digest(bytes));
        } else {
          await expect(operation).rejects.toMatchObject({
            code: "service_unhealthy",
          });
        }
        expect(boundary.readBuffers.every(isZeroed)).toBe(true);
      }
    },
  );

  it("rejects invalid Phase 3 paths before freshness, catalog, or read effects", async () => {
    const { adapter, boundary, catalog } = fixture();
    await expect(
      adapter.read("../secrets.yaml", phase3Context()),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(adapter.readDigest("bad\\path.yaml")).rejects.toMatchObject({
      code: "invalid_input",
    });
    expect(boundary.events).toEqual([]);
    expect(catalog.calls).toEqual([]);
  });

  it("classifies catalog absence as read missing and digest null without content reads", async () => {
    const { adapter, boundary } = fixture({ catalogAbsent: true });
    await expect(
      adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "resource_not_found" });
    await expect(adapter.readDigest(defaultPath)).resolves.toBeNull();
    expect(boundary.reads).toBe(0);
    expect(boundary.events).toEqual(["fresh", "catalog", "fresh", "catalog"]);
  });

  it("denies preknown protected paths and inodes before content reads", async () => {
    const byPath = fixture({ protectedPaths: [defaultPath] });
    await expect(
      byPath.adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "protected_resource" });
    expect(byPath.boundary.reads).toBe(0);

    const byIdentity = fixture({
      entryIdentity: protectedIdentity,
      readIdentity: protectedIdentity,
      protectedIdentities: [protectedIdentity],
    });
    await expect(
      byIdentity.adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "protected_resource" });
    expect(byIdentity.boundary.reads).toBe(0);
  });

  it.each(["resource_not_found", "protected_resource"] as const)(
    "translates unexpected accepted-read %s races to unhealthy",
    async (code) => {
      for (const method of ["read", "readDigest"] as const) {
        const { adapter, boundary } = fixture({
          readError: new RepositoryBoundaryError(
            code,
            `${defaultPath} ${rawSecret}`,
          ),
        });
        await expectRejectedSafely(
          invoke(adapter, method),
          "service_unhealthy",
        );
        expect(boundary.reads).toBe(1);
      }
    },
  );

  it.each([
    ["root identity", { readRootIdentity: identity("other-root") }],
    ["file identity", { readIdentity: identity("other-file") }],
    ["size", { catalogSize: 4 }],
  ] as const)(
    "fails closed on %s drift after catalog",
    async (_case, options) => {
      for (const method of ["read", "readDigest"] as const) {
        const { adapter, boundary } = fixture({
          bytes: Buffer.from("abc"),
          ...options,
        });
        await expect(invoke(adapter, method)).rejects.toMatchObject({
          code: "service_unhealthy",
        });
        expect(boundary.readBuffers.every(isZeroed)).toBe(true);
      }
    },
  );

  it.each([
    [
      "unready",
      new RepositoryBoundaryError(
        "capability_unavailable",
        `${defaultPath} ${rawSecret}`,
      ),
    ],
    [
      "unhealthy",
      new RepositoryBoundaryError(
        "service_unhealthy",
        `${defaultPath} ${rawSecret}`,
      ),
    ],
  ] as const)(
    "preserves registry %s boundary codes with safe messages",
    async (_case, error) => {
      const { adapter } = fixture({ freshErrors: [error] });
      await expectRejectedSafely(
        adapter.read(defaultPath, phase3Context()),
        error.code,
      );
    },
  );

  it("reports freshness drift after read and still zeros boundary bytes", async () => {
    const { adapter, boundary } = fixture({
      freshErrors: [
        undefined,
        new RepositoryBoundaryError(
          "service_unhealthy",
          `${defaultPath} ${rawSecret}`,
        ),
      ],
    });
    await expect(
      adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
    expect(boundary.readBuffers.every(isZeroed)).toBe(true);
  });

  it("carries caller cancellation and deadlines through the single read context", async () => {
    const cancelled = new AbortController();
    cancelled.abort();
    const cancelledFixture = fixture({ checkActive: true });
    await expect(
      cancelledFixture.adapter.read(defaultPath, {
        signal: cancelled.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(cancelledFixture.boundary.contexts[0]?.signal).toBe(
      cancelled.signal,
    );

    const deadlineFixture = fixture({ checkActive: true });
    const expiredDeadline = Date.now() - 1;
    await expect(
      deadlineFixture.adapter.read(defaultPath, {
        signal: new AbortController().signal,
        deadlineAt: expiredDeadline,
      }),
    ).rejects.toMatchObject({ code: "deadline_exceeded" });
    expect(deadlineFixture.boundary.contexts[0]?.deadlineAt).toBe(
      expiredDeadline,
    );
  });

  it("fails after-read cancellation before returning caller bytes", async () => {
    const controller = new AbortController();
    const { adapter, boundary } = fixture({
      checkActive: true,
      afterRead: () => controller.abort(),
    });
    await expect(
      adapter.read(defaultPath, {
        signal: controller.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(boundary.readBuffers.every(isZeroed)).toBe(true);
  });

  it("fails after-read deadline expiry before returning caller bytes", async () => {
    vi.useFakeTimers();
    try {
      const now = new Date("2026-07-21T12:00:00.000Z");
      vi.setSystemTime(now);
      const { adapter, boundary } = fixture({
        checkActive: true,
        afterRead: () => vi.setSystemTime(now.getTime() + 60_001),
      });
      await expect(
        adapter.read(defaultPath, {
          signal: new AbortController().signal,
          deadlineAt: now.getTime() + 60_000,
        }),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
      expect(boundary.readBuffers.every(isZeroed)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("sanitizes preserved boundary errors and unknown exceptions", async () => {
    const boundaryFailure = fixture({
      readError: new RepositoryBoundaryError(
        "path_denied",
        `${defaultPath} ${rawSecret}`,
      ),
    });
    await expect(
      boundaryFailure.adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "path_denied" });
    await expectNoDisclosure(
      boundaryFailure.adapter.read(defaultPath, phase3Context()),
    );

    const unknownFailure = fixture({
      catalogError: new Error(`${defaultPath} ${rawSecret}`),
    });
    await expect(
      unknownFailure.adapter.read(defaultPath, phase3Context()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
    await expectNoDisclosure(
      unknownFailure.adapter.read(defaultPath, phase3Context()),
    );
  });

  it("returns caller-owned copies and repeated reads are independent", async () => {
    const bytes = Buffer.from("stable source");
    const { adapter, boundary } = fixture({ bytes });
    const first = await adapter.read(defaultPath, phase3Context());
    const second = await adapter.read(defaultPath, phase3Context());
    expect(first.bytes).not.toBe(second.bytes);
    first.bytes.fill(0);
    expect(Array.from(second.bytes)).toEqual(Array.from(bytes));
    const third = await adapter.read(defaultPath, phase3Context());
    expect(Array.from(third.bytes)).toEqual(Array.from(bytes));
    expect(boundary.readBuffers).toHaveLength(3);
    expect(boundary.readBuffers.every(isZeroed)).toBe(true);
  });

  it("derives one Phase 2 context with fresh IDs and exact caller signal/deadline per read", async () => {
    const controller = new AbortController();
    const deadlineAt = Date.now() + 123_456;
    const { adapter, boundary, catalog } = fixture();
    await adapter.read(defaultPath, {
      signal: controller.signal,
      deadlineAt,
    });
    const contexts = [
      boundary.contexts[0],
      catalog.calls[0],
      boundary.readContexts[0],
      boundary.contexts[1],
    ];
    expect(new Set(contexts).size).toBe(1);
    const context = contexts[0]!;
    expect(context.signal).toBe(controller.signal);
    expect(context.deadlineAt).toBe(deadlineAt);
    expect(context.requestId).toMatch(uuidPattern);
    expect(context.operationId).toMatch(uuidPattern);

    await adapter.read(defaultPath, phase3Context());
    expect(boundary.contexts[2]?.requestId).toMatch(uuidPattern);
    expect(boundary.contexts[2]?.requestId).not.toBe(context.requestId);
    expect(boundary.contexts[2]?.operationId).not.toBe(context.operationId);
  });

  it("uses an internal non-aborted 60s context for readDigest", async () => {
    const before = Date.now();
    const { adapter, boundary, catalog } = fixture();
    await expect(adapter.readDigest(defaultPath)).resolves.toBe(
      digest("value\n"),
    );
    const after = Date.now();
    const contexts = [
      boundary.contexts[0],
      catalog.calls[0],
      boundary.readContexts[0],
      boundary.contexts[1],
    ];
    expect(new Set(contexts).size).toBe(1);
    const context = contexts[0]!;
    expect(context.requestId).toMatch(uuidPattern);
    expect(context.operationId).toMatch(uuidPattern);
    expect(context.signal.aborted).toBe(false);
    expect(context.deadlineAt).toBeGreaterThanOrEqual(before + 60_000);
    expect(context.deadlineAt).toBeLessThanOrEqual(after + 60_000);
  });
});

describe("Phase 3K contextual protected source digest bridge", () => {
  it("executes both interface forms with one frozen exact fresh context per contextual call", async () => {
    const bytes = Uint8Array.from([0xff, 0x00, 0x61]);
    const legacyFixture = fixture({ bytes });
    const sourcePort: Phase3SourcePort = legacyFixture.adapter;
    await expect(sourcePort.readDigest(defaultPath)).resolves.toBe(
      digest(bytes),
    );

    const { adapter, boundary, catalog } = fixture({ bytes });
    const postEffectPort: Phase3PostEffectSourceDigestPort = adapter;
    const controller = new AbortController();
    const deadlineAt = Date.now() + 123_456;
    let signalReads = 0;
    let deadlineReads = 0;
    const supplied = {
      get signal(): AbortSignal {
        signalReads += 1;
        return controller.signal;
      },
      get deadlineAt(): number {
        deadlineReads += 1;
        return deadlineAt;
      },
    } as Phase3OperationContext;
    const firstDigest = await postEffectPort.readDigest(defaultPath, supplied);
    expect(firstDigest).toBe(digest(bytes));
    expect(firstDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(typeof firstDigest).toBe("string");
    expect(signalReads).toBe(1);
    expect(deadlineReads).toBe(1);

    const contexts = [
      boundary.contexts[0],
      catalog.calls[0],
      boundary.readContexts[0],
      boundary.contexts[1],
    ];
    expect(new Set(contexts).size).toBe(1);
    const first = contexts[0]!;
    expect(first).not.toBe(supplied);
    expect(Object.isFrozen(first)).toBe(true);
    expect(first.signal).toBe(controller.signal);
    expect(first.deadlineAt).toBe(deadlineAt);
    expect(first.requestId).toMatch(uuidPattern);
    expect(first.operationId).toMatch(uuidPattern);
    expect(first.requestId).not.toBe(first.operationId);

    await expect(
      postEffectPort.readDigest(defaultPath, phase3Context()),
    ).resolves.toBe(digest(bytes));
    const second = boundary.contexts[2]!;
    expect(Object.isFrozen(second)).toBe(true);
    expect(second.requestId).toMatch(uuidPattern);
    expect(second.operationId).toMatch(uuidPattern);
    expect(
      new Set([
        first.requestId,
        first.operationId,
        second.requestId,
        second.operationId,
      ]).size,
    ).toBe(4);
    expect(boundary.reads).toBe(2);
    expect(boundary.readBuffers.every(isZeroed)).toBe(true);
  });

  it("validates paths before hostile context access and classifies absence and protection before reads", async () => {
    let gets = 0;
    const hostile = {
      get signal(): AbortSignal {
        gets += 1;
        throw new Error(rawSecret);
      },
      get deadlineAt(): number {
        gets += 1;
        throw new Error(rawSecret);
      },
    };
    const invalid = fixture();
    await expectSanitizedFailure(
      contextualDigest(invalid.adapter, hostile, "../secrets.yaml"),
      "invalid_input",
      [rawSecret, "../secrets.yaml"],
    );
    expect(gets).toBe(0);
    expect(invalid.boundary.events).toEqual([]);
    expect(invalid.catalog.calls).toEqual([]);

    const absent = fixture({ catalogAbsent: true });
    await expect(
      absent.adapter.readDigest(defaultPath, phase3Context()),
    ).resolves.toBeNull();
    expect(absent.boundary.events).toEqual(["fresh", "catalog"]);
    expect(absent.boundary.reads).toBe(0);

    for (const options of [
      { protectedPaths: [defaultPath] },
      {
        entryIdentity: protectedIdentity,
        readIdentity: protectedIdentity,
        protectedIdentities: [protectedIdentity],
      },
    ]) {
      const denied = fixture(options);
      await expect(
        denied.adapter.readDigest(defaultPath, phase3Context()),
      ).rejects.toMatchObject({ code: "protected_resource" });
      expect(denied.boundary.reads).toBe(0);
    }
  });

  it.each([
    ["empty", 0, true],
    ["limit", PHASE2_MAX_TEXT_BYTES, true],
    ["limit plus one", PHASE2_MAX_TEXT_BYTES + 1, false],
  ] as const)(
    "handles contextual digest %s bytes with exact bounds and zeroization",
    async (_case, size, allowed) => {
      const bytes = new Uint8Array(size);
      bytes.fill(0x61);
      const { adapter, boundary } = fixture({ bytes });
      const operation = adapter.readDigest(defaultPath, phase3Context());
      if (allowed) await expect(operation).resolves.toBe(digest(bytes));
      else
        await expect(operation).rejects.toMatchObject({
          code: "service_unhealthy",
        });
      expect(boundary.readBuffers).toHaveLength(1);
      expect(boundary.readBuffers.every(isZeroed)).toBe(true);
    },
  );

  it.each(["resource_not_found", "protected_resource"] as const)(
    "maps contextual accepted-read %s races to unhealthy without retry",
    async (code) => {
      const { adapter, boundary } = fixture({
        readError: new RepositoryBoundaryError(
          code,
          defaultPath + " " + rawSecret,
        ),
      });
      await expectSanitizedFailure(
        adapter.readDigest(defaultPath, phase3Context()),
        "service_unhealthy",
        [defaultPath, rawSecret],
      );
      expect(boundary.reads).toBe(1);
      expect(boundary.readBuffers).toEqual([]);
    },
  );

  it.each([
    ["root", { readRootIdentity: identity("other-root") }],
    ["file", { readIdentity: identity("other-file") }],
    ["size", { catalogSize: 4 }],
  ] as const)(
    "fails contextual digest closed on %s drift and zeros bytes",
    async (_case, options) => {
      const { adapter, boundary } = fixture({
        bytes: Buffer.from("abc"),
        ...options,
      });
      await expect(
        adapter.readDigest(defaultPath, phase3Context()),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
      expect(boundary.readBuffers).toHaveLength(1);
      expect(boundary.readBuffers.every(isZeroed)).toBe(true);
    },
  );

  it("sanitizes first, final, known, and unknown contextual failures", async () => {
    const cases = [
      {
        options: {
          freshErrors: [
            new RepositoryBoundaryError(
              "capability_unavailable",
              defaultPath + " " + rawSecret,
            ),
          ],
        },
        code: "capability_unavailable" as const,
      },
      {
        options: {
          readError: new RepositoryBoundaryError(
            "path_denied",
            defaultPath + " " + rawSecret,
          ),
        },
        code: "path_denied" as const,
      },
      {
        options: {
          catalogError: new Error(defaultPath + " " + rawSecret),
        },
        code: "service_unhealthy" as const,
      },
    ];
    for (const item of cases) {
      const current = fixture(item.options);
      await expectSanitizedFailure(
        current.adapter.readDigest(defaultPath, phase3Context()),
        item.code,
        [defaultPath, rawSecret],
      );
    }

    const final = fixture({
      freshErrors: [
        undefined,
        new RepositoryBoundaryError(
          "path_denied",
          defaultPath + " " + rawSecret,
        ),
      ],
    });
    await expectSanitizedFailure(
      final.adapter.readDigest(defaultPath, phase3Context()),
      "path_denied",
      [defaultPath, rawSecret],
    );
    expect(final.boundary.readBuffers).toHaveLength(1);
    expect(final.boundary.readBuffers.every(isZeroed)).toBe(true);
  });

  it("honors cancellation and deadlines before and during contextual reads", async () => {
    const cancelled = new AbortController();
    cancelled.abort();
    const preCancelled = fixture({ checkActive: true });
    await expect(
      preCancelled.adapter.readDigest(defaultPath, {
        signal: cancelled.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(preCancelled.boundary.reads).toBe(0);

    const duringController = new AbortController();
    const duringCancelled = fixture({
      checkActive: true,
      afterRead: () => duringController.abort(),
    });
    await expect(
      duringCancelled.adapter.readDigest(defaultPath, {
        signal: duringController.signal,
        deadlineAt: Date.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(duringCancelled.boundary.readBuffers.every(isZeroed)).toBe(true);

    vi.useFakeTimers();
    try {
      const now = new Date("2026-07-22T12:00:00.000Z");
      vi.setSystemTime(now);
      const preDeadline = fixture({ checkActive: true });
      await expect(
        preDeadline.adapter.readDigest(defaultPath, {
          signal: new AbortController().signal,
          deadlineAt: now.getTime() - 1,
        }),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
      expect(preDeadline.boundary.reads).toBe(0);

      const duringDeadline = fixture({
        checkActive: true,
        afterRead: () => vi.setSystemTime(now.getTime() + 60_001),
      });
      await expect(
        duringDeadline.adapter.readDigest(defaultPath, {
          signal: new AbortController().signal,
          deadlineAt: now.getTime() + 60_000,
        }),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
      expect(duringDeadline.boundary.readBuffers.every(isZeroed)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["null", null],
    ["number", 0],
    ["string", "context"],
    ["boolean", false],
    ["array", []],
    ["plain signal", { signal: { aborted: false }, deadlineAt: 1 }],
    [
      "NaN deadline",
      { signal: new AbortController().signal, deadlineAt: Number.NaN },
    ],
    [
      "infinite deadline",
      {
        signal: new AbortController().signal,
        deadlineAt: Number.POSITIVE_INFINITY,
      },
    ],
    [
      "string deadline",
      { signal: new AbortController().signal, deadlineAt: "1" },
    ],
  ])(
    "rejects runtime-hostile %s context without fallback or effects",
    async (_case, value) => {
      const { adapter, boundary, catalog } = fixture();
      await expectSanitizedFailure(
        contextualDigest(adapter, value),
        "service_unhealthy",
        [defaultPath, rawSecret],
      );
      expect(boundary.events).toEqual([]);
      expect(catalog.calls).toEqual([]);
      expect(boundary.reads).toBe(0);
    },
  );

  it("rejects a shadowed brand-compatible forgery and descriptor-trapping proxy before effects", async () => {
    const realSignal = new AbortController().signal;
    const forgedSignal = Object.create(
      AbortSignal.prototype,
      Object.getOwnPropertyDescriptors(realSignal),
    ) as AbortSignal;
    expect(Reflect.get(AbortSignal.prototype, "aborted", forgedSignal)).toBe(
      false,
    );

    const shadowCanary = "SHADOW-ABORTED-GETTER-CANARY";
    let shadowReads = 0;
    Object.defineProperty(forgedSignal, "aborted", {
      configurable: true,
      enumerable: true,
      get(): boolean {
        shadowReads += 1;
        throw new Error(shadowCanary);
      },
    });
    const shadowFixture = fixture();
    await expectSanitizedFailure(
      contextualDigest(shadowFixture.adapter, {
        signal: forgedSignal,
        deadlineAt: Date.now() + 60_000,
      }),
      "service_unhealthy",
      [defaultPath, rawSecret, shadowCanary],
    );
    expect(shadowReads).toBe(0);
    expect(shadowFixture.boundary.events).toEqual([]);
    expect(shadowFixture.catalog.calls).toEqual([]);
    expect(shadowFixture.boundary.reads).toBe(0);

    const descriptorCanary = "SIGNAL-DESCRIPTOR-TRAP-CANARY";
    const descriptorProperties: PropertyKey[] = [];
    const descriptorProxy = new Proxy(realSignal, {
      getOwnPropertyDescriptor(_target, property): never {
        descriptorProperties.push(property);
        throw new Error(descriptorCanary);
      },
    });
    const proxyFixture = fixture();
    await expectSanitizedFailure(
      contextualDigest(proxyFixture.adapter, {
        signal: descriptorProxy,
        deadlineAt: Date.now() + 60_000,
      }),
      "service_unhealthy",
      [defaultPath, rawSecret, descriptorCanary],
    );
    expect(descriptorProperties).toEqual(["aborted"]);
    expect(proxyFixture.boundary.events).toEqual([]);
    expect(proxyFixture.catalog.calls).toEqual([]);
    expect(proxyFixture.boundary.reads).toBe(0);
  });

  it("sanitizes throwing getters and proxy traps with at-most-once reads", async () => {
    let signalReads = 0;
    let deadlineReads = 0;
    const signalCanary = "SIGNAL-GETTER-CANARY";
    const signalFixture = fixture();
    await expectSanitizedFailure(
      contextualDigest(signalFixture.adapter, {
        get signal(): AbortSignal {
          signalReads += 1;
          throw new Error(signalCanary);
        },
        get deadlineAt(): number {
          deadlineReads += 1;
          return Date.now() + 60_000;
        },
      }),
      "service_unhealthy",
      [defaultPath, signalCanary],
    );
    expect(signalReads).toBe(1);
    expect(deadlineReads).toBe(0);
    expect(signalFixture.boundary.events).toEqual([]);

    signalReads = 0;
    deadlineReads = 0;
    const deadlineCanary = "DEADLINE-GETTER-CANARY";
    const deadlineFixture = fixture();
    await expectSanitizedFailure(
      contextualDigest(deadlineFixture.adapter, {
        get signal(): AbortSignal {
          signalReads += 1;
          return new AbortController().signal;
        },
        get deadlineAt(): number {
          deadlineReads += 1;
          throw new Error(deadlineCanary);
        },
      }),
      "service_unhealthy",
      [defaultPath, deadlineCanary],
    );
    expect(signalReads).toBe(1);
    expect(deadlineReads).toBe(1);
    expect(deadlineFixture.boundary.events).toEqual([]);

    const proxyCanary = "PROXY-GET-CANARY";
    const properties: PropertyKey[] = [];
    const proxyFixture = fixture();
    const hostile = new Proxy(
      {},
      {
        get(_target, property): never {
          properties.push(property);
          throw new Error(proxyCanary);
        },
      },
    );
    await expectSanitizedFailure(
      contextualDigest(proxyFixture.adapter, hostile),
      "service_unhealthy",
      [defaultPath, proxyCanary],
    );
    expect(properties).toEqual(["signal"]);
    expect(proxyFixture.boundary.events).toEqual([]);
    expect(proxyFixture.catalog.calls).toEqual([]);
  });
});

function fixture(
  options: Readonly<{
    bytes?: Uint8Array;
    catalogAbsent?: boolean;
    catalogSize?: number;
    catalogError?: unknown;
    entryIdentity?: FileIdentity;
    readIdentity?: FileIdentity;
    readRootIdentity?: FileIdentity;
    readError?: unknown;
    protectedPaths?: readonly string[];
    protectedIdentities?: readonly FileIdentity[];
    freshErrors?: readonly (RepositoryBoundaryError | undefined)[];
    checkActive?: boolean;
    afterRead?: () => void;
  }> = {},
): {
  readonly adapter: ProtectedPhase3SourceAdapter;
  readonly boundary: FakeBoundary;
  readonly catalog: FakeCatalog;
} {
  const bytes = options.bytes ?? Buffer.from("value\n");
  const entryIdentity = options.entryIdentity ?? fileIdentity;
  const catalog = new FakeCatalog({
    files:
      options.catalogAbsent === true
        ? []
        : [
            Object.freeze({
              path: defaultPath,
              identity: entryIdentity,
              size: options.catalogSize ?? bytes.byteLength,
              mtimeNanoseconds: "1",
              ctimeNanoseconds: "1",
            }),
          ],
    error: options.catalogError,
  });
  const boundary = new FakeBoundary({
    bytes,
    readIdentity: options.readIdentity ?? entryIdentity,
    readRootIdentity: options.readRootIdentity ?? rootIdentity,
    readError: options.readError,
    protectedPaths: options.protectedPaths,
    protectedIdentities: options.protectedIdentities,
    freshErrors: options.freshErrors,
    checkActive: options.checkActive === true,
    afterRead: options.afterRead,
    events: catalog.events,
  });
  return {
    adapter: new ProtectedPhase3SourceAdapter(catalog, boundary),
    boundary,
    catalog,
  };
}

class FakeCatalog implements RepositoryCatalogProvider {
  readonly calls: Phase2OperationContext[] = [];
  readonly events: string[] = [];
  constructor(
    private readonly options: Readonly<{
      readonly files: readonly {
        readonly path: string;
        readonly identity: FileIdentity;
        readonly size: number;
        readonly mtimeNanoseconds: string;
        readonly ctimeNanoseconds: string;
      }[];
      readonly error?: unknown;
    }>,
  ) {}

  async catalog(context: Phase2OperationContext) {
    await Promise.resolve();
    this.events.push("catalog");
    this.calls.push(context);
    if (this.options.error) throw this.options.error;
    return Object.freeze({
      rootIdentity,
      directories: Object.freeze([]),
      files: Object.freeze([...this.options.files]),
    });
  }
}

class FakeBoundary implements Phase3SourceBoundary {
  readonly contexts: Phase2OperationContext[] = [];
  readonly readContexts: Phase2OperationContext[] = [];
  readonly readBuffers: Uint8Array[] = [];
  readonly events: string[];
  reads = 0;
  private freshCalls = 0;
  private readonly protectedPaths: ReadonlySet<string>;
  private readonly protectedIdentities: ReadonlySet<string>;

  constructor(
    private readonly options: Readonly<{
      readonly bytes: Uint8Array;
      readonly readIdentity: FileIdentity;
      readonly readRootIdentity: FileIdentity;
      readonly readError?: unknown;
      readonly protectedPaths: readonly string[] | undefined;
      readonly protectedIdentities: readonly FileIdentity[] | undefined;
      readonly freshErrors:
        | readonly (RepositoryBoundaryError | undefined)[]
        | undefined;
      readonly checkActive?: boolean;
      readonly afterRead: (() => void) | undefined;
      readonly events: string[];
    }>,
  ) {
    this.events = options.events;
    this.protectedPaths = new Set(options.protectedPaths ?? []);
    this.protectedIdentities = new Set(
      (options.protectedIdentities ?? []).map(identityKey),
    );
  }

  async assertFresh(context: Phase2OperationContext): Promise<void> {
    await Promise.resolve();
    this.events.push("fresh");
    this.contexts.push(context);
    this.assertActive(context);
    const error = this.options.freshErrors?.[this.freshCalls++];
    if (error) throw error;
  }

  isProtected(path: string, identity: FileIdentity): boolean {
    this.events.push("protected");
    return (
      this.protectedPaths.has(path) ||
      this.protectedIdentities.has(identityKey(identity))
    );
  }

  async readContent(
    path: string,
    context: Phase2OperationContext,
  ): Promise<SecureFileRead> {
    await Promise.resolve();
    this.events.push("read");
    this.reads += 1;
    this.readContexts.push(context);
    this.assertActive(context);
    if (this.options.readError) throw this.options.readError;
    const bytes = Uint8Array.from(this.options.bytes);
    this.readBuffers.push(bytes);
    this.options.afterRead?.();
    return Object.freeze({
      path,
      identity: this.options.readIdentity,
      rootIdentity: this.options.readRootIdentity,
      bytes,
    });
  }

  private assertActive(context: Phase2OperationContext): void {
    if (!this.options.checkActive) return;
    if (context.signal.aborted)
      throw new RepositoryBoundaryError(
        "operation_cancelled",
        `${defaultPath} ${rawSecret}`,
      );
    if (Date.now() >= context.deadlineAt)
      throw new RepositoryBoundaryError(
        "deadline_exceeded",
        `${defaultPath} ${rawSecret}`,
      );
  }
}

function phase3Context(): {
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
} {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 60_000,
  };
}

function contextualDigest(
  adapter: ProtectedPhase3SourceAdapter,
  context: unknown,
  path = defaultPath,
): Promise<string | null> {
  return (
    adapter.readDigest as (
      path: string,
      context: unknown,
    ) => Promise<string | null>
  )(path, context);
}

async function expectSanitizedFailure(
  promise: Promise<unknown>,
  code: RepositoryBoundaryError["code"],
  forbidden: readonly string[],
): Promise<void> {
  try {
    await promise;
    throw new Error("Expected operation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(RepositoryBoundaryError);
    expect((error as RepositoryBoundaryError).code).toBe(code);
    const message = error instanceof Error ? error.message : String(error);
    const serialized = JSON.stringify(error);
    for (const value of forbidden) {
      expect(message).not.toContain(value);
      expect(serialized).not.toContain(value);
    }
    expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
  }
}

function invoke(
  adapter: ProtectedPhase3SourceAdapter,
  method: "read" | "readDigest",
): Promise<unknown> {
  return method === "read"
    ? adapter.read(defaultPath, phase3Context())
    : adapter.readDigest(defaultPath);
}

function identity(name: string): FileIdentity {
  return Object.freeze({ device: `device-${name}`, inode: `inode-${name}` });
}

function identityKey(value: FileIdentity): string {
  return `${value.device}:${value.inode}`;
}

function digest(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isZeroed(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

async function expectNoDisclosure(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    throw new Error("Expected operation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(RepositoryBoundaryError);
    const message = error instanceof Error ? error.message : String(error);
    expect(message).not.toContain(defaultPath);
    expect(message).not.toContain(rawSecret);
  }
}

async function expectRejectedSafely(
  promise: Promise<unknown>,
  code: RepositoryBoundaryError["code"],
): Promise<void> {
  try {
    await promise;
    throw new Error("Expected operation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(RepositoryBoundaryError);
    expect((error as RepositoryBoundaryError).code).toBe(code);
    const message = error instanceof Error ? error.message : String(error);
    expect(message).not.toContain(defaultPath);
    expect(message).not.toContain(rawSecret);
  }
}
