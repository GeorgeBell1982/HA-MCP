import { describe, expect, it, vi } from "vitest";
import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
} from "../src/phase3/applyCoordinator.js";
import {
  assertPhase3TransactionRecord,
  phase3TransactionRecordSchema,
  phase3TransactionStates,
  type Phase3TransactionRecord,
  type Phase3TransactionState,
} from "../src/phase3/contracts.js";
import {
  NarrowPhase3VerificationAdapter,
  Phase3VerificationError,
  phase3VerificationErrorCodes,
  phase3VerificationStages,
  phase3VerificationStatuses,
  type Phase3PostEffectSourceDigestPort,
  type Phase3TrustedVerificationProbePort,
  type Phase3VerificationOutcome,
  type Phase3VerificationProbeRequest,
  type Phase3VerificationProbeResult,
  type Phase3VerificationStatus,
} from "../src/phase3/verificationAdapter.js";

const expectedSha256 = "a".repeat(64);
const candidateSha256 = "b".repeat(64);
const otherSha256 = "c".repeat(64);
const transactionId = "11111111-1111-4111-8111-111111111111";
const pathCanary = "private/verification-canary.yaml";

function context(
  signal = new AbortController().signal,
  deadlineAt = Date.now() + 60_000,
): Phase3OperationContext {
  return { signal, deadlineAt };
}

function rawRecord(
  patch: Partial<Phase3TransactionRecord> = {},
): Phase3TransactionRecord {
  return {
    schemaVersion: 2,
    transactionId,
    proposalId: "22222222-2222-4222-8222-222222222222",
    proposalStorageSha256: "d".repeat(64),
    path: pathCanary,
    expectedSha256,
    candidateSha256,
    diffSha256: "e".repeat(64),
    checkpointId: "33333333-3333-4333-8333-333333333333",
    checkpointSha256: expectedSha256,
    impact: "none",
    reloadTarget: null,
    rollbackReloadRequired: false,
    state: "reload_succeeded",
    priorState: "post_validation_succeeded",
    version: 4,
    createdAt: "2026-07-22T00:00:00.000Z",
    updatedAt: "2026-07-22T00:01:00.000Z",
    failure: null,
    ...patch,
  };
}

function recordForState(
  state: Phase3TransactionState,
): Phase3TransactionRecord {
  const patch: Partial<Phase3TransactionRecord> = { state, priorState: null };
  if (state === "reload_intent")
    Object.assign(patch, {
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      priorState: "post_validation_succeeded",
    });
  if (state === "reload_succeeded")
    patch.priorState = "post_validation_succeeded";
  if (state === "rollback_reload_intent")
    Object.assign(patch, {
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      rollbackReloadRequired: true,
      priorState: "rollback_validation_succeeded",
    });
  if (state === "rollback_reload_succeeded")
    Object.assign(patch, {
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      rollbackReloadRequired: true,
      priorState: "rollback_reload_intent",
    });
  if (state === "rollback_validation_succeeded")
    patch.priorState = "rollback_committed";
  return assertPhase3TransactionRecord(rawRecord(patch));
}

function expectedDigest(
  record: Phase3TransactionRecord,
  outcome: Phase3VerificationOutcome,
): string {
  return outcome === "candidate"
    ? record.candidateSha256
    : record.checkpointSha256;
}

function evidence(
  request: Phase3VerificationProbeRequest,
  status: Phase3VerificationStatus = "verified",
  patch: Partial<Phase3VerificationProbeResult> = {},
): Phase3VerificationProbeResult {
  return Object.freeze({
    status,
    transactionId: request.transactionId,
    outcome: request.outcome,
    expectedSha256: request.expectedSha256,
    ...patch,
  });
}

type SourceStep = unknown;
type ProbeStep = unknown;
type SourceOperation = (
  path: string,
  context: Phase3OperationContext,
) => unknown;
type ProbeOperation = (
  request: Phase3VerificationProbeRequest,
  context: Phase3OperationContext,
) => unknown;

function isSourceOperation(value: unknown): value is SourceOperation {
  return typeof value === "function";
}

function isProbeOperation(value: unknown): value is ProbeOperation {
  return typeof value === "function";
}

function harness(
  record: Phase3TransactionRecord,
  outcome: Phase3VerificationOutcome,
  options: Readonly<{
    sourceSteps?: readonly SourceStep[];
    probeStep?: ProbeStep;
    operationContext?: Phase3OperationContext;
  }> = {},
) {
  const calls: string[] = [];
  const sourceContexts: Phase3OperationContext[] = [];
  const probeContexts: Phase3OperationContext[] = [];
  const requests: Phase3VerificationProbeRequest[] = [];
  const digest = expectedDigest(record, outcome);
  const sourceSteps = [...(options.sourceSteps ?? [digest, digest])];
  let sourceIndex = 0;
  const source = {
    async readDigest(path: string, received: Phase3OperationContext) {
      calls.push(`source:${sourceIndex + 1}`);
      sourceContexts.push(received);
      const step = sourceSteps[sourceIndex++];
      const value = isSourceOperation(step) ? step(path, received) : step;
      if (value instanceof Error) throw value;
      return await Promise.resolve(value);
    },
  } as unknown as Phase3PostEffectSourceDigestPort;
  const probePort = {
    async probe(
      request: Phase3VerificationProbeRequest,
      received: Phase3OperationContext,
    ) {
      calls.push("probe");
      requests.push(request);
      probeContexts.push(received);
      const step = options.probeStep;
      const value = isProbeOperation(step)
        ? step(request, received)
        : (step ?? evidence(request));
      if (value instanceof Error) throw value;
      return await Promise.resolve(value);
    },
  } as unknown as Phase3TrustedVerificationProbePort;
  const operationContext = options.operationContext ?? context();
  return {
    calls,
    sourceContexts,
    probeContexts,
    requests,
    operationContext,
    run: new NarrowPhase3VerificationAdapter(source, probePort).verify(
      record,
      outcome,
      operationContext,
    ),
  };
}

async function captureError(operation: Promise<unknown>) {
  try {
    await operation;
    throw new Error("expected Phase 3 verification failure");
  } catch (error) {
    expect(error).toBeInstanceOf(Phase3VerificationError);
    expect(error).toBeInstanceOf(Phase3CoordinatorError);
    return error as Phase3VerificationError;
  }
}

function exactMatrixAllows(
  record: Phase3TransactionRecord,
  outcome: Phase3VerificationOutcome,
): boolean {
  if (outcome === "candidate")
    return (
      record.state === "reload_succeeded" &&
      !record.rollbackReloadRequired &&
      ((record.reloadTarget === null &&
        record.priorState === "post_validation_succeeded") ||
        (record.reloadTarget !== null && record.priorState === "reload_intent"))
    );
  return (
    (record.state === "rollback_validation_succeeded" &&
      record.priorState === "rollback_committed" &&
      !record.rollbackReloadRequired) ||
    (record.state === "rollback_reload_succeeded" &&
      record.priorState === "rollback_reload_intent" &&
      record.rollbackReloadRequired &&
      record.reloadTarget !== null)
  );
}

const stateContextCases = (["candidate", "checkpoint"] as const).flatMap(
  (outcome) =>
    (
      [
        "reload_succeeded",
        "rollback_validation_succeeded",
        "rollback_reload_succeeded",
      ] as const
    ).flatMap((state) =>
      ([null, ...phase3TransactionStates] as const).flatMap((priorState) =>
        [
          {
            name: "no-target/flag-false",
            impact: "none" as const,
            reloadTarget: null,
            rollbackReloadRequired: false,
          },
          {
            name: "target/flag-false",
            impact: "domain_reload" as const,
            reloadTarget: "automation.reload" as const,
            rollbackReloadRequired: false,
          },
          {
            name: "target/flag-true",
            impact: "domain_reload" as const,
            reloadTarget: "automation.reload" as const,
            rollbackReloadRequired: true,
          },
          {
            name: "no-target/flag-true",
            impact: "none" as const,
            reloadTarget: null,
            rollbackReloadRequired: true,
          },
        ].map((variant) => ({
          label: `${outcome}/${state}/${String(priorState)}/${variant.name}`,
          outcome,
          raw: rawRecord({
            state,
            priorState,
            impact: variant.impact,
            reloadTarget: variant.reloadTarget,
            rollbackReloadRequired: variant.rollbackReloadRequired,
          }),
        })),
      ),
    ),
);

describe("Phase 3J narrow verification adapter", () => {
  it("exports immutable closed contracts", () => {
    expect(phase3VerificationStatuses).toEqual([
      "verified",
      "rejected",
      "unavailable",
      "unhealthy",
    ]);
    expect(phase3VerificationStages).toEqual([
      "input",
      "source_before",
      "probe",
      "source_after",
    ]);
    expect(phase3VerificationErrorCodes).toEqual([
      "invalid_transaction_record",
      "invalid_outcome",
      "illegal_verification_state",
      "operation_cancelled",
      "deadline_exceeded",
      "source_digest_malformed",
      "source_missing",
      "source_digest_mismatch",
      "source_unhealthy",
      "evidence_malformed",
      "evidence_binding_mismatch",
      "verification_rejected",
      "verification_unavailable",
      "verification_unhealthy",
      "internal_failure",
    ]);
    for (const value of [
      phase3VerificationStatuses,
      phase3VerificationStages,
      phase3VerificationErrorCodes,
    ]) {
      expect(Object.isFrozen(value)).toBe(true);
      expect(() =>
        (value as readonly string[] as string[]).push("forged"),
      ).toThrow(TypeError);
    }
  });

  it.each(
    phase3TransactionStates.flatMap((state) =>
      (["candidate", "checkpoint"] as const).map((outcome) => ({
        state,
        outcome,
      })),
    ),
  )(
    "enforces $state x $outcome after strict record assertion",
    async ({ state, outcome }) => {
      const record = recordForState(state);
      const test = harness(record, outcome);
      const allowed = exactMatrixAllows(record, outcome);
      if (allowed) {
        await expect(test.run).resolves.toBeUndefined();
        expect(test.calls).toEqual(["source:1", "probe", "source:2"]);
      } else {
        await expect(test.run).rejects.toMatchObject({
          code: "illegal_verification_state",
          stage: "input",
        });
        expect(test.calls).toEqual([]);
      }
    },
  );

  it.each(stateContextCases)(
    "enforces predecessor/flag/target matrix: $label",
    async ({ raw, outcome }) => {
      const parsed = phase3TransactionRecordSchema.safeParse(raw);
      const test = harness(raw, outcome);
      if (parsed.success && exactMatrixAllows(parsed.data, outcome)) {
        await expect(test.run).resolves.toBeUndefined();
        expect(test.calls).toEqual(["source:1", "probe", "source:2"]);
      } else {
        await expect(test.run).rejects.toMatchObject({
          code: parsed.success
            ? "illegal_verification_state"
            : "invalid_transaction_record",
          stage: "input",
        });
        expect(test.calls).toEqual([]);
      }
    },
  );

  it("distinguishes malformed input and outcome before effects", async () => {
    const record = rawRecord();
    const malformed = harness(
      { ...record, path: "../outside.yaml" },
      "candidate",
    );
    await expect(malformed.run).rejects.toMatchObject({
      code: "invalid_transaction_record",
      stage: "input",
    });
    expect(malformed.calls).toEqual([]);

    const invalidOutcome = harness(
      record,
      "stale" as Phase3VerificationOutcome,
    );
    await expect(invalidOutcome.run).rejects.toMatchObject({
      code: "invalid_outcome",
      stage: "input",
    });
    expect(invalidOutcome.calls).toEqual([]);
  });

  it.each(["candidate", "checkpoint"] as const)(
    "uses the exact ordered digest sandwich and same context for %s",
    async (outcome) => {
      const record =
        outcome === "candidate"
          ? rawRecord()
          : rawRecord({
              state: "rollback_validation_succeeded",
              priorState: "rollback_committed",
            });
      const test = harness(record, outcome, {
        probeStep(request: Phase3VerificationProbeRequest) {
          expect(Object.isFrozen(request)).toBe(true);
          expect(Reflect.ownKeys(request)).toEqual([
            "transactionId",
            "path",
            "outcome",
            "expectedSha256",
            "impact",
            "reloadTarget",
            "rollbackReloadRequired",
          ]);
          expect(request).toEqual({
            transactionId: record.transactionId,
            path: record.path,
            outcome,
            expectedSha256: expectedDigest(record, outcome),
            impact: record.impact,
            reloadTarget: record.reloadTarget,
            rollbackReloadRequired: record.rollbackReloadRequired,
          });
          expect(() =>
            Object.assign(request as { path: string }, { path: "forged.yaml" }),
          ).toThrow(TypeError);
          return evidence(request);
        },
      });
      await expect(test.run).resolves.toBeUndefined();
      expect(test.calls).toEqual(["source:1", "probe", "source:2"]);
      expect(test.sourceContexts).toEqual([
        test.operationContext,
        test.operationContext,
      ]);
      expect(test.probeContexts).toEqual([test.operationContext]);
      expect(test.requests).toHaveLength(1);
    },
  );

  it.each(
    (["source_before", "source_after"] as const).flatMap((stage) =>
      [
        ["malformed", "NOT_A_DIGEST", "source_digest_malformed"],
        ["missing", null, "source_missing"],
        ["mismatch", otherSha256, "source_digest_mismatch"],
        ["throw", new Error("UPSTREAM_SOURCE_CANARY"), "source_unhealthy"],
      ].map(([name, value, code]) => ({ stage, name, value, code })),
    ),
  )(
    "classifies $stage source $name exactly with no retry",
    async ({ stage, value, code }) => {
      const steps =
        stage === "source_before"
          ? [value, candidateSha256]
          : [candidateSha256, value];
      const test = harness(rawRecord(), "candidate", { sourceSteps: steps });
      await expect(test.run).rejects.toMatchObject({ code, stage });
      expect(test.calls).toEqual(
        stage === "source_before"
          ? ["source:1"]
          : ["source:1", "probe", "source:2"],
      );
    },
  );

  it.each(phase3VerificationStatuses)(
    "classifies exact frozen probe status %s",
    async (status) => {
      const test = harness(rawRecord(), "candidate", {
        probeStep: (request: Phase3VerificationProbeRequest) =>
          evidence(request, status),
      });
      if (status === "verified")
        await expect(test.run).resolves.toBeUndefined();
      else
        await expect(test.run).rejects.toMatchObject({
          code:
            status === "rejected"
              ? "verification_rejected"
              : status === "unavailable"
                ? "verification_unavailable"
                : "verification_unhealthy",
          stage: "probe",
        });
      expect(test.calls).toEqual(
        status === "verified"
          ? ["source:1", "probe", "source:2"]
          : ["source:1", "probe"],
      );
    },
  );

  it.each([
    {
      name: "transaction",
      patch: { transactionId: "44444444-4444-4444-8444-444444444444" },
    },
    { name: "outcome", patch: { outcome: "checkpoint" as const } },
    { name: "digest", patch: { expectedSha256: otherSha256 } },
  ])("rejects stale $name evidence binding", async ({ patch }) => {
    const test = harness(rawRecord(), "candidate", {
      probeStep: (request: Phase3VerificationProbeRequest) =>
        evidence(request, "verified", patch),
    });
    await expect(test.run).rejects.toMatchObject({
      code: "evidence_binding_mismatch",
      stage: "probe",
    });
    expect(test.calls).toEqual(["source:1", "probe"]);
  });

  it("rejects unfrozen, excess, accessor, symbol, primitive, and invalid evidence", async () => {
    let getterCalls = 0;
    const accessor = {
      get status() {
        getterCalls += 1;
        return "verified";
      },
      transactionId,
      outcome: "candidate",
      expectedSha256: candidateSha256,
    };
    Object.freeze(accessor);
    const symbol = Object.freeze({
      status: "verified",
      transactionId,
      outcome: "candidate",
      expectedSha256: candidateSha256,
      [Symbol("forged")]: true,
    });
    const malformed: readonly unknown[] = [
      {
        status: "verified",
        transactionId,
        outcome: "candidate",
        expectedSha256: candidateSha256,
      },
      Object.freeze({
        status: "verified",
        transactionId,
        outcome: "candidate",
        expectedSha256: candidateSha256,
        excess: true,
      }),
      accessor,
      symbol,
      "verified",
      Object.freeze({
        status: "stale",
        transactionId,
        outcome: "candidate",
        expectedSha256: candidateSha256,
      }),
      Object.freeze({
        status: "verified",
        transactionId,
        outcome: "candidate",
        expectedSha256: "malformed",
      }),
    ];
    for (const value of malformed) {
      const test = harness(rawRecord(), "candidate", { probeStep: value });
      await expect(test.run).rejects.toMatchObject({
        code: "evidence_malformed",
        stage: "probe",
      });
      expect(test.calls).toEqual(["source:1", "probe"]);
    }
    expect(getterCalls).toBe(0);
  });

  it("sanitizes hostile ownKeys and descriptor proxies", async () => {
    const target = Object.freeze({
      status: "verified" as const,
      transactionId,
      outcome: "candidate" as const,
      expectedSha256: candidateSha256,
    });
    const hostile = [
      new Proxy(target, {
        ownKeys() {
          throw new Error("HOSTILE_OWN_KEYS_CANARY");
        },
      }),
      new Proxy(target, {
        getOwnPropertyDescriptor() {
          throw new Error("HOSTILE_DESCRIPTOR_CANARY");
        },
      }),
    ];
    for (const value of hostile) {
      const error = await captureError(
        harness(rawRecord(), "candidate", { probeStep: value }).run,
      );
      expect(error).toMatchObject({
        code: "evidence_malformed",
        stage: "probe",
      });
      expect(String(error)).not.toContain("CANARY");
    }
  });

  it("snapshots foreign evidence without property gets or later rereads", async () => {
    let gets = 0;
    const target = Object.freeze({
      status: "verified" as const,
      transactionId,
      outcome: "candidate" as const,
      expectedSha256: candidateSha256,
    });
    const foreign = new Proxy(target, {
      get(_target, key) {
        if (Reflect.ownKeys(target).includes(key)) {
          gets += 1;
          throw new Error("FOREIGN_GET_CANARY");
        }
        return undefined;
      },
    });
    await expect(
      harness(rawRecord(), "candidate", { probeStep: foreign }).run,
    ).resolves.toBeUndefined();
    expect(gets).toBe(0);
  });

  it("rechecks cancellation after descriptor snapshot traps return valid evidence", async () => {
    const controller = new AbortController();
    const target = Object.freeze({
      status: "verified" as const,
      transactionId,
      outcome: "candidate" as const,
      expectedSha256: candidateSha256,
    });
    const foreign = new Proxy(target, {
      getOwnPropertyDescriptor(current, key) {
        controller.abort();
        return Reflect.getOwnPropertyDescriptor(current, key);
      },
    });
    const test = harness(rawRecord(), "candidate", {
      operationContext: context(controller.signal),
      probeStep: foreign,
    });
    await expect(test.run).rejects.toMatchObject({
      code: "operation_cancelled",
      stage: "probe",
    });
    expect(test.calls).toEqual(["source:1", "probe"]);
    expect(test.requests).toHaveLength(1);
  });

  it("rechecks the deadline after isExtensible snapshot traps return valid evidence", async () => {
    let now = 10;
    const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
    try {
      const target = Object.freeze({
        status: "verified" as const,
        transactionId,
        outcome: "candidate" as const,
        expectedSha256: candidateSha256,
      });
      const foreign = new Proxy(target, {
        isExtensible(current) {
          now = 100;
          return Reflect.isExtensible(current);
        },
      });
      const test = harness(rawRecord(), "candidate", {
        operationContext: context(new AbortController().signal, 50),
        probeStep: foreign,
      });
      await expect(test.run).rejects.toMatchObject({
        code: "deadline_exceeded",
        stage: "probe",
      });
      expect(test.calls).toEqual(["source:1", "probe"]);
      expect(test.requests).toHaveLength(1);
    } finally {
      clock.mockRestore();
    }
  });

  it("gives cancellation precedence when ownKeys snapshot traps abort and throw", async () => {
    const controller = new AbortController();
    const target = Object.freeze({
      status: "verified" as const,
      transactionId,
      outcome: "candidate" as const,
      expectedSha256: candidateSha256,
    });
    const foreign = new Proxy(target, {
      ownKeys() {
        controller.abort();
        throw new Error("OWN_KEYS_ABORT_CANARY");
      },
    });
    const test = harness(rawRecord(), "candidate", {
      operationContext: context(controller.signal),
      probeStep: foreign,
    });
    const error = await captureError(test.run);
    expect(error).toMatchObject({
      code: "operation_cancelled",
      stage: "probe",
    });
    expect(String(error)).not.toContain("OWN_KEYS_ABORT_CANARY");
    expect(test.calls).toEqual(["source:1", "probe"]);
    expect(test.requests).toHaveLength(1);
  });

  it.each(["source_before", "probe", "source_after"] as const)(
    "cancellation after fulfilled and rejected %s takes precedence",
    async (stage) => {
      for (const rejected of [false, true]) {
        const controller = new AbortController();
        const cancel = () => {
          controller.abort();
          return rejected ? new Error("BOUNDARY_THROW_CANARY") : undefined;
        };
        const options = {
          operationContext: context(controller.signal),
          sourceSteps:
            stage === "source_before"
              ? [cancel, candidateSha256]
              : stage === "source_after"
                ? [candidateSha256, cancel]
                : [candidateSha256, candidateSha256],
          probeStep:
            stage === "probe"
              ? () => cancel()
              : (request: Phase3VerificationProbeRequest) => evidence(request),
        };
        const error = await captureError(
          harness(rawRecord(), "candidate", options).run,
        );
        expect(error).toMatchObject({ code: "operation_cancelled", stage });
        expect(String(error)).not.toContain("BOUNDARY_THROW_CANARY");
      }
    },
  );

  it.each(["source_before", "probe", "source_after"] as const)(
    "deadline after fulfilled and rejected %s takes precedence",
    async (stage) => {
      for (const rejected of [false, true]) {
        let now = 10;
        const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
        try {
          const expire = () => {
            now = 100;
            return rejected ? new Error("DEADLINE_THROW_CANARY") : undefined;
          };
          const options = {
            operationContext: context(new AbortController().signal, 50),
            sourceSteps:
              stage === "source_before"
                ? [expire, candidateSha256]
                : stage === "source_after"
                  ? [candidateSha256, expire]
                  : [candidateSha256, candidateSha256],
            probeStep:
              stage === "probe"
                ? () => expire()
                : (request: Phase3VerificationProbeRequest) =>
                    evidence(request),
          };
          const error = await captureError(
            harness(rawRecord(), "candidate", options).run,
          );
          expect(error).toMatchObject({ code: "deadline_exceeded", stage });
          expect(String(error)).not.toContain("DEADLINE_THROW_CANARY");
        } finally {
          clock.mockRestore();
        }
      }
    },
  );

  it.each(["cancelled", "expired", "nonfinite"] as const)(
    "rejects %s input context before effects",
    async (kind) => {
      const controller = new AbortController();
      if (kind === "cancelled") controller.abort();
      const operationContext = context(
        controller.signal,
        kind === "expired"
          ? Date.now() - 1
          : kind === "nonfinite"
            ? Number.NaN
            : Date.now() + 60_000,
      );
      const test = harness(rawRecord(), "candidate", { operationContext });
      await expect(test.run).rejects.toMatchObject({
        code:
          kind === "cancelled" ? "operation_cancelled" : "deadline_exceeded",
        stage: "input",
      });
      expect(test.calls).toEqual([]);
    },
  );

  it("uses cancellation precedence when cancellation and deadline coincide", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      harness(rawRecord(), "candidate", {
        operationContext: context(controller.signal, Number.NaN),
      }).run,
    ).rejects.toMatchObject({ code: "operation_cancelled", stage: "input" });
  });

  it("sanitizes probe rejection, paths, foreign content, and observed digests", async () => {
    const canary = "UPSTREAM_SECRET_CONTENT_CANARY";
    const cases = [
      harness(rawRecord(), "candidate", {
        sourceSteps: [new Error(canary), candidateSha256],
      }).run,
      harness(rawRecord(), "candidate", {
        sourceSteps: [otherSha256, candidateSha256],
      }).run,
      harness(rawRecord(), "candidate", {
        probeStep: new Error(canary),
      }).run,
      harness(rawRecord(), "candidate", {
        probeStep: Object.freeze({
          status: "verified",
          transactionId: canary,
          outcome: "candidate",
          expectedSha256: candidateSha256,
        }),
      }).run,
    ];
    for (const operation of cases) {
      const error = await captureError(operation);
      const disclosed = `${String(error)} ${JSON.stringify(error)}`;
      expect(disclosed).not.toContain(canary);
      expect(disclosed).not.toContain(pathCanary);
      expect(disclosed).not.toContain(otherSha256);
      expect(Object.hasOwn(error, "cause")).toBe(false);
      expect(Object.hasOwn(error, "path")).toBe(false);
    }
  });
});
