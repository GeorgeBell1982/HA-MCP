import { describe, expect, it } from "vitest";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../src/phase2Contracts.js";
import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
} from "../src/phase3/applyCoordinator.js";
import {
  Phase3ValidationError,
  StrictYamlPhase3Validation,
  phase3ValidationPhases,
  type Phase3ValidationPhase,
  type Phase3YamlValidationBoundary,
} from "../src/phase3/validationAdapter.js";
import {
  YamlGateError,
  yamlGateErrorCodes,
  type YamlGateErrorCode,
} from "../src/yaml/strictYamlGate.js";

const candidateCanary = "PHASE3_VALIDATION_CANDIDATE_CANARY";

function context(
  signal = new AbortController().signal,
  deadlineAt = Date.now() + 30_000,
): Phase3OperationContext {
  return { signal, deadlineAt };
}

function bytes(value: string): Uint8Array {
  return Buffer.from(value, "utf8");
}

async function captureError(operation: Promise<unknown>) {
  try {
    await operation;
    throw new Error("expected Phase 3 validation failure");
  } catch (error) {
    expect(error).toBeInstanceOf(Phase3ValidationError);
    expect(error).toBeInstanceOf(Phase3CoordinatorError);
    return error as Phase3ValidationError;
  }
}

class CapturingBoundary implements Phase3YamlValidationBoundary {
  readonly calls: {
    readonly bytes: Uint8Array;
    readonly context: Phase2OperationContext;
  }[] = [];

  constructor(private readonly failure?: Error) {}

  async validate(
    candidate: Uint8Array,
    operation: Phase2OperationContext,
  ): Promise<void> {
    this.calls.push({ bytes: candidate, context: operation });
    if (this.failure) throw this.failure;
  }
}

describe("Phase 3G strict YAML validation adapter", () => {
  it.each(phase3ValidationPhases)(
    "runs the real strict gate for %s",
    async (phase) => {
      await expect(
        new StrictYamlPhase3Validation().validate(
          bytes("automation:\n  alias: Lights\n"),
          phase,
          context(),
        ),
      ).resolves.toBeUndefined();
    },
  );

  it("accepts implicit and explicit empty YAML", async () => {
    const validation = new StrictYamlPhase3Validation();
    for (const source of ["", "  \n# empty\n", "---\n", "--- # empty\n...\n"])
      await expect(
        validation.validate(bytes(source), "candidate_pre_apply", context()),
      ).resolves.toBeUndefined();
  });

  it("preserves real strict-gate diagnostics and size boundaries", async () => {
    const validation = new StrictYamlPhase3Validation();
    const malformed = await captureError(
      validation.validate(
        bytes("a: [1, 2\n"),
        "candidate_pre_apply",
        context(),
      ),
    );
    expect(malformed).toMatchObject({
      code: "yaml_syntax",
      phase: "candidate_pre_apply",
    });

    const exact = bytes(`#${"a".repeat(PHASE2_MAX_TEXT_BYTES - 2)}\n`);
    expect(exact.byteLength).toBe(PHASE2_MAX_TEXT_BYTES);
    await expect(
      validation.validate(exact, "candidate_pre_apply", context()),
    ).resolves.toBeUndefined();

    const oversized = bytes(`#${"a".repeat(PHASE2_MAX_TEXT_BYTES - 1)}\n`);
    const sizeError = await captureError(
      validation.validate(oversized, "candidate_pre_apply", context()),
    );
    expect(sizeError.code).toBe("file_too_large");
  });

  it("rejects invalid phases, cancellation, and deadlines before effects", async () => {
    const boundary = new CapturingBoundary();
    const validation = new StrictYamlPhase3Validation(boundary);
    const invalid = await captureError(
      validation.validate(
        bytes("a: 1\n"),
        "unexpected_phase" as Phase3ValidationPhase,
        context(),
      ),
    );
    expect(invalid).toMatchObject({ code: "invalid_phase", phase: "invalid" });

    const controller = new AbortController();
    controller.abort();
    const cancelled = await captureError(
      validation.validate(
        bytes("a: 1\n"),
        "candidate_pre_apply",
        context(controller.signal),
      ),
    );
    expect(cancelled.code).toBe("operation_cancelled");

    const expired = await captureError(
      validation.validate(
        bytes("a: 1\n"),
        "candidate_pre_apply",
        context(new AbortController().signal, Date.now() - 1),
      ),
    );
    expect(expired.code).toBe("deadline_exceeded");
    expect(boundary.calls).toHaveLength(0);
  });

  it("derives one frozen fresh Phase 2 context per call", async () => {
    const boundary = new CapturingBoundary();
    const validation = new StrictYamlPhase3Validation(boundary);
    const caller = context();
    await validation.validate(bytes("a: 1\n"), "candidate_pre_apply", caller);
    await validation.validate(bytes("a: 1\n"), "candidate_post_apply", caller);

    expect(boundary.calls).toHaveLength(2);
    const [first, second] = boundary.calls;
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    for (const call of boundary.calls) {
      expect(Object.isFrozen(call.context)).toBe(true);
      expect(call.context.signal).toBe(caller.signal);
      expect(call.context.deadlineAt).toBe(caller.deadlineAt);
      expect(call.context.requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
      expect(call.context.operationId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
      expect(call.context.requestId).not.toBe(call.context.operationId);
    }
    expect(first!.context.requestId).not.toBe(second!.context.requestId);
    expect(first!.context.operationId).not.toBe(second!.context.operationId);
  });

  it("preserves caller bytes and zeros owned bytes on success and failure", async () => {
    for (const failure of [undefined, new YamlGateError("yaml_syntax")]) {
      const boundary = new CapturingBoundary(failure);
      const validation = new StrictYamlPhase3Validation(boundary);
      const caller = bytes(candidateCanary);
      const original = Uint8Array.from(caller);
      const operation = validation.validate(
        caller,
        "candidate_pre_apply",
        context(),
      );
      if (failure)
        await expect(operation).rejects.toBeInstanceOf(Phase3ValidationError);
      else await expect(operation).resolves.toBeUndefined();
      expect([...caller]).toEqual([...original]);
      expect(boundary.calls[0]!.bytes).not.toBe(caller);
      expect(boundary.calls[0]!.bytes.every((value) => value === 0)).toBe(true);
    }
  });

  it.each(
    phase3ValidationPhases.flatMap((phase) =>
      yamlGateErrorCodes.map((code) => [phase, code] as const),
    ),
  )(
    "maps %s %s through the exhaustive closed error contract",
    async (phase, code) => {
      const cause = new YamlGateError(code, 7, 11);
      cause.message = "UNDERLYING_CAUSE_CANARY";
      const boundary = new CapturingBoundary(cause);
      const error = await captureError(
        new StrictYamlPhase3Validation(boundary).validate(
          bytes(candidateCanary),
          phase,
          context(),
        ),
      );
      expect(error).toMatchObject({ code, phase, line: 7, column: 11 });
      expect(Number.isFinite(error.line)).toBe(true);
      expect(Number.isFinite(error.column)).toBe(true);
      expect(error.line).toBeGreaterThan(0);
      expect(error.column).toBeGreaterThan(0);
      expect(error.message.length).toBeLessThanOrEqual(96);
      expect(error.message).toContain(code);
      expect(error.message).not.toContain(candidateCanary);
      expect(error.message).not.toContain("UNDERLYING_CAUSE_CANARY");
    },
  );

  it("sanitizes unknown failures and invalid positions", async () => {
    const unknown = new CapturingBoundary(
      new Error("UNKNOWN_FAILURE_WITH_SECRET_CANARY"),
    );
    const internal = await captureError(
      new StrictYamlPhase3Validation(unknown).validate(
        bytes(candidateCanary),
        "checkpoint_post_rollback",
        context(),
      ),
    );
    expect(internal).toMatchObject({
      code: "internal_failure",
      phase: "checkpoint_post_rollback",
      line: 1,
      column: 1,
    });
    expect(internal.message).not.toContain("SECRET_CANARY");

    const invalidPosition = new CapturingBoundary(
      new YamlGateError("yaml_syntax", Number.NaN, -10),
    );
    const normalized = await captureError(
      new StrictYamlPhase3Validation(invalidPosition).validate(
        bytes(candidateCanary),
        "candidate_post_apply",
        context(),
      ),
    );
    expect(normalized).toMatchObject({ line: 1, column: 1 });
  });

  it("rejects non-byte runtime input without invoking the boundary", async () => {
    const boundary = new CapturingBoundary();
    const error = await captureError(
      new StrictYamlPhase3Validation(boundary).validate(
        "not bytes" as unknown as Uint8Array,
        "candidate_pre_apply",
        context(),
      ),
    );
    expect(error.code).toBe("unsupported_encoding");
    expect(boundary.calls).toHaveLength(0);
  });
});
