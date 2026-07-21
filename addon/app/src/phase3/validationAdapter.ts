import { randomUUID } from "node:crypto";
import type { Phase2OperationContext } from "../phase2Contracts.js";
import {
  validateStrictYaml,
  YamlGateError,
  type YamlGateErrorCode,
} from "../yaml/strictYamlGate.js";
import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
  type Phase3ValidationPort,
} from "./applyCoordinator.js";

export const phase3ValidationPhases = [
  "candidate_pre_apply",
  "candidate_post_apply",
  "checkpoint_post_rollback",
] as const;

export type Phase3ValidationPhase = (typeof phase3ValidationPhases)[number];
export type Phase3ValidationErrorCode = YamlGateErrorCode | "invalid_phase";

export interface Phase3YamlValidationBoundary {
  validate(bytes: Uint8Array, context: Phase2OperationContext): Promise<void>;
}

const strictYamlBoundary: Phase3YamlValidationBoundary = Object.freeze({
  async validate(
    bytes: Uint8Array,
    context: Phase2OperationContext,
  ): Promise<void> {
    await validateStrictYaml(bytes, context);
  },
});

export class Phase3ValidationError extends Phase3CoordinatorError {
  constructor(
    public override readonly code: Phase3ValidationErrorCode,
    public readonly phase: Phase3ValidationPhase | "invalid",
    public readonly line = 1,
    public readonly column = 1,
  ) {
    super(code, validationMessage(code));
    this.name = "Phase3ValidationError";
  }
}

export class StrictYamlPhase3Validation implements Phase3ValidationPort {
  constructor(
    private readonly boundary: Phase3YamlValidationBoundary = strictYamlBoundary,
  ) {}

  async validate(
    bytes: Uint8Array,
    phase: Phase3ValidationPhase,
    context: Phase3OperationContext,
  ): Promise<void> {
    if (!isValidationPhase(phase))
      throw new Phase3ValidationError("invalid_phase", "invalid");
    if (!(bytes instanceof Uint8Array))
      throw new Phase3ValidationError("unsupported_encoding", phase);
    if (context.signal.aborted)
      throw new Phase3ValidationError("operation_cancelled", phase);
    if (
      !Number.isFinite(context.deadlineAt) ||
      Date.now() >= context.deadlineAt
    )
      throw new Phase3ValidationError("deadline_exceeded", phase);

    const owned = Uint8Array.from(bytes);
    const derivedContext = phase2Context(context);
    try {
      await this.boundary.validate(owned, derivedContext);
    } catch (error) {
      if (error instanceof YamlGateError)
        throw new Phase3ValidationError(
          error.code,
          phase,
          safePosition(error.line),
          safePosition(error.column),
        );
      throw new Phase3ValidationError("internal_failure", phase);
    } finally {
      owned.fill(0);
    }
  }
}

function isValidationPhase(value: unknown): value is Phase3ValidationPhase {
  return (phase3ValidationPhases as readonly unknown[]).includes(value);
}

function phase2Context(
  context: Phase3OperationContext,
): Phase2OperationContext {
  return Object.freeze({
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt: context.deadlineAt,
    signal: context.signal,
  });
}

function safePosition(value: number): number {
  return Number.isSafeInteger(value) && value > 0 ? value : 1;
}

function validationMessage(code: Phase3ValidationErrorCode): string {
  return code === "invalid_phase"
    ? "Phase 3 validation phase is invalid"
    : `Phase 3 YAML validation failed: ${code}`;
}
