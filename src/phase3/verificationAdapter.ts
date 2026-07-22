import {
  Phase3CoordinatorError,
  type Phase3OperationContext,
  type Phase3VerificationPort,
} from "./applyCoordinator.js";
import {
  assertPhase3TransactionRecord,
  type Phase3Impact,
  type Phase3ReloadTarget,
  type Phase3TransactionRecord,
} from "./contracts.js";

export const phase3VerificationStatuses = Object.freeze([
  "verified",
  "rejected",
  "unavailable",
  "unhealthy",
] as const);
export type Phase3VerificationStatus =
  (typeof phase3VerificationStatuses)[number];

export const phase3VerificationStages = Object.freeze([
  "input",
  "source_before",
  "probe",
  "source_after",
] as const);
export type Phase3VerificationStage = (typeof phase3VerificationStages)[number];

export const phase3VerificationErrorCodes = Object.freeze([
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
] as const);
export type Phase3VerificationErrorCode =
  (typeof phase3VerificationErrorCodes)[number];

export type Phase3VerificationOutcome = "candidate" | "checkpoint";

export type Phase3VerificationProbeRequest = Readonly<{
  transactionId: string;
  path: string;
  outcome: Phase3VerificationOutcome;
  expectedSha256: string;
  impact: Phase3Impact;
  reloadTarget: Phase3ReloadTarget | null;
  rollbackReloadRequired: boolean;
}>;

export type Phase3VerificationProbeResult = Readonly<{
  status: Phase3VerificationStatus;
  transactionId: string;
  outcome: Phase3VerificationOutcome;
  expectedSha256: string;
}>;

export interface Phase3PostEffectSourceDigestPort {
  readDigest(
    path: string,
    context: Phase3OperationContext,
  ): Promise<string | null>;
}

export interface Phase3TrustedVerificationProbePort {
  probe(
    request: Phase3VerificationProbeRequest,
    context: Phase3OperationContext,
  ): Promise<Phase3VerificationProbeResult>;
}

export class Phase3VerificationError extends Phase3CoordinatorError {
  constructor(
    public override readonly code: Phase3VerificationErrorCode,
    public readonly stage: Phase3VerificationStage,
  ) {
    super(code, `Phase 3 verification failed: ${code}`);
    this.name = "Phase3VerificationError";
  }
}

type BoundarySettlement<T> =
  | Readonly<{ fulfilled: true; value: T }>
  | Readonly<{ fulfilled: false }>;

type Phase3VerificationProbeSnapshot = Readonly<{
  status: string | undefined;
  transactionId: string | undefined;
  outcome: string | undefined;
  expectedSha256: string | undefined;
}>;

export class NarrowPhase3VerificationAdapter implements Phase3VerificationPort {
  constructor(
    private readonly source: Phase3PostEffectSourceDigestPort,
    private readonly probePort: Phase3TrustedVerificationProbePort,
  ) {}

  async verify(
    record: Phase3TransactionRecord,
    outcome: Phase3VerificationOutcome,
    context: Phase3OperationContext,
  ): Promise<void> {
    const parsed = parseTransactionRecord(record);
    if (outcome !== "candidate" && outcome !== "checkpoint")
      throw new Phase3VerificationError("invalid_outcome", "input");
    if (!verificationStateIsLegal(parsed, outcome))
      throw new Phase3VerificationError("illegal_verification_state", "input");
    assertActive(context, "input");

    const expectedSha256 =
      outcome === "candidate"
        ? parsed.candidateSha256
        : parsed.checkpointSha256;

    const firstDigest = await settleBoundary(
      () => this.source.readDigest(parsed.path, context),
      context,
      "source_before",
    );
    assertExactSourceDigest(firstDigest, expectedSha256, "source_before");

    const request: Phase3VerificationProbeRequest = Object.freeze({
      transactionId: parsed.transactionId,
      path: parsed.path,
      outcome,
      expectedSha256,
      impact: parsed.impact,
      reloadTarget: parsed.reloadTarget,
      rollbackReloadRequired: parsed.rollbackReloadRequired,
    });
    assertVerifiedEvidence(
      await settleBoundary(
        () => this.probePort.probe(request, context),
        context,
        "probe",
      ),
      request,
      context,
    );

    const finalDigest = await settleBoundary(
      () => this.source.readDigest(parsed.path, context),
      context,
      "source_after",
    );
    assertExactSourceDigest(finalDigest, expectedSha256, "source_after");
  }
}

function parseTransactionRecord(value: unknown): Phase3TransactionRecord {
  try {
    return assertPhase3TransactionRecord(value);
  } catch {
    throw new Phase3VerificationError("invalid_transaction_record", "input");
  }
}

function verificationStateIsLegal(
  record: Phase3TransactionRecord,
  outcome: Phase3VerificationOutcome,
): boolean {
  if (outcome === "candidate")
    return (
      record.state === "reload_succeeded" &&
      record.rollbackReloadRequired === false &&
      ((record.reloadTarget === null &&
        record.priorState === "post_validation_succeeded") ||
        (record.reloadTarget !== null && record.priorState === "reload_intent"))
    );

  return (
    (record.state === "rollback_validation_succeeded" &&
      record.priorState === "rollback_committed" &&
      record.rollbackReloadRequired === false) ||
    (record.state === "rollback_reload_succeeded" &&
      record.priorState === "rollback_reload_intent" &&
      record.rollbackReloadRequired === true &&
      record.reloadTarget !== null)
  );
}

async function settleBoundary<T>(
  operation: () => Promise<T>,
  context: Phase3OperationContext,
  stage: Exclude<Phase3VerificationStage, "input">,
): Promise<BoundarySettlement<T>> {
  let settlement: BoundarySettlement<T>;
  try {
    settlement = Object.freeze({ fulfilled: true, value: await operation() });
  } catch {
    settlement = Object.freeze({ fulfilled: false });
  }
  assertActive(context, stage);
  return settlement;
}

function assertExactSourceDigest(
  settlement: BoundarySettlement<string | null>,
  expectedSha256: string,
  stage: "source_before" | "source_after",
): void {
  if (!settlement.fulfilled)
    throw new Phase3VerificationError("source_unhealthy", stage);
  if (settlement.value === null)
    throw new Phase3VerificationError("source_missing", stage);
  if (!isSha256(settlement.value))
    throw new Phase3VerificationError("source_digest_malformed", stage);
  if (settlement.value !== expectedSha256)
    throw new Phase3VerificationError("source_digest_mismatch", stage);
}

function assertVerifiedEvidence(
  settlement: BoundarySettlement<Phase3VerificationProbeResult>,
  request: Phase3VerificationProbeRequest,
  context: Phase3OperationContext,
): void {
  if (!settlement.fulfilled)
    throw new Phase3VerificationError("internal_failure", "probe");
  const snapshot = snapshotProbeResult(settlement.value);
  assertActive(context, "probe");
  const evidence = parseProbeSnapshot(snapshot);
  if (evidence === undefined)
    throw new Phase3VerificationError("evidence_malformed", "probe");
  if (
    evidence.transactionId !== request.transactionId ||
    evidence.outcome !== request.outcome ||
    evidence.expectedSha256 !== request.expectedSha256
  )
    throw new Phase3VerificationError("evidence_binding_mismatch", "probe");
  if (evidence.status === "verified") return;
  const code: Phase3VerificationErrorCode =
    evidence.status === "rejected"
      ? "verification_rejected"
      : evidence.status === "unavailable"
        ? "verification_unavailable"
        : "verification_unhealthy";
  throw new Phase3VerificationError(code, "probe");
}

function snapshotProbeResult(
  value: unknown,
): Phase3VerificationProbeSnapshot | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  try {
    if (Reflect.isExtensible(value)) return undefined;
    const keys = Reflect.ownKeys(value);
    const expectedKeys = [
      "status",
      "transactionId",
      "outcome",
      "expectedSha256",
    ] as const;
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key) => typeof key !== "string") ||
      !expectedKeys.every((key) => keys.includes(key))
    )
      return undefined;

    const snapshot: Record<string, string | undefined> = Object.create(
      null,
    ) as Record<string, string | undefined>;
    for (const key of expectedKeys) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true ||
        descriptor.configurable !== false ||
        descriptor.writable !== false
      )
        return undefined;
      snapshot[key] =
        typeof descriptor.value === "string" ? descriptor.value : undefined;
    }

    return Object.freeze({
      status: snapshot.status,
      transactionId: snapshot.transactionId,
      outcome: snapshot.outcome,
      expectedSha256: snapshot.expectedSha256,
    });
  } catch {
    return undefined;
  }
}

function parseProbeSnapshot(
  snapshot: Phase3VerificationProbeSnapshot | undefined,
): Phase3VerificationProbeResult | undefined {
  if (
    snapshot === undefined ||
    !(phase3VerificationStatuses as readonly unknown[]).includes(
      snapshot.status,
    ) ||
    snapshot.transactionId === undefined ||
    (snapshot.outcome !== "candidate" && snapshot.outcome !== "checkpoint") ||
    !isSha256(snapshot.expectedSha256)
  )
    return undefined;
  return Object.freeze({
    status: snapshot.status as Phase3VerificationStatus,
    transactionId: snapshot.transactionId,
    outcome: snapshot.outcome,
    expectedSha256: snapshot.expectedSha256,
  });
}

function assertActive(
  context: Phase3OperationContext,
  stage: Phase3VerificationStage,
): void {
  try {
    if (context.signal.aborted)
      throw new Phase3VerificationError("operation_cancelled", stage);
    if (
      !Number.isFinite(context.deadlineAt) ||
      Date.now() >= context.deadlineAt
    )
      throw new Phase3VerificationError("deadline_exceeded", stage);
  } catch (error) {
    if (error instanceof Phase3VerificationError) throw error;
    throw new Phase3VerificationError("internal_failure", stage);
  }
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}
