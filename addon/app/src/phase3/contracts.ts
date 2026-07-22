import { createHash } from "node:crypto";
import { z } from "zod";

export type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends object
    ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
    : T;

function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}

export const phase3TransactionStates = deepFreeze([
  "intent_prepared",
  "apply_committed",
  "post_validation_succeeded",
  "reload_intent",
  "reload_succeeded",
  "verification_succeeded",
  "rollback_intent",
  "rollback_committed",
  "rollback_validation_succeeded",
  "rollback_reload_intent",
  "rollback_reload_succeeded",
  "rollback_verification_succeeded",
  "manual_recovery_required",
] as const);

export type Phase3TransactionState = (typeof phase3TransactionStates)[number];

export const phase3TerminalOutcomes = deepFreeze({
  verification_succeeded: "verified",
  rollback_verification_succeeded: "rolled_back",
  manual_recovery_required: "blocked",
} as const);

export const phase3NonTerminalStates = deepFreeze(
  phase3TransactionStates.filter(
    (state) => !(state in phase3TerminalOutcomes),
  ) as Exclude<Phase3TransactionState, keyof typeof phase3TerminalOutcomes>[],
);

export const phase3LegalTransitions = deepFreeze({
  intent_prepared: [
    "apply_committed",
    "rollback_intent",
    "manual_recovery_required",
  ],
  apply_committed: [
    "post_validation_succeeded",
    "rollback_intent",
    "manual_recovery_required",
  ],
  post_validation_succeeded: [
    "reload_intent",
    "reload_succeeded",
    "rollback_intent",
    "manual_recovery_required",
  ],
  reload_intent: [
    "reload_succeeded",
    "rollback_intent",
    "manual_recovery_required",
  ],
  reload_succeeded: [
    "verification_succeeded",
    "rollback_intent",
    "manual_recovery_required",
  ],
  verification_succeeded: [],
  rollback_intent: ["rollback_committed", "manual_recovery_required"],
  rollback_committed: [
    "rollback_validation_succeeded",
    "manual_recovery_required",
  ],
  rollback_validation_succeeded: [
    "rollback_reload_intent",
    "rollback_verification_succeeded",
    "manual_recovery_required",
  ],
  rollback_reload_intent: [
    "rollback_reload_succeeded",
    "manual_recovery_required",
  ],
  rollback_reload_succeeded: [
    "rollback_verification_succeeded",
    "manual_recovery_required",
  ],
  rollback_verification_succeeded: [],
  manual_recovery_required: [],
} as const satisfies Record<
  Phase3TransactionState,
  readonly Phase3TransactionState[]
>);

export function phase3CanTransition(
  from: Phase3TransactionState,
  to: Phase3TransactionState,
): boolean {
  return phase3LegalTransitions[from].includes(to as never);
}

export function phase3CanRecordTransition(
  previous: Phase3TransactionRecord,
  next: Phase3TransactionRecord,
): boolean {
  if (!phase3CanTransition(previous.state, next.state)) return false;
  if (previous.reloadTarget !== next.reloadTarget) return false;
  if (previous.rollbackReloadRequired && !next.rollbackReloadRequired)
    return false;
  if (
    !previous.rollbackReloadRequired &&
    next.rollbackReloadRequired &&
    next.state !== "rollback_intent"
  )
    return false;
  if (next.state === "rollback_intent") {
    if (previous.state === "reload_intent")
      return recordReloadContextIsLegal(next);
    if (previous.state === "reload_succeeded")
      return (
        next.rollbackReloadRequired === (previous.reloadTarget !== null) &&
        recordReloadContextIsLegal(next)
      );
    return !next.rollbackReloadRequired && recordReloadContextIsLegal(next);
  }
  if (previous.state === "post_validation_succeeded") {
    if (next.state === "reload_intent") return next.reloadTarget !== null;
    if (next.state === "reload_succeeded") return next.reloadTarget === null;
  }
  if (previous.state === "rollback_validation_succeeded") {
    if (next.state === "rollback_reload_intent")
      return next.rollbackReloadRequired && next.reloadTarget !== null;
    if (next.state === "rollback_verification_succeeded")
      return !next.rollbackReloadRequired;
  }
  return recordReloadContextIsLegal(next);
}

export const phase3CommitStatuses = deepFreeze([
  "before_commit",
  "committed",
  "commit_unknown",
] as const);

export type Phase3CommitStatus = (typeof phase3CommitStatuses)[number];

export const phase3ImpactValues = deepFreeze([
  "none",
  "domain_reload",
  "restart_required",
] as const);

export type Phase3Impact = (typeof phase3ImpactValues)[number];

export const phase3ReloadTargets = deepFreeze([
  "automation.reload",
  "script.reload",
  "scene.reload",
] as const);

export type Phase3ReloadTarget = (typeof phase3ReloadTargets)[number];

export const phase3RiskValues = deepFreeze(["low", "high"] as const);
export type Phase3Risk = (typeof phase3RiskValues)[number];

export const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export const phase3CanonicalRelativePathSchema = z
  .string()
  .min(1)
  .max(512)
  .refine((value) => value === value.normalize("NFC"), "Path must use NFC")
  .refine((value) => !value.includes("\\"), "Use '/' separators")
  .refine((value) => !value.startsWith("/"), "Path must be relative")
  .refine((value) => !value.includes(":"), "Path contains a denied character")
  .refine(
    (value) =>
      !Array.from(value).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code <= 0x1f || code === 0x7f;
      }),
    "Path contains a denied control character",
  )
  .refine(
    (value) =>
      value
        .split("/")
        .every(
          (segment) => segment !== "" && segment !== "." && segment !== "..",
        ),
    "Path must be canonical and non-traversing",
  );

export const phase3ProposalStateSchema = z.enum([
  "pending",
  "discarded",
  "expired",
]);

export const phase3ProposalSnapshotSchema = z
  .object({
    proposalId: z.string().uuid(),
    proposalStorageSha256: sha256Schema,
    state: phase3ProposalStateSchema,
    path: phase3CanonicalRelativePathSchema,
    expectedSha256: sha256Schema,
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
    risk: z.enum(phase3RiskValues),
    impact: z.enum(phase3ImpactValues),
    reloadTarget: z.enum(phase3ReloadTargets).nullable(),
    expiresAt: z.string().datetime(),
  })
  .strict()
  .superRefine(assertReloadTargetBinding);

export type Phase3ProposalSnapshot = z.infer<
  typeof phase3ProposalSnapshotSchema
>;

export const phase3ApprovalGrantSchema = z
  .object({
    grantId: z.string().uuid(),
    proposalId: z.string().uuid(),
    proposalStorageSha256: sha256Schema,
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
    operation: z.literal("apply"),
    risk: z.enum(phase3RiskValues),
    impact: z.enum(phase3ImpactValues),
    reloadTarget: z.enum(phase3ReloadTargets).nullable(),
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
  })
  .strict()
  .superRefine((value, context) => {
    if (Date.parse(value.issuedAt) >= Date.parse(value.expiresAt))
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "Grant must expire after issuance",
      });
    assertReloadTargetBinding(value, context);
  });

export type Phase3ApprovalGrant = z.infer<typeof phase3ApprovalGrantSchema>;

export const phase3StructuredFailureSchema = z
  .object({
    stage: z.enum([
      "policy",
      "lock",
      "identity",
      "source",
      "validation",
      "approval",
      "checkpoint",
      "apply",
      "post_validation",
      "reload",
      "verification",
      "rollback",
      "recovery",
    ]),
    code: z.string().min(1).max(80),
    message: z.string().min(1).max(500),
    commitStatus: z.enum(phase3CommitStatuses).optional(),
    observedSha256: sha256Schema.optional(),
    at: z.string().datetime(),
  })
  .strict();

export type Phase3StructuredFailure = z.infer<
  typeof phase3StructuredFailureSchema
>;

export const phase3TransactionRecordSchema = z
  .object({
    schemaVersion: z.literal(2),
    transactionId: z.string().uuid(),
    proposalId: z.string().uuid(),
    proposalStorageSha256: sha256Schema,
    path: phase3CanonicalRelativePathSchema,
    expectedSha256: sha256Schema,
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
    checkpointId: z.string().uuid(),
    checkpointSha256: sha256Schema,
    impact: z.enum(phase3ImpactValues),
    reloadTarget: z.enum(phase3ReloadTargets).nullable(),
    rollbackReloadRequired: z.boolean(),
    state: z.enum(phase3TransactionStates),
    priorState: z.enum(phase3TransactionStates).nullable(),
    version: z.number().int().nonnegative(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    failure: phase3StructuredFailureSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    assertReloadTargetBinding(value, context);
    assertTransactionReloadContext(value, context);
  });

export type Phase3TransactionRecord = z.infer<
  typeof phase3TransactionRecordSchema
>;

export interface Phase3JournalPort {
  createIntent(
    record: Phase3TransactionRecord,
  ): Promise<Phase3TransactionRecord>;
  transition(
    transactionId: string,
    expectedVersion: number,
    state: Phase3TransactionState,
    patch?: Readonly<{
      failure?: Phase3StructuredFailure | null;
      rollbackReloadRequired?: boolean;
    }>,
  ): Promise<Phase3TransactionRecord>;
  load(transactionId: string): Promise<Phase3TransactionRecord | null>;
  listRecoverable(): Promise<readonly Phase3TransactionRecord[]>;
}

export const phase3JournalContract = deepFreeze({
  schemaVersion: 2,
  durability:
    "create-intent and every transition are durable compare-and-swap writes",
  versioning: "version increments exactly once per accepted transition",
  reconciliation:
    "exact transaction reads permit bounded compare-and-swap conflict reconciliation without weakening immutable identity",
  identity:
    "transactionId, proposalId, proposalStorageSha256, path, expectedSha256, candidateSha256, diffSha256, checkpointId, checkpointSha256, impact, and reloadTarget are immutable",
  rollbackReloadRequired:
    "rollbackReloadRequired starts false and can only change false-to-true on rollback_intent; it is not immutable identity",
  commitPoint:
    "AtomicApplyPort.replace reaches the live commit point only at atomic rename; commit_unknown is treated as possibly committed",
  transitionOrdering: [
    "intent_prepared before apply",
    "apply_committed before post-commit validation/reload/verification",
    "rollback_intent before checkpoint restore or checkpoint-already-live recovery completion",
    "rollback_committed before rollback validation/verification",
  ] as const,
  legalTransitions: phase3LegalTransitions,
});

export type RecoveryDigestCase =
  | "expected_or_checkpoint"
  | "candidate"
  | "other_or_missing";

export const phase3RecoveryDispositions = deepFreeze([
  "verified",
  "rolled_back",
  "manual_attention_required",
] as const);

export type Phase3RecoveryDisposition =
  (typeof phase3RecoveryDispositions)[number];

export interface Phase3RecoveryResult {
  readonly transactionId: string;
  readonly terminalState: Phase3TransactionState;
  readonly observedDigest: RecoveryDigestCase;
  readonly observedSha256: string | null;
  readonly disposition: Phase3RecoveryDisposition;
  readonly manualAttentionRequired: boolean;
  readonly record: Phase3TransactionRecord;
}

export const phase3RecoveryTable = deepFreeze({
  intent_prepared: {
    expected_or_checkpoint: "rolled_back_no_live_effect",
    candidate: "rollback",
    other_or_missing: "manual_recovery_required",
  },
  apply_committed: {
    candidate: "rollback",
    expected_or_checkpoint: "complete_rollback_validation_verification",
    other_or_missing: "manual_recovery_required",
  },
  post_validation_succeeded: {
    candidate: "rollback",
    expected_or_checkpoint: "complete_rollback_validation_verification",
    other_or_missing: "manual_recovery_required",
  },
  reload_intent: {
    candidate: "rollback_with_reload_required",
    expected_or_checkpoint: "complete_rollback_validation_reload_verification",
    other_or_missing: "manual_recovery_required",
  },
  reload_succeeded: {
    candidate: "rollback_with_reload_required",
    expected_or_checkpoint: "complete_rollback_validation_reload_verification",
    other_or_missing: "manual_recovery_required",
  },
  rollback_intent: {
    candidate: "rollback",
    expected_or_checkpoint: "complete_rollback_validation_verification",
    other_or_missing: "manual_recovery_required",
  },
  rollback_committed: {
    candidate: "manual_recovery_required",
    expected_or_checkpoint: "complete_rollback_validation_verification",
    other_or_missing: "manual_recovery_required",
  },
  rollback_validation_succeeded: {
    candidate: "manual_recovery_required",
    expected_or_checkpoint: "complete_rollback_reload_or_verification",
    other_or_missing: "manual_recovery_required",
  },
  rollback_reload_intent: {
    candidate: "manual_recovery_required",
    expected_or_checkpoint: "manual_recovery_required",
    other_or_missing: "manual_recovery_required",
  },
  rollback_reload_succeeded: {
    candidate: "manual_recovery_required",
    expected_or_checkpoint: "complete_rollback_verification",
    other_or_missing: "manual_recovery_required",
  },
  verification_succeeded: {
    candidate: "verified_no_effect",
    expected_or_checkpoint: "external_manual_required_no_transition",
    other_or_missing: "external_manual_required_no_transition",
  },
  rollback_verification_succeeded: {
    candidate: "external_manual_required_no_transition",
    expected_or_checkpoint: "rolled_back_no_effect",
    other_or_missing: "external_manual_required_no_transition",
  },
  manual_recovery_required: { any: "no_effect" },
} as const);

export const phase3Contract = deepFreeze({
  registered: false,
  adapterNeutral: true,
  writesEnabled: false,
  grantProducer: "absent" as const,
  cli: "absent" as const,
  mcpTools: "absent" as const,
  liveAdapters: "absent" as const,
  lockScope: "validated-canonical-relative-path" as const,
  restartPolicy: "never-restart" as const,
});

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function sha256(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function assertPhase3TransactionRecord(
  value: unknown,
): Phase3TransactionRecord {
  return phase3TransactionRecordSchema.parse(value);
}

function assertTransactionReloadContext(
  value: Phase3TransactionRecord,
  context: z.RefinementCtx,
): void {
  if (recordReloadContextIsLegal(value)) return;
  context.addIssue({
    code: z.ZodIssueCode.custom,
    path: ["state"],
    message:
      "Transaction reload state is inconsistent with durable reload context",
  });
}

function recordReloadContextIsLegal(
  value: Pick<
    Phase3TransactionRecord,
    "priorState" | "state" | "reloadTarget" | "rollbackReloadRequired"
  >,
): boolean {
  if (value.rollbackReloadRequired && value.reloadTarget === null) return false;
  if (value.state === "reload_intent") return value.reloadTarget !== null;
  if (
    value.state === "rollback_reload_intent" ||
    value.state === "rollback_reload_succeeded"
  )
    return value.rollbackReloadRequired && value.reloadTarget !== null;
  if (
    value.priorState === "post_validation_succeeded" &&
    value.state === "reload_succeeded"
  )
    return value.reloadTarget === null;
  if (
    value.priorState === "rollback_validation_succeeded" &&
    value.state === "rollback_verification_succeeded"
  )
    return !value.rollbackReloadRequired;
  return true;
}

function assertReloadTargetBinding(
  value: {
    readonly impact: Phase3Impact;
    readonly reloadTarget: Phase3ReloadTarget | null;
  },
  context: z.RefinementCtx,
): void {
  if (value.impact === "domain_reload") {
    if (value.reloadTarget === null)
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reloadTarget"],
        message: "Domain reload impact requires an explicit reload target",
      });
    return;
  }
  if (value.reloadTarget !== null)
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["reloadTarget"],
      message: "Reload target is only valid for domain reload impact",
    });
}
