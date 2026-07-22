import {
  phase3ApprovalGrantSchema,
  phase3ProposalSnapshotSchema,
  type Phase3ApprovalGrant,
  type Phase3ProposalSnapshot,
} from "./contracts.js";

export type Phase3ApprovalErrorCode =
  | "approval_cancelled"
  | "approval_not_found"
  | "approval_replayed"
  | "approval_not_yet_valid"
  | "approval_expired"
  | "approval_wrong_binding"
  | "approval_store_unhealthy"
  | "approval_commit_unknown"
  | "approval_capacity_exhausted"
  | "proposal_not_pending"
  | "proposal_expired";

export class Phase3ApprovalError extends Error {
  constructor(
    public readonly code: Phase3ApprovalErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Phase3ApprovalError";
  }
}

export interface Phase3ApprovalContext {
  readonly now: number;
  readonly signal: AbortSignal;
}

export interface Phase3ApprovalPort {
  consumeApplyGrant(
    grantId: string,
    proposal: Phase3ProposalSnapshot,
    context: Phase3ApprovalContext,
  ): Promise<Phase3ApprovalGrant>;
}

export interface Phase3ApprovalActiveContext {
  readonly signal: AbortSignal;
}

export class InjectedApprovalGrantPort implements Phase3ApprovalPort {
  private readonly grants = new Map<string, Phase3ApprovalGrant>();
  private readonly consumed = new Set<string>();

  constructor(grants: readonly unknown[]) {
    for (const grant of grants) {
      const parsed = phase3ApprovalGrantSchema.parse(grant);
      if (this.grants.has(parsed.grantId))
        throw new Phase3ApprovalError(
          "approval_wrong_binding",
          "Duplicate injected approval grant",
        );
      this.grants.set(parsed.grantId, Object.freeze(parsed));
    }
  }

  async consumeApplyGrant(
    grantId: string,
    proposal: Phase3ProposalSnapshot,
    context: Phase3ApprovalContext,
  ): Promise<Phase3ApprovalGrant> {
    await Promise.resolve();
    const active = assertPhase3ApprovalNotCancelled(context);
    const grant = this.grants.get(grantId);
    if (!grant)
      throw new Phase3ApprovalError(
        "approval_not_found",
        "Approval grant was not injected",
      );
    if (this.consumed.has(grantId))
      throw new Phase3ApprovalError(
        "approval_replayed",
        "Approval grant has already been consumed",
      );
    validatePhase3ApplyGrant(grant, proposal, context, active);
    this.consumed.add(grantId);
    return grant;
  }
}

export function assertPhase3ApprovalNotCancelled(
  context: Phase3ApprovalContext,
): Phase3ApprovalActiveContext {
  const signal = approvalSignal(context);
  if (intrinsicAborted(signal))
    throw new Phase3ApprovalError(
      "approval_cancelled",
      "Approval consumption was cancelled before commit",
    );
  return Object.freeze({ signal });
}

export function validatePhase3ApprovalProposal(
  proposal: Phase3ProposalSnapshot,
  context: Phase3ApprovalContext,
): Readonly<{ proposal: Phase3ProposalSnapshot; now: number }> {
  let parsed: ReturnType<typeof phase3ProposalSnapshotSchema.safeParse>;
  try {
    parsed = phase3ProposalSnapshotSchema.safeParse(proposal);
  } catch {
    throw proposalNotPending();
  }
  if (!parsed.success || parsed.data.state !== "pending")
    throw proposalNotPending();
  const now = approvalNow(context);
  const proposalExpiry = Date.parse(parsed.data.expiresAt);
  if (!Number.isSafeInteger(proposalExpiry)) throw wrongBinding();
  if (now >= proposalExpiry)
    throw new Phase3ApprovalError(
      "proposal_expired",
      "Proposal is expired at approval time",
    );
  return Object.freeze({ proposal: Object.freeze(parsed.data), now });
}

export function validatePhase3ApplyGrant(
  grant: Phase3ApprovalGrant,
  proposal: Phase3ProposalSnapshot,
  context: Phase3ApprovalContext,
  active: Phase3ApprovalActiveContext,
): Phase3ProposalSnapshot {
  const validated = validatePhase3ApprovalProposal(proposal, context);
  const parsed = phase3ApprovalGrantSchema.safeParse(grant);
  if (!parsed.success) throw wrongBinding();
  const issuedAt = Date.parse(parsed.data.issuedAt);
  const expiresAt = Date.parse(parsed.data.expiresAt);
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt))
    throw wrongBinding();
  if (validated.now < issuedAt)
    throw new Phase3ApprovalError(
      "approval_not_yet_valid",
      "Approval grant is not valid before its issuance time",
    );
  if (validated.now >= expiresAt)
    throw new Phase3ApprovalError(
      "approval_expired",
      "Approval grant is expired at the boundary",
    );
  if (
    parsed.data.proposalId !== validated.proposal.proposalId ||
    parsed.data.proposalStorageSha256 !==
      validated.proposal.proposalStorageSha256 ||
    parsed.data.candidateSha256 !== validated.proposal.candidateSha256 ||
    parsed.data.diffSha256 !== validated.proposal.diffSha256 ||
    parsed.data.operation !== "apply" ||
    parsed.data.risk !== validated.proposal.risk ||
    parsed.data.impact !== validated.proposal.impact ||
    parsed.data.reloadTarget !== validated.proposal.reloadTarget
  )
    throw wrongBinding();
  if (intrinsicAborted(active.signal))
    throw new Phase3ApprovalError(
      "approval_cancelled",
      "Approval consumption was cancelled before commit",
    );
  return validated.proposal;
}

function approvalNow(context: Phase3ApprovalContext): number {
  try {
    const now = context.now;
    if (!Number.isSafeInteger(now)) throw new Error("invalid");
    return now;
  } catch {
    throw unhealthyContext();
  }
}

function approvalSignal(context: Phase3ApprovalContext): AbortSignal {
  try {
    const signal = context.signal;
    if (!isIntrinsicBrandCompatibleUnshadowedAbortSignal(signal))
      throw new Error("invalid");
    return signal;
  } catch {
    throw unhealthyContext();
  }
}

function isIntrinsicBrandCompatibleUnshadowedAbortSignal(
  value: unknown,
): value is AbortSignal {
  if (typeof value !== "object" || value === null) return false;
  try {
    if (Reflect.getOwnPropertyDescriptor(value, "aborted") !== undefined)
      return false;
    Reflect.get(AbortSignal.prototype, "aborted", value);
    return true;
  } catch {
    return false;
  }
}

function intrinsicAborted(signal: AbortSignal): boolean {
  try {
    return Reflect.get(AbortSignal.prototype, "aborted", signal) === true;
  } catch {
    throw unhealthyContext();
  }
}

function unhealthyContext(): Phase3ApprovalError {
  return new Phase3ApprovalError(
    "approval_store_unhealthy",
    "Approval context failed closed",
  );
}

function wrongBinding(): Phase3ApprovalError {
  return new Phase3ApprovalError(
    "approval_wrong_binding",
    "Approval grant does not bind the exact proposal identity",
  );
}

function proposalNotPending(): Phase3ApprovalError {
  return new Phase3ApprovalError(
    "proposal_not_pending",
    "Approval requires an exact pending proposal",
  );
}
