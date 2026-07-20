import {
  phase3ApprovalGrantSchema,
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
    assertNotCancelled(context);
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
    if (proposal.state !== "pending")
      throw new Phase3ApprovalError(
        "proposal_not_pending",
        "Approval requires an exact pending proposal",
      );
    if (context.now >= Date.parse(proposal.expiresAt))
      throw new Phase3ApprovalError(
        "proposal_expired",
        "Proposal is expired at approval time",
      );
    if (context.now < Date.parse(grant.issuedAt))
      throw new Phase3ApprovalError(
        "approval_not_yet_valid",
        "Approval grant is not valid before its issuance time",
      );
    if (context.now >= Date.parse(grant.expiresAt))
      throw new Phase3ApprovalError(
        "approval_expired",
        "Approval grant is expired at the boundary",
      );
    if (
      grant.proposalId !== proposal.proposalId ||
      grant.proposalStorageSha256 !== proposal.proposalStorageSha256 ||
      grant.candidateSha256 !== proposal.candidateSha256 ||
      grant.diffSha256 !== proposal.diffSha256 ||
      grant.operation !== "apply" ||
      grant.risk !== proposal.risk
    )
      throw new Phase3ApprovalError(
        "approval_wrong_binding",
        "Approval grant does not bind the exact proposal identity",
      );
    assertNotCancelled(context);
    this.consumed.add(grantId);
    return grant;
  }
}

function assertNotCancelled(context: Phase3ApprovalContext): void {
  if (context.signal.aborted)
    throw new Phase3ApprovalError(
      "approval_cancelled",
      "Approval consumption was cancelled before commit",
    );
}
