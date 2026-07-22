import { describe, expect, it } from "vitest";
import {
  InjectedApprovalGrantPort,
  Phase3ApprovalError,
} from "../src/phase3/approval.js";
import {
  sha256,
  type Phase3ProposalSnapshot,
} from "../src/phase3/contracts.js";

const now = Date.parse("2026-07-20T00:00:30.000Z");
const proposal: Phase3ProposalSnapshot = {
  proposalId: "11111111-1111-4111-8111-111111111111",
  proposalStorageSha256: sha256("proposal"),
  state: "pending",
  path: "automations/lights.yaml",
  expectedSha256: sha256("old"),
  candidateSha256: sha256("new"),
  diffSha256: sha256("diff"),
  risk: "high",
  impact: "domain_reload",
  reloadTarget: "automation.reload",
  expiresAt: "2026-07-20T00:02:00.000Z",
};

const grant = {
  grantId: "22222222-2222-4222-8222-222222222222",
  proposalId: proposal.proposalId,
  proposalStorageSha256: proposal.proposalStorageSha256,
  candidateSha256: proposal.candidateSha256,
  diffSha256: proposal.diffSha256,
  operation: "apply",
  risk: proposal.risk,
  impact: proposal.impact,
  reloadTarget: proposal.reloadTarget,
  issuedAt: "2026-07-20T00:00:00.000Z",
  expiresAt: "2026-07-20T00:01:00.000Z",
};

describe("Phase 3A injected approval grants", () => {
  it("atomically consumes an exact grant once", async () => {
    const port = new InjectedApprovalGrantPort([grant]);
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now,
        signal: new AbortController().signal,
      }),
    ).resolves.toMatchObject({ grantId: grant.grantId });
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now,
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "approval_replayed" });
  });

  it("fails closed for expiry boundary and wrong binding", async () => {
    const port = new InjectedApprovalGrantPort([grant]);
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now: Date.parse(grant.expiresAt),
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ code: "approval_expired" });
    await expect(
      port.consumeApplyGrant(
        grant.grantId,
        { ...proposal, proposalStorageSha256: sha256("drift") },
        { now, signal: new AbortController().signal },
      ),
    ).rejects.toMatchObject({ code: "approval_wrong_binding" });
  });

  it("rejects the same impact bound to a different closed reload target", async () => {
    const port = new InjectedApprovalGrantPort([grant]);
    await expect(
      port.consumeApplyGrant(
        grant.grantId,
        { ...proposal, reloadTarget: "script.reload" },
        { now, signal: new AbortController().signal },
      ),
    ).rejects.toMatchObject({ code: "approval_wrong_binding" });
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now,
        signal: new AbortController().signal,
      }),
    ).resolves.toMatchObject({ grantId: grant.grantId });
  });
  it("enforces the complete issuance and expiry window without consuming early attempts", async () => {
    const port = new InjectedApprovalGrantPort([grant]);
    const signal = new AbortController().signal;
    const issuedAt = Date.parse(grant.issuedAt);
    const expiresAt = Date.parse(grant.expiresAt);
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt - 1,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_not_yet_valid" });
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now: issuedAt,
        signal,
      }),
    ).resolves.toMatchObject({ grantId: grant.grantId });

    const nearExpiry = new InjectedApprovalGrantPort([grant]);
    await expect(
      nearExpiry.consumeApplyGrant(grant.grantId, proposal, {
        now: expiresAt - 1,
        signal,
      }),
    ).resolves.toMatchObject({ grantId: grant.grantId });

    const expired = new InjectedApprovalGrantPort([grant]);
    await expect(
      expired.consumeApplyGrant(grant.grantId, proposal, {
        now: expiresAt,
        signal,
      }),
    ).rejects.toMatchObject({ code: "approval_expired" });
  });
  it("requires pending proposal identity and honors precommit cancellation", async () => {
    const port = new InjectedApprovalGrantPort([grant]);
    await expect(
      port.consumeApplyGrant(
        grant.grantId,
        { ...proposal, state: "discarded" },
        { now, signal: new AbortController().signal },
      ),
    ).rejects.toMatchObject({ code: "proposal_not_pending" });
    const controller = new AbortController();
    controller.abort();
    await expect(
      port.consumeApplyGrant(grant.grantId, proposal, {
        now,
        signal: controller.signal,
      }),
    ).rejects.toBeInstanceOf(Phase3ApprovalError);
  });
});
