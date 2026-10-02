import { PassThrough } from "node:stream";
import type { ReadStream, WriteStream } from "node:tty";
import { describe, expect, it, vi } from "vitest";
import type { StoredProposal } from "../src/proposals/storage.js";
import {
  sha256,
  type Phase3ProposalSnapshot,
  type Phase3TransactionRecord,
} from "../src/phase3/contracts.js";
import {
  approveAndApplyProposal,
  createPhase3OperatorTerminal,
  type Phase3OperatorApprovalPorts,
  type Phase3OperatorAuditRecord,
} from "../src/phase3/operatorApproval.js";

const proposalId = "11111111-1111-4111-8111-111111111111";
const grantId = "22222222-2222-4222-8222-222222222222";
function context() {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 10000,
  };
}
function fixture() {
  const proposal: Phase3ProposalSnapshot = {
    proposalId,
    proposalStorageSha256: sha256("stored"),
    state: "pending",
    path: "automations.yaml",
    expectedSha256: sha256("old"),
    candidateSha256: sha256("new"),
    diffSha256: sha256("diff"),
    risk: "high",
    impact: "domain_reload",
    reloadTarget: "automation.reload",
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  };
  const records: Phase3OperatorAuditRecord[] = [];
  const write = vi.fn(async (_text: string) => {});
  const issue = vi.fn(async () => ({
    grantId,
    proposalId,
    proposalStorageSha256: proposal.proposalStorageSha256,
    candidateSha256: proposal.candidateSha256,
    diffSha256: proposal.diffSha256,
    risk: proposal.risk,
    impact: proposal.impact,
    reloadTarget: proposal.reloadTarget,
    operation: "apply" as const,
    issuedAt: new Date().toISOString(),
    expiresAt: proposal.expiresAt,
  }));
  const apply = vi.fn(
    async () =>
      ({
        transactionId: grantId,
        state: "verification_succeeded",
        approvalGrantId: grantId,
      }) as Phase3TransactionRecord,
  );
  const ports: Phase3OperatorApprovalPorts = {
    terminal: {
      inputIsTTY: true,
      outputIsTTY: true,
      write,
      readConfirmation: async () =>
        `APPLY ${proposalId} ${proposal.proposalStorageSha256}`,
    },
    proposals: { load: async () => ({ ...proposal }) },
    store: {
      readExact: async () =>
        ({
          storageSha256: proposal.proposalStorageSha256,
          public: {
            redactedDiff:
              "- old\n+ new\u001b[2J\u202e\t\u2028\u2029\nsecret-value",
          },
        }) as StoredProposal,
    },
    registry: {
      assertFresh: async () => {},
      redactWholeText: (text) => text.replace("secret-value", "[REDACTED]"),
    },
    approvals: { issueApplyGrant: issue },
    coordinator: { apply },
    audit: {
      append: async (record) => {
        records.push(record);
      },
    },
  };
  return { proposal, ports, records, issue, apply, write };
}

describe("local Phase 3 human approval", () => {
  it("displays exact identity and sanitized redacted diff, then issues and applies internally", async () => {
    const f = fixture();
    const result = await approveAndApplyProposal(
      proposalId,
      f.ports,
      context(),
    );
    expect(result.state).toBe("verification_succeeded");
    const shown = f.write.mock.calls[0]![0];
    expect(shown).toContain(f.proposal.candidateSha256);
    expect(shown).toContain(f.proposal.diffSha256);
    expect(shown).toContain("\\u001b[2J\\u202e");
    expect(shown).not.toContain("secret-value");
    expect(shown).toContain("\\u0009\\u2028\\u2029");
    expect(f.apply).toHaveBeenCalledWith(
      { proposalId, grantId },
      expect.anything(),
    );
    expect(f.records.map((record) => record.event)).toEqual([
      "attempt",
      "displayed",
      "confirmed",
      "grant_issued",
      "settled",
    ]);
    expect(JSON.stringify(f.records)).not.toContain("new\\u001b");
  });
  it.each(["inputIsTTY", "outputIsTTY"] as const)(
    "rejects a noninteractive %s before any approval/effect",
    async (field) => {
      const f = fixture();
      await expect(
        approveAndApplyProposal(
          proposalId,
          { ...f.ports, terminal: { ...f.ports.terminal, [field]: false } },
          context(),
        ),
      ).rejects.toMatchObject({ code: "interactive_terminal_required" });
      expect(f.records).toEqual([]);
      expect(f.issue).not.toHaveBeenCalled();
    },
  );
  it.each([
    "yes",
    "",
    "APPLY",
    `APPLY ${proposalId} wrong`,
    ` APPLY ${proposalId} ${sha256("stored")}`,
  ])("rejects incorrect typed confirmation %s", async (answer) => {
    const f = fixture();
    f.ports.terminal.readConfirmation = async () => answer;
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toMatchObject({ code: "confirmation_rejected" });
    expect(f.issue).not.toHaveBeenCalled();
    expect(f.apply).not.toHaveBeenCalled();
  });
  it.each(["identity", "diff", "secrets"])(
    "rejects %s drift between display and confirmation",
    async (kind) => {
      const f = fixture();
      f.ports.terminal.readConfirmation = async () => {
        const answer = `APPLY ${proposalId} ${f.proposal.proposalStorageSha256}`;
        if (kind === "identity")
          f.proposal.proposalStorageSha256 = sha256("changed");
        if (kind === "diff")
          f.ports.store.readExact = async () =>
            ({
              storageSha256: f.proposal.proposalStorageSha256,
              public: { redactedDiff: "different" },
            }) as StoredProposal;
        if (kind === "secrets")
          f.ports.registry.redactWholeText = () => "[REDACTED]";
        return answer;
      };
      await expect(
        approveAndApplyProposal(proposalId, f.ports, context()),
      ).rejects.toMatchObject({ code: "proposal_changed_after_display" });
      expect(f.issue).not.toHaveBeenCalled();
    },
  );
  it("refuses expired/unsupported proposals and oversized display", async () => {
    const f = fixture();
    f.proposal.expiresAt = new Date(0).toISOString();
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toMatchObject({ code: "proposal_unavailable" });
    f.proposal.expiresAt = new Date(Date.now() + 60000).toISOString();
    f.proposal.path = "scripts.yaml";
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toMatchObject({ code: "unsupported_proposal" });
    f.proposal.path = "automations.yaml";
    f.ports.registry.redactWholeText = () => "x".repeat(71000);
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toMatchObject({ code: "display_limit_exceeded" });
    expect(f.issue).not.toHaveBeenCalled();
  });
  it.each(["displayed", "confirmed", "grant_issued"])(
    "fails closed if the %s audit cannot be persisted",
    async (event) => {
      const f = fixture();
      f.ports.audit.append = async (record) => {
        if (record.event === event) throw new Error("audit unavailable");
      };
      await expect(
        approveAndApplyProposal(proposalId, f.ports, context()),
      ).rejects.toThrow("audit unavailable");
      expect(f.apply).not.toHaveBeenCalled();
      if (event !== "grant_issued") expect(f.issue).not.toHaveBeenCalled();
    },
  );
  it("does not retry an apply when final audit fails", async () => {
    const f = fixture();
    f.ports.audit.append = async (record) => {
      if (record.event === "settled") throw new Error("audit unavailable");
      f.records.push(record);
    };
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toMatchObject({
      code: "post_settlement_audit_uncertain",
      transactionId: grantId,
      state: "verification_succeeded",
    });
    expect(f.apply).toHaveBeenCalledTimes(1);
    expect(f.records.at(-1)).toMatchObject({
      event: "audit_uncertain",
      transactionId: grantId,
      state: "verification_succeeded",
    });
    expect(f.records.some((record) => record.event === "failed")).toBe(false);
  });

  it("records an attempted review when protected loading fails", async () => {
    const f = fixture();
    f.ports.proposals.load = async () => {
      throw new Error("unavailable");
    };
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toThrow("unavailable");
    expect(f.records.map((record) => record.event)).toEqual([
      "attempt",
      "failed",
    ]);
    expect(f.records[0]?.proposalStorageSha256).toBeUndefined();
    expect(f.issue).not.toHaveBeenCalled();
  });
  it("does not claim displayed evidence when terminal writing fails", async () => {
    const f = fixture();
    f.ports.terminal.write = async () => {
      throw new Error("terminal failure");
    };
    await expect(
      approveAndApplyProposal(proposalId, f.ports, context()),
    ).rejects.toThrow("terminal failure");
    expect(f.records.map((record) => record.event)).toEqual([
      "attempt",
      "failed",
    ]);
    expect(f.issue).not.toHaveBeenCalled();
  });
  it("checks cancellation after confirmation before grant issuance", async () => {
    const f = fixture();
    const controller = new AbortController();
    f.ports.terminal.readConfirmation = async () => {
      controller.abort();
      return `APPLY ${proposalId} ${f.proposal.proposalStorageSha256}`;
    };
    await expect(
      approveAndApplyProposal(proposalId, f.ports, {
        ...context(),
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: "operation_inactive" });
    expect(f.issue).not.toHaveBeenCalled();
  });
});

describe("inherited TTY confirmation input", () => {
  function terminal() {
    const input = new PassThrough();
    const output = new PassThrough();
    Object.assign(input, { isTTY: true });
    Object.assign(output, { isTTY: true });
    return {
      input,
      terminal: createPhase3OperatorTerminal(
        input as unknown as ReadStream,
        output as unknown as WriteStream,
      ),
    };
  }
  it("accepts a single line and detaches handlers", async () => {
    const t = terminal();
    const answer = t.terminal.readConfirmation(context());
    t.input.write("APPLY test\r\n");
    expect(await answer).toBe("APPLY test");
    expect(t.input.listenerCount("data")).toBe(0);
  });
  it.each(["x".repeat(257), "first\nsecond\n"])(
    "rejects bounded/multiple-line input",
    async (input) => {
      const t = terminal();
      const answer = t.terminal.readConfirmation(context());
      t.input.write(input);
      await expect(answer).rejects.toThrow();
      expect(t.input.listenerCount("data")).toBe(0);
    },
  );
  it("times out and detaches handlers", async () => {
    const t = terminal();
    await expect(
      t.terminal.readConfirmation({
        ...context(),
        deadlineAt: Date.now() + 10,
      }),
    ).rejects.toMatchObject({ code: "operation_inactive" });
    expect(t.input.listenerCount("data")).toBe(0);
  });
});
