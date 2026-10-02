import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  approveAndRecoverPhase3,
  type Phase3OperatorRecoveryPorts,
} from "../src/phase3/operatorRecovery.js";
import {
  canonicalJson,
  sha256,
  type Phase3RecoveryResult,
  type Phase3TransactionRecord,
} from "../src/phase3/contracts.js";
import { Phase3OperatorAudit } from "../src/phase3/operatorAudit.js";
import type { Phase3OperatorAuditRecord } from "../src/phase3/operatorApproval.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
const transactionId = "11111111-1111-4111-8111-111111111111";
function context() {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 10000,
  };
}
function fixture(empty = false) {
  const record: Phase3TransactionRecord = {
    schemaVersion: 2,
    transactionId,
    proposalId: "22222222-2222-4222-8222-222222222222",
    proposalStorageSha256: sha256("storage"),
    path: "automations.yaml",
    expectedSha256: sha256("old"),
    candidateSha256: sha256("new"),
    diffSha256: sha256("diff"),
    checkpointId: "33333333-3333-4333-8333-333333333333",
    checkpointSha256: sha256("old"),
    impact: "domain_reload",
    reloadTarget: "automation.reload",
    rollbackReloadRequired: false,
    state: "intent_prepared",
    priorState: null,
    version: 0,
    createdAt: "2026-10-02T00:00:00.000Z",
    updatedAt: "2026-10-02T00:00:00.000Z",
    failure: null,
  };
  const records: Phase3OperatorAuditRecord[] = [];
  const order: string[] = [];
  const result: Phase3RecoveryResult = {
    transactionId,
    terminalState: "rollback_verification_succeeded",
    observedDigest: "expected_or_checkpoint",
    observedSha256: record.checkpointSha256,
    disposition: "rolled_back",
    manualAttentionRequired: false,
    record: {
      ...record,
      state: "rollback_verification_succeeded",
      version: 4,
      priorState: "rollback_validation_succeeded",
    },
  };
  const recover = vi.fn(async () => {
    order.push("recover");
    return empty ? [] : [result];
  });
  const write = vi.fn(async (_text: string) => {
    order.push("write");
  });
  const ports: Phase3OperatorRecoveryPorts = {
    terminal: {
      inputIsTTY: true,
      outputIsTTY: true,
      write,
      readConfirmation: async () => {
        order.push("read");
        return empty
          ? "RECOVER EMPTY"
          : `RECOVER ${transactionId} ${sha256(canonicalJson(record))}`;
      },
    },
    journal: {
      listRecoverable: async () => (empty ? [] : [{ ...record }]),
      load: async () => ({ ...record }),
    },
    coordinator: { recover },
    audit: {
      append: async (row) => {
        records.push(row);
        order.push(row.event);
      },
    },
  };
  return { ports, record, result, recover, records, order, write };
}
describe("human reviewed Phase 3 recovery", () => {
  it("durably audits exact review before dispatch and records actual returned outcome", async () => {
    const f = fixture();
    const root = await mkdtemp(join(tmpdir(), "phase3-recovery-audit-"));
    roots.push(root);
    const path = join(root, "operator.jsonl");
    const audit = new Phase3OperatorAudit(
      path,
      { assertHeld: async () => undefined },
      { privateMode: () => true, syncDirectory: async () => undefined },
    );
    f.ports = { ...f.ports, audit };
    f.recover.mockImplementationOnce(async () => {
      const rows = (await readFile(path, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Phase3OperatorAuditRecord);
      expect(rows.map((row) => row.event)).toEqual([
        "recovery_attempt",
        "recovery_displayed",
        "recovery_confirmed",
      ]);
      expect(rows[2]?.displayedSha256).toBe(sha256(canonicalJson(f.record)));
      return [f.result];
    });
    expect(await approveAndRecoverPhase3(f.ports, context())).toEqual([
      f.result,
    ]);
    const rows = (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Phase3OperatorAuditRecord);
    expect(rows.at(-1)).toMatchObject({
      event: "recovery_settled",
      transactionId,
      state: f.result.record.state,
      proposalId: f.record.proposalId,
      proposalStorageSha256: f.record.proposalStorageSha256,
    });
    expect(f.recover).toHaveBeenCalledTimes(1);
  });
  it("uses exact empty confirmation and keeps displayed after terminal write", async () => {
    const f = fixture(true);
    expect(await approveAndRecoverPhase3(f.ports, context())).toEqual([]);
    expect(f.order).toEqual([
      "recovery_attempt",
      "write",
      "recovery_displayed",
      "read",
      "recovery_confirmed",
      "recover",
      "recovery_settled",
    ]);
    expect(f.write.mock.calls[0]?.[0]).toContain("RECOVER EMPTY");
  });
  it.each(["inputIsTTY", "outputIsTTY"] as const)(
    "refuses noninteractive %s before journal/audit/effects",
    async (field) => {
      const f = fixture();
      f.ports = {
        ...f.ports,
        terminal: { ...f.ports.terminal, [field]: false },
      };
      await expect(
        approveAndRecoverPhase3(f.ports, context()),
      ).rejects.toMatchObject({ code: "interactive_terminal_required" });
      expect(f.records).toEqual([]);
      expect(f.recover).not.toHaveBeenCalled();
    },
  );
  it("audits an attempt before failed journal discovery and sanitizes upstream errors", async () => {
    const f = fixture();
    f.ports = {
      ...f.ports,
      journal: {
        ...f.ports.journal,
        listRecoverable: async () => {
          expect(f.records[0]?.event).toBe("recovery_attempt");
          throw new Error("upstream secret-token");
        },
      },
    };
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({ code: "recovery_failed" });
    expect(f.records.map((row) => row.event)).toEqual([
      "recovery_attempt",
      "recovery_failed",
    ]);
    expect(f.recover).not.toHaveBeenCalled();
  });
  it.each([
    "wrong",
    "oversize",
    "cancel",
    "drift",
    "load_drift",
    "multiple",
  ] as const)("refuses %s before effects", async (kind) => {
    const f = fixture();
    const controller = new AbortController();
    const ctx = { ...context(), signal: controller.signal };
    if (kind === "multiple")
      f.ports = {
        ...f.ports,
        journal: {
          ...f.ports.journal,
          listRecoverable: async () => [
            f.record,
            { ...f.record, transactionId: f.record.proposalId },
          ],
        },
      };
    const original = f.ports.terminal.readConfirmation.bind(f.ports.terminal);
    f.ports = {
      ...f.ports,
      terminal: {
        ...f.ports.terminal,
        readConfirmation: async (active) => {
          const correct = await original(active);
          if (kind === "wrong") return "RECOVER";
          if (kind === "oversize") return "x".repeat(257);
          if (kind === "cancel") controller.abort();
          if (kind === "drift") f.record.version += 1;
          if (kind === "load_drift")
            f.ports.journal.load = async () => ({ ...f.record, version: 1 });
          return correct;
        },
      },
    };
    await expect(approveAndRecoverPhase3(f.ports, ctx)).rejects.toThrow();
    expect(f.recover).not.toHaveBeenCalled();
    expect(f.records.at(-1)?.event).toBe("recovery_failed");
  });
  it.each([
    "recovery_attempt",
    "recovery_displayed",
    "recovery_confirmed",
  ] as const)("refuses failed %s audit before dispatch", async (event) => {
    const f = fixture();
    const original = f.ports.audit.append.bind(f.ports.audit);
    f.ports = {
      ...f.ports,
      audit: {
        append: async (row) => {
          if (row.event === event) throw new Error("audit secret");
          await original(row);
        },
      },
    };
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({ code: "recovery_failed" });
    expect(f.recover).not.toHaveBeenCalled();
  });
  it("reports dispatch rejection as uncertain with known identity and no invented terminal state", async () => {
    const f = fixture();
    f.recover.mockRejectedValueOnce(new Error("post-effect secret"));
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({
      code: "recovery_outcome_uncertain",
      transactionId,
    });
    expect(f.recover).toHaveBeenCalledTimes(1);
    expect(f.records.at(-1)).toMatchObject({
      event: "recovery_uncertain",
      transactionId,
    });
    expect(f.records.at(-1)).not.toHaveProperty("state");
    expect(f.records.some((row) => row.event === "recovery_failed")).toBe(
      false,
    );
  });
  it.each([false, true])(
    "reports post-result audit failure as uncertain without retry (empty=%s)",
    async (empty) => {
      const f = fixture(empty);
      const original = f.ports.audit.append.bind(f.ports.audit);
      f.ports = {
        ...f.ports,
        audit: {
          append: async (row) => {
            if (row.event === "recovery_settled")
              throw new Error("audit secret");
            await original(row);
          },
        },
      };
      await expect(
        approveAndRecoverPhase3(f.ports, context()),
      ).rejects.toMatchObject({
        code: empty
          ? "recovery_outcome_uncertain"
          : "post_settlement_audit_uncertain",
        ...(!empty ? { transactionId, state: f.result.record.state } : {}),
      });
      expect(f.records.at(-1)?.event).toBe("recovery_uncertain");
      expect(f.recover).toHaveBeenCalledTimes(1);
    },
  );
  it("escapes bidi/C1 terminal controls and never displays freeform failure contents", async () => {
    const f = fixture();
    f.record.path = "automations\u202e\u0085.yaml";
    f.record.failure = {
      stage: "recovery",
      code: "private-secret-code",
      message: "private-secret\u001b[2J",
      at: new Date().toISOString(),
    };
    await approveAndRecoverPhase3(f.ports, context());
    const shown = f.write.mock.calls[0]![0];
    expect(shown).toContain("\\u202e\\u0085");
    expect(shown).not.toContain("private-secret");
    expect(shown).not.toContain("\u202e");
    expect(shown).not.toContain("\u001b");
  });
  it("preserves uncertain dispatch classification even if uncertainty audit fails", async () => {
    const f = fixture();
    f.recover.mockRejectedValueOnce(new Error("private upstream credential"));
    const original = f.ports.audit.append.bind(f.ports.audit);
    f.ports = {
      ...f.ports,
      audit: {
        append: async (row) => {
          if (row.event === "recovery_uncertain")
            throw new Error("private audit credential");
          await original(row);
        },
      },
    };
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({
      code: "recovery_outcome_uncertain",
      transactionId,
    });
    expect(f.recover).toHaveBeenCalledTimes(1);
    expect(f.records.some((row) => row.event === "recovery_failed")).toBe(
      false,
    );
  });
  it("refuses to report settlement when recovery returns an unexpected transaction set", async () => {
    const f = fixture();
    f.recover.mockResolvedValueOnce([]);
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({
      code: "recovery_outcome_uncertain",
      transactionId,
    });
    expect(f.records.at(-1)?.event).toBe("recovery_uncertain");
    expect(f.recover).toHaveBeenCalledTimes(1);
  });
  it("sanitizes failure-audit errors and never dispatches without durable attempt evidence", async () => {
    const f = fixture();
    f.ports = {
      ...f.ports,
      audit: {
        append: async () => {
          throw new Error("private audit credential");
        },
      },
    };
    await expect(
      approveAndRecoverPhase3(f.ports, context()),
    ).rejects.toMatchObject({ code: "recovery_audit_failed" });
    expect(f.recover).not.toHaveBeenCalled();
  });
});
