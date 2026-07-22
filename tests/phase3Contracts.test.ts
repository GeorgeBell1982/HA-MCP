import { describe, expect, it } from "vitest";
import {
  phase3ApprovalGrantSchema,
  phase3Contract,
  phase3CanTransition,
  phase3JournalContract,
  phase3LegalTransitions,
  phase3NonTerminalStates,
  phase3RecoveryDispositions,
  phase3RecoveryTable,
  phase3TerminalOutcomes,
  phase3TransactionRecordSchema,
  phase3TransactionStates,
} from "../src/phase3/contracts.js";

const digest = "a".repeat(64);
const proposalId = "11111111-1111-4111-8111-111111111111";
const transactionId = "22222222-2222-4222-8222-222222222222";

/* eslint-disable @typescript-eslint/no-unsafe-call -- These calls must remain invalid for typecheck. */
function assertReadonlyContractTypes(): void {
  // @ts-expect-error Exported state collections are readonly.
  phase3NonTerminalStates.push("intent_prepared");
  // @ts-expect-error Exported transition adjacency arrays are readonly.
  phase3LegalTransitions.apply_committed.push("verification_succeeded");
  // @ts-expect-error Exported safety flags are readonly.
  phase3Contract.writesEnabled = true;
  // @ts-expect-error Exported recovery table rows are readonly.
  phase3RecoveryTable.apply_committed.candidate = "verified_no_effect";
}
/* eslint-enable @typescript-eslint/no-unsafe-call */

void assertReadonlyContractTypes;

describe("Phase 3A contracts", () => {
  it("freezes exact transaction states and terminal outcomes", () => {
    expect(phase3TransactionStates).toEqual([
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
    ]);
    expect(phase3TerminalOutcomes).toEqual({
      verification_succeeded: "verified",
      rollback_verification_succeeded: "rolled_back",
      manual_recovery_required: "blocked",
    });
    expect(Object.isFrozen(phase3TransactionStates)).toBe(true);
    expect(Object.isFrozen(phase3LegalTransitions)).toBe(true);
    expect(Object.isFrozen(phase3LegalTransitions.apply_committed)).toBe(true);
    expect(Object.isFrozen(phase3RecoveryTable)).toBe(true);
    expect(Object.isFrozen(phase3RecoveryTable.apply_committed)).toBe(true);
  });

  it("resists runtime mutation without weakening transition legality", () => {
    expect(() =>
      (
        phase3LegalTransitions.apply_committed as readonly string[] as string[]
      ).push("verification_succeeded"),
    ).toThrow(TypeError);
    expect(() =>
      (phase3TransactionStates as readonly string[] as string[]).push(
        "forged_state",
      ),
    ).toThrow(TypeError);
    expect(() =>
      Object.assign(phase3RecoveryTable.apply_committed, {
        candidate: "verified_no_effect",
      }),
    ).toThrow(TypeError);
    expect(
      phase3CanTransition("apply_committed", "verification_succeeded"),
    ).toBe(false);
    expect(phase3RecoveryTable.apply_committed.candidate).toBe("rollback");
  });

  it("requires strict durable transaction records", () => {
    const record = {
      schemaVersion: 2,
      transactionId,
      proposalId,
      proposalStorageSha256: digest,
      path: "automations/lights.yaml",
      expectedSha256: digest,
      candidateSha256: "b".repeat(64),
      diffSha256: "c".repeat(64),
      checkpointId: "33333333-3333-4333-8333-333333333333",
      checkpointSha256: digest,
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      rollbackReloadRequired: false,
      state: "intent_prepared",
      priorState: null,
      version: 0,
      createdAt: "2026-07-20T00:00:00.000Z",
      updatedAt: "2026-07-20T00:00:00.000Z",
      failure: null,
    };
    expect(phase3TransactionRecordSchema.safeParse(record).success).toBe(true);
    expect(
      phase3TransactionRecordSchema.safeParse({ ...record, state: "prepared" })
        .success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        path: "../bad.yaml",
      }).success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({ ...record, extra: true })
        .success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        impact: "none",
        reloadTarget: null,
        rollbackReloadRequired: true,
      }).success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        state: "reload_succeeded",
        priorState: "post_validation_succeeded",
      }).success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        impact: "none",
        reloadTarget: null,
        state: "reload_intent",
        priorState: "post_validation_succeeded",
      }).success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        state: "rollback_verification_succeeded",
        priorState: "rollback_validation_succeeded",
        rollbackReloadRequired: true,
      }).success,
    ).toBe(false);
    expect(
      phase3TransactionRecordSchema.safeParse({
        ...record,
        state: "rollback_reload_intent",
        priorState: "rollback_validation_succeeded",
        rollbackReloadRequired: false,
      }).success,
    ).toBe(false);
  });

  it("binds approval grants to apply only", () => {
    const grant = {
      grantId: "44444444-4444-4444-8444-444444444444",
      proposalId,
      proposalStorageSha256: digest,
      candidateSha256: "b".repeat(64),
      diffSha256: "c".repeat(64),
      operation: "apply",
      risk: "high",
      impact: "domain_reload",
      reloadTarget: "automation.reload",
      issuedAt: "2026-07-20T00:00:00.000Z",
      expiresAt: "2026-07-20T00:01:00.000Z",
    };
    expect(phase3ApprovalGrantSchema.safeParse(grant).success).toBe(true);
    expect(
      phase3ApprovalGrantSchema.safeParse({ ...grant, operation: "approve" })
        .success,
    ).toBe(false);
    expect(
      phase3ApprovalGrantSchema.safeParse({
        ...grant,
        expiresAt: grant.issuedAt,
      }).success,
    ).toBe(false);
  });

  it("documents CAS journal, commit point, recovery table, and isolation", () => {
    expect(phase3JournalContract.versioning).toContain("version increments");
    expect(phase3JournalContract.commitPoint).toContain("atomic rename");
    expect(phase3JournalContract.legalTransitions).toBe(phase3LegalTransitions);
    expect(phase3LegalTransitions.verification_succeeded).toEqual([]);
    expect(phase3LegalTransitions.rollback_validation_succeeded).toEqual([
      "rollback_reload_intent",
      "rollback_verification_succeeded",
      "manual_recovery_required",
    ]);
    expect(phase3CanTransition("apply_committed", "rollback_intent")).toBe(
      true,
    );
    expect(
      phase3CanTransition(
        "rollback_validation_succeeded",
        "rollback_committed",
      ),
    ).toBe(false);
    expect(phase3RecoveryDispositions).toEqual([
      "verified",
      "rolled_back",
      "manual_attention_required",
    ]);
    expect(phase3RecoveryTable.intent_prepared.candidate).toBe("rollback");
    expect(
      phase3RecoveryTable.verification_succeeded.expected_or_checkpoint,
    ).toBe("external_manual_required_no_transition");
    expect(
      phase3RecoveryTable.rollback_verification_succeeded
        .expected_or_checkpoint,
    ).toBe("rolled_back_no_effect");
    expect(phase3Contract).toMatchObject({
      registered: false,
      writesEnabled: false,
      grantProducer: "absent",
      cli: "absent",
      mcpTools: "absent",
      liveAdapters: "absent",
    });
  });
});
