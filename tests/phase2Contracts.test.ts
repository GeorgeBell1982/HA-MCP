import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ReadTools } from "../src/application.js";
import {
  PHASE2_MAX_TEXT_BYTES,
  phase2AuditAttemptSchema,
  phase2AuditOutcomeSchema,
  phase2Contract,
  phase2ErrorCodes,
  phase2ToolInputSchemas,
  phase2ToolNames,
  phase2ToolOutputSchemas,
  phase2YamlPolicy,
  proposalPublicSchema,
  protectedProposalPayloadSchema,
  resourceIdSchema,
  repositoryCursorSchema,
  repositorySearchQuerySchema,
  repositorySnippetSchema,
  relativeConfigPathSchema,
} from "../src/phase2Contracts.js";

const sha = "a".repeat(64);
const proposalId = "4c43818c-ddfe-47ea-ad13-35fe796b13ce";
const idempotencyKey = "1c43818c-ddfe-47ea-ad13-35fe796b13ce";
const digest = (value: string | Buffer) =>
  createHash("sha256").update(value).digest("hex");

describe("Phase 2 frozen contracts", () => {
  it("freezes the complete activated inventory outside the Phase 1 registry", () => {
    expect(phase2ToolNames).toEqual([
      "ha_list_config_files",
      "ha_read_config_file",
      "ha_search_config",
      "ha_list_config_resources",
      "ha_get_config_resource",
      "ha_get_git_status",
      "ha_get_git_diff",
      "ha_list_proposals",
      "ha_get_pending_diff",
      "ha_propose_config_change",
      "ha_discard_proposed_change",
    ]);
    expect(Object.keys(phase2ToolOutputSchemas)).toEqual(phase2ToolNames);
    const phase1Names = ReadTools.prototype.names.call({});
    expect(phase2ToolNames.every((name) => !phase1Names.includes(name))).toBe(
      true,
    );
    expect(phase2Contract.registered).toBe(true);
    expect(phase2Contract.sourceRoot).toBe("/homeassistant");
  });

  it("rejects non-canonical and platform-ambiguous paths", () => {
    expect(
      relativeConfigPathSchema.safeParse("packages/lights.yaml").success,
    ).toBe(true);
    for (const path of [
      "",
      "/homeassistant/a.yaml",
      "../a.yaml",
      "a/../b.yaml",
      "a\\b.yaml",
      "a//b.yaml",
      "C:/a.yaml",
      "a\u0000.yaml",
      "a\nb.yaml",
      "cafe\u0301.yaml",
    ])
      expect(
        relativeConfigPathSchema.safeParse(path).success,
        JSON.stringify(path),
      ).toBe(false);
  });

  it("requires a YAML whole-document proposal, SHA and idempotency key", () => {
    const schema = phase2ToolInputSchemas.ha_propose_config_change;
    const valid = {
      idempotencyKey,
      path: "automations.yaml",
      expectedSha256: sha,
      proposedContent: "- id: example\n",
    };
    expect(schema.safeParse(valid).success).toBe(true);
    expect(schema.safeParse({ ...valid, path: "notes.txt" }).success).toBe(
      false,
    );
    expect(
      schema.safeParse({ ...valid, idempotencyKey: undefined }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        ...valid,
        proposedContent: "\u00e9".repeat(PHASE2_MAX_TEXT_BYTES / 2 + 1),
      }).success,
    ).toBe(false);
    expect(phase2Contract.proposalInputMode).toBe(
      "existing-yaml-file-whole-document",
    );
    expect(phase2Contract.mutationOfLiveConfig).toBe(false);
    expect(phase2Contract.createsDeletesRenames).toBe(false);
  });

  it("requires proposal identity for pending diff and exposes no caller revisions", () => {
    expect(
      phase2ToolInputSchemas.ha_get_pending_diff.safeParse({}).success,
    ).toBe(false);
    expect(
      phase2ToolInputSchemas.ha_get_pending_diff.safeParse({ proposalId })
        .success,
    ).toBe(true);
    expect(
      phase2ToolInputSchemas.ha_get_git_diff.safeParse({ revision: "HEAD~1" })
        .success,
    ).toBe(false);
    expect(
      phase2ToolInputSchemas.ha_get_git_diff.safeParse({ scope: "both" })
        .success,
    ).toBe(true);
  });

  it("separates and validates protected exact bytes", () => {
    const publicProposal = {
      proposalId,
      idempotencyKey,
      state: "pending",
      path: "automations.yaml",
      expectedSha256: sha,
      candidateSha256: digest(""),
      diffSha256: digest("x"),
      redactedDiff: "@@ redacted @@",
      createdAt: "2026-07-16T00:00:00.000Z",
      expiresAt: "2026-07-17T00:00:00.000Z",
      risk: "high",
      validationPlan: ["parse Home Assistant YAML"],
      reloadImpact: "domain_reload",
      sourceEvidence:
        "Protected /data proposal store and /homeassistant repository snapshot",
    };
    expect(proposalPublicSchema.safeParse(publicProposal).success).toBe(true);
    expect(
      proposalPublicSchema.safeParse({
        ...publicProposal,
        exactCandidateBytesBase64: "eA==",
      }).success,
    ).toBe(false);
    const protectedPayload = {
      schemaVersion: 1,
      proposalId,
      idempotencyKey,
      candidateSha256: digest(""),
      diffSha256: digest("x"),
      encoding: "utf-8",
      exactCandidateBytesBase64: "",
      exactDiffBytesBase64: "eA==",
    };
    expect(
      protectedProposalPayloadSchema.safeParse(protectedPayload).success,
    ).toBe(true);
    expect(
      protectedProposalPayloadSchema.safeParse({
        ...protectedPayload,
        exactCandidateBytesBase64: "not base64",
      }).success,
    ).toBe(false);
    expect(
      protectedProposalPayloadSchema.safeParse({
        ...protectedPayload,
        candidateSha256: "b".repeat(64),
      }).success,
    ).toBe(false);
    const invalidUtf8 = Buffer.from([0xff]);
    expect(
      protectedProposalPayloadSchema.safeParse({
        ...protectedPayload,
        candidateSha256: digest(invalidUtf8),
        exactCandidateBytesBase64: invalidUtf8.toString("base64"),
      }).success,
    ).toBe(false);
    expect(phase2Contract.proposalPayloadClassification).toBe("protected");
  });
  it("freezes strict success and failure output envelopes", () => {
    const requestId = "2c43818c-ddfe-47ea-ad13-35fe796b13ce";
    expect(
      phase2ToolOutputSchemas.ha_get_git_status.safeParse({
        ok: true,
        requestId,
        data: {
          clean: true,
          branch: "main",
          changes: [],
          sourceEvidence: "Git metadata confined to /homeassistant",
        },
        warnings: [],
        evidence: [{ source: "git", observedAt: "2026-07-16T00:00:00.000Z" }],
      }).success,
    ).toBe(true);
    expect(
      phase2ToolOutputSchemas.ha_get_git_status.safeParse({
        ok: true,
        requestId,
        data: {
          clean: true,
          branch: "main",
          changes: [],
          sourceEvidence: "Git metadata confined to /homeassistant",
        },
        warnings: [],
        evidence: [{ source: "git", observedAt: "2026-07-16T00:00:00.000Z" }],
        nextCursor: "forbidden-on-singleton",
      }).success,
    ).toBe(false);
    expect(
      phase2ToolOutputSchemas.ha_list_config_files.safeParse({
        ok: true,
        requestId,
        data: { items: [] },
        warnings: [],
        evidence: [{ source: "files", observedAt: "2026-07-16T00:00:00.000Z" }],
        nextCursor: null,
      }).success,
    ).toBe(true);
    expect(
      phase2ToolOutputSchemas.ha_get_git_status.safeParse({
        ok: false,
        requestId,
        error: {
          code: "repository_unavailable",
          message: "Repository unavailable",
        },
        warnings: [],
        evidence: [],
        leaked: "no",
      }).success,
    ).toBe(false);
  });

  it("freezes YAML and idempotency branch policy", () => {
    expect(phase2YamlPolicy.encoding).toBe("strict-utf8-no-bom-no-nul");
    expect(phase2YamlPolicy.duplicateKeys).toBe("reject");
    expect(phase2YamlPolicy.unknownTags).toBe("reject");
    expect(phase2YamlPolicy.mergeKeys).toBe("reject");
    expect(phase2YamlPolicy.reserialization).toBe("prohibited");
    expect(phase2Contract.idempotency.identity).toEqual([
      "path",
      "expectedSha256",
      "candidateSha256",
    ]);
    expect(phase2Contract.idempotency.sameKeyDifferentIdentity).toBe(
      "proposal_conflict",
    );
  });

  it("freezes redacted two-phase audit records and recovery semantics", () => {
    const base = {
      schemaVersion: 2,
      timestamp: "2026-07-16T00:00:00.000Z",
      requestId: "2c43818c-ddfe-47ea-ad13-35fe796b13ce",
      operationId: "3c43818c-ddfe-47ea-ad13-35fe796b13ce",
      tool: "ha_read_config_file",
    };
    expect(
      phase2AuditAttemptSchema.safeParse({
        ...base,
        phase: "attempt",
        risk: "read-only",
        target: { kind: "path", path: "configuration.yaml" },
      }).success,
    ).toBe(true);
    expect(
      phase2AuditAttemptSchema.safeParse({
        ...base,
        phase: "attempt",
        risk: "read-only",
        target: { kind: "path", path: "configuration.yaml" },
        content: "secret",
      }).success,
    ).toBe(false);
    expect(
      phase2AuditOutcomeSchema.safeParse({
        ...base,
        tool: "ha_propose_config_change",
        phase: "outcome",
        result: "committed_response_unconfirmed",
        completion: {
          proposalId,
          candidateSha256: "b".repeat(64),
          diffSha256: "c".repeat(64),
        },
      }).success,
    ).toBe(true);
    const discardCompletion = {
      proposalId,
      state: "discarded",
      candidateSha256: "b".repeat(64),
      diffSha256: "c".repeat(64),
    };
    for (const result of [
      "success",
      "committed_response_unconfirmed",
      "reconciled",
    ] as const)
      expect(
        phase2AuditOutcomeSchema.safeParse({
          ...base,
          tool: "ha_discard_proposed_change",
          phase: "outcome",
          result,
          completion: discardCompletion,
        }).success,
        result,
      ).toBe(true);
    expect(
      phase2AuditOutcomeSchema.safeParse({
        ...base,
        tool: "ha_discard_proposed_change",
        phase: "outcome",
        result: "success",
      }).success,
    ).toBe(false);
    expect(
      phase2AuditOutcomeSchema.safeParse({
        ...base,
        phase: "outcome",
        result: "failure",
      }).success,
    ).toBe(false);
    expect(
      phase2AuditOutcomeSchema.safeParse({
        ...base,
        phase: "outcome",
        result: "success",
        errorCode: "stale_source",
      }).success,
    ).toBe(false);
    expect(
      phase2AuditAttemptSchema.safeParse({
        ...base,
        tool: "ha_propose_config_change",
        phase: "attempt",
        risk: "proposal-metadata",
        target: {},
      }).success,
    ).toBe(false);
    const proposalAttempt = {
      ...base,
      tool: "ha_propose_config_change",
      phase: "attempt",
      risk: "proposal-metadata",
      target: {
        kind: "proposal-create",
        idempotencyKey,
        path: "automations.yaml",
        expectedSha256: sha,
        candidateSha256: "b".repeat(64),
      },
    };
    expect(phase2AuditAttemptSchema.safeParse(proposalAttempt).success).toBe(
      true,
    );
    expect(
      phase2AuditAttemptSchema.safeParse({
        ...proposalAttempt,
        target: { ...proposalAttempt.target, diffSha256: "c".repeat(64) },
      }).success,
    ).toBe(false);
    expect(phase2ErrorCodes).toContain("service_unhealthy");
    expect(phase2ErrorCodes).toContain("resource_not_found");
    expect(phase2Contract.auditOrdering).toEqual([
      "attempt-durable",
      "effect-or-read",
      "outcome-durable",
      "response",
    ]);
    expect(phase2Contract.auditFailurePolicy).toBe(
      "latch-unhealthy-and-reconcile-at-startup",
    );
  });
  it("freezes exact repository cursor, query, and snippet structures", () => {
    const cursor = Buffer.alloc(102).toString("base64url");
    expect(cursor).toHaveLength(136);
    expect(repositoryCursorSchema.safeParse(cursor).success).toBe(true);
    expect(repositoryCursorSchema.safeParse(cursor + "A").success).toBe(false);
    expect(
      repositoryCursorSchema.safeParse(cursor.slice(0, -1) + "=").success,
    ).toBe(false);
    expect(repositorySearchQuerySchema.safeParse("needle").success).toBe(true);
    for (const query of ["bad\nquery", "cafe\u0301", "😀".repeat(129)])
      expect(repositorySearchQuerySchema.safeParse(query).success).toBe(false);
    expect(repositorySnippetSchema.safeParse("😀".repeat(1000)).success).toBe(
      true,
    );
    expect(repositorySnippetSchema.safeParse("😀".repeat(1001)).success).toBe(
      false,
    );
    expect(resourceIdSchema.safeParse("automation.id").success).toBe(true);
    expect(resourceIdSchema.safeParse("😀".repeat(256)).success).toBe(false);
    expect(resourceIdSchema.safeParse("é".repeat(256)).success).toBe(true);
    expect(resourceIdSchema.safeParse("é".repeat(255) + "€").success).toBe(
      false,
    );
    for (const resourceId of ["cafe\u0301", "bad\nvalue", ""])
      expect(resourceIdSchema.safeParse(resourceId).success).toBe(false);
  });
});
