import { createHash } from "node:crypto";
import { z } from "zod";

export const PHASE2_MAX_TEXT_BYTES = 512 * 1024;
export const PHASE2_DEFAULT_LIST_LIMIT = 100;
export const PHASE2_MAX_LIST_LIMIT = 500;

const boundedTextSchema = z
  .string()
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= PHASE2_MAX_TEXT_BYTES,
    "UTF-8 content exceeds the Phase 2 byte limit",
  );

export const relativeConfigPathSchema = z
  .string()
  .min(1)
  .max(512)
  .refine(
    (value) => value === value.normalize("NFC"),
    "Path must use NFC normalization",
  )
  .refine(
    (value) =>
      !value.includes(":") &&
      !Array.from(value).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code <= 0x1f || code === 0x7f;
      }),
    "Path contains a denied character",
  )
  .refine((value) => !value.includes("\\"), "Use '/' as the path separator")
  .refine((value) => !value.startsWith("/"), "Path must be relative")
  .refine(
    (value) =>
      value
        .split("/")
        .every(
          (segment) => segment !== "" && segment !== "." && segment !== "..",
        ),
    "Path must be normalized and may not traverse",
  );

export const proposalTargetPathSchema = relativeConfigPathSchema.refine(
  (value) => /\.ya?ml$/iu.test(value),
  "Proposals target an existing YAML document",
);

export const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
export const repositoryCursorSchema = z
  .string()
  .length(136)
  .regex(/^[A-Za-z0-9_-]{136}$/u)
  .refine((value) => {
    const decoded = Buffer.from(value, "base64url");
    return (
      decoded.byteLength === 102 && decoded.toString("base64url") === value
    );
  }, "Cursor must be canonical fixed-width base64url");
const cursorSchema = repositoryCursorSchema;
export const repositorySearchQuerySchema = z
  .string()
  .min(1)
  .refine(
    (value) => Array.from(value).length <= 200,
    "Query exceeds its character limit",
  )
  .refine((value) => value === value.normalize("NFC"), "Query must use NFC")
  .refine(
    (value) =>
      !Array.from(value).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code <= 0x1f || code === 0x7f;
      }),
    "Query contains a denied control character",
  )
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= 512,
    "Query exceeds its UTF-8 byte limit",
  );
export const repositorySnippetSchema = z
  .string()
  .refine(
    (value) => Array.from(value).length <= 1000,
    "Snippet exceeds its Unicode scalar limit",
  )
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= 4096,
    "Snippet exceeds its UTF-8 byte limit",
  );
const pageInputSchema = z
  .object({
    cursor: cursorSchema.optional(),
    limit: z
      .number()
      .int()
      .min(1)
      .max(PHASE2_MAX_LIST_LIMIT)
      .default(PHASE2_DEFAULT_LIST_LIMIT),
  })
  .strict();

export const configResourceTypeSchema = z.enum([
  "automation",
  "script",
  "helper",
  "scene",
  "blueprint",
]);
export const resourceIdSchema = z
  .string()
  .min(1)
  .superRefine((value, context) => {
    if (
      value !== value.normalize("NFC") ||
      /\p{Cc}/u.test(value) ||
      Array.from(value).length > 256 ||
      Buffer.byteLength(value, "utf8") > 512
    )
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Resource ID is outside its canonical public boundary",
      });
  });

export const phase2ToolInputSchemas = {
  ha_list_config_files: pageInputSchema,
  ha_read_config_file: z.object({ path: relativeConfigPathSchema }).strict(),
  ha_search_config: pageInputSchema
    .extend({ query: repositorySearchQuerySchema })
    .strict(),
  ha_list_config_resources: pageInputSchema
    .extend({ resourceType: configResourceTypeSchema })
    .strict(),
  ha_get_config_resource: z
    .object({
      resourceType: configResourceTypeSchema,
      resourceId: resourceIdSchema,
    })
    .strict(),
  ha_get_git_status: z.object({}).strict(),
  ha_get_git_diff: z
    .object({
      scope: z.enum(["worktree", "index", "both"]).default("both"),
      paths: z.array(relativeConfigPathSchema).max(100).optional(),
    })
    .strict(),
  ha_list_proposals: pageInputSchema,
  ha_get_pending_diff: z.object({ proposalId: z.string().uuid() }).strict(),
  ha_propose_config_change: z
    .object({
      idempotencyKey: z.string().uuid(),
      path: proposalTargetPathSchema,
      expectedSha256: sha256Schema,
      proposedContent: boundedTextSchema,
    })
    .strict(),
  ha_discard_proposed_change: z
    .object({ proposalId: z.string().uuid() })
    .strict(),
} as const;

export type Phase2ToolName = keyof typeof phase2ToolInputSchemas;

export const phase2ToolNames = Object.freeze(
  Object.keys(phase2ToolInputSchemas) as Phase2ToolName[],
);

export const phase2SourceEvidence = {
  configRepository:
    "Home Assistant configuration repository rooted at /homeassistant",
  gitRepository: "Git metadata confined to /homeassistant",
  proposalStore:
    "Protected /data proposal store and /homeassistant repository snapshot",
  dashboardUnavailable:
    "No verified supported Home Assistant API is available for storage-mode dashboards",
} as const;

export const phase2ErrorCodes = [
  "invalid_input",
  "path_denied",
  "protected_resource",
  "file_too_large",
  "unsupported_encoding",
  "stale_source",
  "resource_not_found",
  "repository_unavailable",
  "proposal_not_found",
  "proposal_expired",
  "proposal_conflict",
  "deadline_exceeded",
  "operation_cancelled",
  "service_unhealthy",
] as const;

export type Phase2ErrorCode = (typeof phase2ErrorCodes)[number];

export const proposalStateSchema = z.enum(["pending", "discarded", "expired"]);

export const proposalPublicSchema = z
  .object({
    proposalId: z.string().uuid(),
    idempotencyKey: z.string().uuid(),
    state: proposalStateSchema,
    path: proposalTargetPathSchema,
    expectedSha256: sha256Schema,
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
    redactedDiff: boundedTextSchema,
    createdAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    risk: z.enum(["low", "high"]),
    validationPlan: z.array(z.string().min(1).max(200)).max(20),
    reloadImpact: z.enum(["none", "domain_reload", "restart_required"]),
    sourceEvidence: z.literal(phase2SourceEvidence.proposalStore),
  })
  .strict();

const canonicalProtectedBase64Schema = z
  .string()
  .max(Math.ceil(PHASE2_MAX_TEXT_BYTES / 3) * 4)
  .refine((value) => {
    if (
      value !== "" &&
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
        value,
      )
    )
      return false;
    const decoded = Buffer.from(value, "base64");
    return (
      decoded.byteLength <= PHASE2_MAX_TEXT_BYTES &&
      decoded.toString("base64") === value
    );
  }, "Value must be canonical base64 within the decoded byte limit");

export const protectedProposalPayloadSchema = z
  .object({
    schemaVersion: z.literal(1),
    proposalId: z.string().uuid(),
    idempotencyKey: z.string().uuid(),
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
    encoding: z.literal("utf-8"),
    exactCandidateBytesBase64: canonicalProtectedBase64Schema,
    exactDiffBytesBase64: canonicalProtectedBase64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    const pairs = [
      {
        field: "exactCandidateBytesBase64" as const,
        digest: value.candidateSha256,
      },
      {
        field: "exactDiffBytesBase64" as const,
        digest: value.diffSha256,
      },
    ];
    for (const pair of pairs) {
      const bytes = Buffer.from(value[pair.field], "base64");
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [pair.field],
          message: "Protected bytes must be valid UTF-8",
        });
      }
      if (createHash("sha256").update(bytes).digest("hex") !== pair.digest) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [pair.field],
          message: "Protected bytes do not match the declared digest",
        });
      }
    }
  });
const phase2ErrorCodeSchema = z.enum(phase2ErrorCodes);
const evidenceSchema = z
  .object({ source: z.string().min(1), observedAt: z.string().datetime() })
  .strict();
const errorSchema = z
  .object({ code: phase2ErrorCodeSchema, message: z.string().min(1).max(500) })
  .strict();
const outputEnvelope = <T extends z.ZodTypeAny>(data: T, paged = false) =>
  z.discriminatedUnion("ok", [
    z
      .object({
        ok: z.literal(true),
        requestId: z.string().uuid(),
        data,
        warnings: z.array(z.string().max(500)).max(20),
        evidence: z.array(evidenceSchema).min(1).max(20),
        ...(paged ? { nextCursor: cursorSchema.nullable() } : {}),
      })
      .strict(),
    z
      .object({
        ok: z.literal(false),
        requestId: z.string().uuid(),
        error: errorSchema,
        warnings: z.array(z.string().max(500)).max(20),
        evidence: z.array(evidenceSchema).max(20),
      })
      .strict(),
  ]);
const pagedOutputEnvelope = <T extends z.ZodTypeAny>(data: T) =>
  outputEnvelope(data, true);
const fileSummarySchema = z
  .object({
    path: relativeConfigPathSchema,
    sha256: sha256Schema,
    bytes: z.number().int().nonnegative(),
  })
  .strict();
const resourceSummarySchema = z
  .object({
    resourceType: configResourceTypeSchema,
    resourceId: resourceIdSchema,
    path: relativeConfigPathSchema,
    sha256: sha256Schema,
  })
  .strict();
const gitChangeSchema = z
  .object({
    path: relativeConfigPathSchema,
    index: z.string().length(1),
    worktree: z.string().length(1),
  })
  .strict();

export const phase2ToolOutputSchemas = {
  ha_list_config_files: pagedOutputEnvelope(
    z
      .object({ items: z.array(fileSummarySchema).max(PHASE2_MAX_LIST_LIMIT) })
      .strict(),
  ),
  ha_read_config_file: outputEnvelope(
    z
      .object({
        ...fileSummarySchema.shape,
        content: boundedTextSchema,
        sourceEvidence: z.literal(phase2SourceEvidence.configRepository),
      })
      .strict(),
  ),
  ha_search_config: pagedOutputEnvelope(
    z
      .object({
        items: z
          .array(
            z
              .object({
                path: relativeConfigPathSchema,
                line: z.number().int().positive(),
                snippet: repositorySnippetSchema,
              })
              .strict(),
          )
          .max(PHASE2_MAX_LIST_LIMIT),
      })
      .strict(),
  ),
  ha_list_config_resources: pagedOutputEnvelope(
    z
      .object({
        items: z.array(resourceSummarySchema).max(PHASE2_MAX_LIST_LIMIT),
      })
      .strict(),
  ),
  ha_get_config_resource: outputEnvelope(
    z
      .object({
        ...resourceSummarySchema.shape,
        redactedContent: boundedTextSchema,
        sourceEvidence: z.literal(phase2SourceEvidence.configRepository),
      })
      .strict(),
  ),
  ha_get_git_status: outputEnvelope(
    z
      .object({
        clean: z.boolean(),
        branch: z.string().max(256).nullable(),
        changes: z.array(gitChangeSchema).max(PHASE2_MAX_LIST_LIMIT),
        sourceEvidence: z.literal(phase2SourceEvidence.gitRepository),
      })
      .strict(),
  ),
  ha_get_git_diff: outputEnvelope(
    z
      .object({
        redactedDiff: boundedTextSchema,
        diffSha256: sha256Schema,
        truncated: z.boolean(),
        sourceEvidence: z.literal(phase2SourceEvidence.gitRepository),
      })
      .strict(),
  ),
  ha_list_proposals: pagedOutputEnvelope(
    z
      .object({
        items: z.array(proposalPublicSchema).max(PHASE2_MAX_LIST_LIMIT),
      })
      .strict(),
  ),
  ha_get_pending_diff: outputEnvelope(proposalPublicSchema),
  ha_propose_config_change: outputEnvelope(proposalPublicSchema),
  ha_discard_proposed_change: outputEnvelope(proposalPublicSchema),
} satisfies Record<Phase2ToolName, z.ZodTypeAny>;

const auditBase = {
  schemaVersion: z.literal(2),
  timestamp: z.string().datetime(),
  requestId: z.string().uuid(),
  operationId: z.string().uuid(),
};
const repositoryTargetSchema = z
  .object({ kind: z.literal("repository") })
  .strict();
const pathTargetSchema = z
  .object({ kind: z.literal("path"), path: relativeConfigPathSchema })
  .strict();
const searchTargetSchema = z
  .object({ kind: z.literal("search"), querySha256: sha256Schema })
  .strict();
const resourceTargetSchema = z
  .object({
    kind: z.literal("resource"),
    resourceType: configResourceTypeSchema,
    resourceIdSha256: sha256Schema,
  })
  .strict();
const gitTargetSchema = z
  .object({
    kind: z.literal("git"),
    scope: z.enum(["status", "worktree", "index", "both"]),
    pathsSha256: sha256Schema.optional(),
  })
  .strict();
const proposalStoreTargetSchema = z
  .object({ kind: z.literal("proposal-store") })
  .strict();
const proposalTargetAuditSchema = z
  .object({ kind: z.literal("proposal"), proposalId: z.string().uuid() })
  .strict();
const proposalCreateTargetSchema = z
  .object({
    kind: z.literal("proposal-create"),
    idempotencyKey: z.string().uuid(),
    path: proposalTargetPathSchema,
    expectedSha256: sha256Schema,
    candidateSha256: sha256Schema,
  })
  .strict();
const attempt = <T extends Phase2ToolName, S extends z.ZodTypeAny>(
  tool: T,
  target: S,
  risk: "read-only" | "proposal-metadata",
) =>
  z
    .object({
      ...auditBase,
      phase: z.literal("attempt"),
      tool: z.literal(tool),
      risk: z.literal(risk),
      target,
    })
    .strict();

export const phase2AuditAttemptSchema = z.discriminatedUnion("tool", [
  attempt("ha_list_config_files", repositoryTargetSchema, "read-only"),
  attempt("ha_read_config_file", pathTargetSchema, "read-only"),
  attempt("ha_search_config", searchTargetSchema, "read-only"),
  attempt("ha_list_config_resources", repositoryTargetSchema, "read-only"),
  attempt("ha_get_config_resource", resourceTargetSchema, "read-only"),
  attempt("ha_get_git_status", gitTargetSchema, "read-only"),
  attempt("ha_get_git_diff", gitTargetSchema, "read-only"),
  attempt("ha_list_proposals", proposalStoreTargetSchema, "read-only"),
  attempt("ha_get_pending_diff", proposalTargetAuditSchema, "read-only"),
  attempt(
    "ha_propose_config_change",
    proposalCreateTargetSchema,
    "proposal-metadata",
  ),
  attempt(
    "ha_discard_proposed_change",
    proposalTargetAuditSchema,
    "proposal-metadata",
  ),
]);
const nonProposalEffectToolSchema = z.enum(
  phase2ToolNames.filter(
    (name) =>
      name !== "ha_propose_config_change" &&
      name !== "ha_discard_proposed_change",
  ) as [
    Exclude<
      Phase2ToolName,
      "ha_propose_config_change" | "ha_discard_proposed_change"
    >,
    ...Exclude<
      Phase2ToolName,
      "ha_propose_config_change" | "ha_discard_proposed_change"
    >[],
  ],
);
const outcomeBase = {
  ...auditBase,
  phase: z.literal("outcome"),
};
const proposalCompletionSchema = z
  .object({
    proposalId: z.string().uuid(),
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
  })
  .strict();
const discardCompletionSchema = z
  .object({
    proposalId: z.string().uuid(),
    state: z.literal("discarded"),
    candidateSha256: sha256Schema,
    diffSha256: sha256Schema,
  })
  .strict();
const completedProposalEffect = (
  tool: "ha_propose_config_change" | "ha_discard_proposed_change",
  result: "success" | "committed_response_unconfirmed" | "reconciled",
) =>
  z
    .object({
      ...outcomeBase,
      tool: z.literal(tool),
      result: z.literal(result),
      completion:
        tool === "ha_propose_config_change"
          ? proposalCompletionSchema
          : discardCompletionSchema,
    })
    .strict();

export const phase2AuditOutcomeSchema = z.union([
  z
    .object({
      ...outcomeBase,
      tool: nonProposalEffectToolSchema,
      result: z.literal("success"),
    })
    .strict(),
  completedProposalEffect("ha_propose_config_change", "success"),
  completedProposalEffect("ha_discard_proposed_change", "success"),
  z
    .object({
      ...outcomeBase,
      tool: z.enum(phase2ToolNames as [Phase2ToolName, ...Phase2ToolName[]]),
      result: z.literal("failure"),
      errorCode: phase2ErrorCodeSchema,
    })
    .strict(),
  completedProposalEffect(
    "ha_propose_config_change",
    "committed_response_unconfirmed",
  ),
  completedProposalEffect(
    "ha_discard_proposed_change",
    "committed_response_unconfirmed",
  ),
  completedProposalEffect("ha_propose_config_change", "reconciled"),
  completedProposalEffect("ha_discard_proposed_change", "reconciled"),
]);
export const phase2AuditRecordSchema = z.union([
  phase2AuditAttemptSchema,
  phase2AuditOutcomeSchema,
]);
export interface Phase2OperationContext {
  readonly requestId: string;
  readonly operationId: string;
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

export const phase2YamlPolicy = Object.freeze({
  encoding: "strict-utf8-no-bom-no-nul" as const,
  documents: "exactly-one-or-empty" as const,
  duplicateKeys: "reject" as const,
  customTags: [
    "!include",
    "!include_dir_list",
    "!include_dir_merge_list",
    "!include_dir_named",
    "!include_dir_merge_named",
    "!secret",
    "!input",
  ] as const,
  unknownTags: "reject" as const,
  mergeKeys: "reject" as const,
  aliases: "allow-acyclic-with-100-reference-and-fanout-limit" as const,
  maximumDepth: 64,
  maximumNodes: 100_000,
  lineEndings: "allow-lf-or-crlf-reject-bare-cr-preserve-exact-bytes" as const,
  reserialization: "prohibited" as const,
  commentsQuotesAnchors: "preserve-exact-input-bytes" as const,
});

export const phase2Contract = Object.freeze({
  registered: true,
  sourceRoot: "/homeassistant" as const,
  proposalInputMode: "existing-yaml-file-whole-document" as const,
  proposalPayloadClassification: "protected" as const,
  idempotency: {
    identity: ["path", "expectedSha256", "candidateSha256"] as const,
    sameKeySameIdentity:
      "return-original-proposal-including-terminal-or-expired-state" as const,
    sameKeyDifferentIdentity: "proposal_conflict" as const,
    concurrentSameIdentity: "serialize-and-return-one-proposal" as const,
  },
  mutationOfLiveConfig: false,
  createsDeletesRenames: false,
  dashboardRouting: "verified-supported-api-or-capability-unavailable" as const,
  auditOrdering: [
    "attempt-durable",
    "effect-or-read",
    "outcome-durable",
    "response",
  ] as const,
  auditFailurePolicy: "latch-unhealthy-and-reconcile-at-startup" as const,
  cancellation:
    "internal-abort-signal-and-deadline-not-public-tool-arguments" as const,
  atomicRenameCommitPoint:
    "rename-then-complete-bookkeeping-or-reconcile" as const,
});
