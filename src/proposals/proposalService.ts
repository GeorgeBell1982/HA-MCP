import { createHash, randomUUID } from "node:crypto";
import {
  PHASE2_MAX_TEXT_BYTES,
  phase2ErrorCodes,
  phase2ToolInputSchemas,
  proposalPublicSchema,
  protectedProposalPayloadSchema,
  type Phase2ErrorCode,
  type Phase2OperationContext,
  type Phase2ToolName,
} from "../phase2Contracts.js";
import {
  GitWorkPoller,
  canonicalUnifiedPatch,
  prepareGitYamlSide,
} from "../git/gitReads.js";
import {
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  assertOperationActive,
} from "../security/repositoryBoundary.js";
import { validateStrictYaml, YamlGateError } from "../yaml/strictYamlGate.js";
import {
  catalogsMatchExactly,
  type RepositoryCatalogProvider,
} from "../repository/repositoryReads.js";
import {
  ProposalCursorCodec,
  ProposalCursorError,
  proposalSnapshot,
} from "./cursor.js";
import { Phase2AuditAdapter } from "./phase2Audit.js";
import {
  ProtectedProposalStore,
  ProtectedWriteError,
  journalEnvelope,
  storageEnvelope,
  type ProposalJournal,
  type StoredProposal,
} from "./storage.js";

const PROPOSAL_TTL_MS = 24 * 60 * 60 * 1000;
const LIST_OPERATION = 1;

export class ProposalServiceError extends Error {
  constructor(
    public readonly code: Phase2ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ProposalServiceError";
  }
}

export interface ProposalServiceHooks {
  readonly now?: () => number;
  readonly checkpoint?: (
    stage: "journal_prepared" | "effect_committed" | "outcome_committed",
  ) => Promise<void>;
}

export class ProposalService {
  private generation = 0;

  constructor(
    private readonly store: ProtectedProposalStore,
    private readonly audit: Phase2AuditAdapter,
    private readonly registry: ProtectedIdentityRegistry,
    private readonly catalog: RepositoryCatalogProvider,
    private readonly cursors: ProposalCursorCodec,
    private readonly hooks: ProposalServiceHooks = {},
  ) {}

  async initialize(): Promise<void> {
    await this.audit.recover();
    await this.store.initialize();
    await this.reconcile();
    await this.settlePendingAuditAttempts();
  }

  async list(
    input: unknown,
    context: Phase2OperationContext,
  ): Promise<
    Readonly<{
      items: readonly StoredProposal["public"][];
      nextCursor: string | null;
    }>
  > {
    const parsed = phase2ToolInputSchemas.ha_list_proposals.safeParse(input);
    if (!parsed.success)
      throw error("invalid_input", "Proposal list input is invalid");
    return this.readOperation(
      "ha_list_proposals",
      { kind: "proposal-store" },
      context,
      () =>
        this.store.serialized(async () => {
          const values = await this.loadAndExpire(context);
          const snapshot = proposalSnapshot(values, context);
          try {
            let offset = 0;
            if (parsed.data.cursor) {
              let cursor;
              try {
                cursor = this.cursors.decode(
                  parsed.data.cursor,
                  LIST_OPERATION,
                );
              } catch (cause) {
                throw cause instanceof ProposalCursorError
                  ? error("invalid_input", cause.message)
                  : cause;
              }
              try {
                if (
                  cursor.generation !== this.generation ||
                  !cursor.snapshot.equals(snapshot)
                )
                  throw error(
                    "stale_source",
                    "Proposal cursor snapshot is stale",
                  );
                if (cursor.offset >= values.length)
                  throw error(
                    "stale_source",
                    "Proposal cursor offset is outside the snapshot",
                  );
                offset = cursor.offset;
              } finally {
                cursor.snapshot.fill(0);
              }
            }
            const page = values.slice(offset, offset + parsed.data.limit);
            const nextOffset = offset + page.length;
            const nextCursor =
              nextOffset < values.length
                ? this.cursors.encode(
                    LIST_OPERATION,
                    this.generation,
                    nextOffset,
                    snapshot,
                  )
                : null;
            return Object.freeze({
              items: Object.freeze(page.map((value) => value.public)),
              nextCursor,
            });
          } finally {
            snapshot.fill(0);
          }
        }),
    );
  }

  async get(
    input: unknown,
    context: Phase2OperationContext,
  ): Promise<StoredProposal["public"]> {
    const parsed = phase2ToolInputSchemas.ha_get_pending_diff.safeParse(input);
    if (!parsed.success)
      throw error("invalid_input", "Proposal get input is invalid");
    return this.readOperation(
      "ha_get_pending_diff",
      { kind: "proposal", proposalId: parsed.data.proposalId },
      context,
      () =>
        this.store.serialized(async () => {
          const found = (await this.loadAndExpire(context)).find(
            (value) => value.public.proposalId === parsed.data.proposalId,
          );
          if (!found)
            throw error("proposal_not_found", "Proposal was not found");
          if (found.public.state === "expired")
            throw error("proposal_expired", "Proposal has expired");
          return found.public;
        }),
    );
  }

  async propose(
    input: unknown,
    context: Phase2OperationContext,
  ): Promise<StoredProposal["public"]> {
    const parsed =
      phase2ToolInputSchemas.ha_propose_config_change.safeParse(input);
    if (!parsed.success)
      throw error("invalid_input", "Proposal input is invalid");
    const candidate = Buffer.from(parsed.data.proposedContent, "utf8");
    try {
      if (
        new TextDecoder("utf-8", { fatal: true }).decode(candidate) !==
        parsed.data.proposedContent
      )
        throw error("unsupported_encoding", "Candidate is not canonical UTF-8");
      await validateCandidate(candidate, context);
      const candidateSha256 = digest(candidate);
      const attempt = this.attempt("ha_propose_config_change", context, {
        kind: "proposal-create",
        idempotencyKey: parsed.data.idempotencyKey,
        path: parsed.data.path,
        expectedSha256: parsed.data.expectedSha256,
        candidateSha256,
      });
      assertOperationActive(context);
      await this.audit.append(attempt);
      try {
        const proposal = await this.store.serialized(async () => {
          const values = await this.loadAndExpire(context);
          const existing = values.find(
            (value) =>
              value.public.idempotencyKey === parsed.data.idempotencyKey,
          );
          if (existing) {
            if (
              existing.public.path !== parsed.data.path ||
              existing.public.expectedSha256 !== parsed.data.expectedSha256 ||
              existing.public.candidateSha256 !== candidateSha256
            )
              throw error(
                "proposal_conflict",
                "Idempotency key has a different proposal identity",
              );
            return existing;
          }
          if (values.length >= 500)
            throw error("service_unhealthy", "Proposal count limit reached");
          await this.registry.assertFresh(context);
          const beforeCatalog = await this.catalog.catalog(context);
          const catalogEntry = beforeCatalog.files.find(
            (entry) => entry.path === parsed.data.path,
          );
          if (!catalogEntry)
            throw error(
              "resource_not_found",
              "Proposal source is absent from the authoritative catalog",
            );
          const source = await this.registry.readContent(
            parsed.data.path,
            context,
          );
          try {
            if (
              source.identity.device !== catalogEntry.identity.device ||
              source.identity.inode !== catalogEntry.identity.inode
            )
              throw error(
                "stale_source",
                "Proposal source identity changed after cataloging",
              );
            if (digest(source.bytes) !== parsed.data.expectedSha256)
              throw error("stale_source", "Repository source digest changed");
            await validateCandidate(source.bytes, context);
            const oldText = fatalText(source.bytes);
            const newText = fatalText(candidate);
            const poller = new GitWorkPoller(context);
            const exactDiff = canonicalUnifiedPatch(
              oldText,
              newText,
              parsed.data.path,
              poller,
            );
            const exactDiffBytes = Buffer.from(exactDiff, "utf8");
            try {
              if (exactDiffBytes.byteLength > PHASE2_MAX_TEXT_BYTES)
                throw error(
                  "file_too_large",
                  "Exact proposal diff exceeds its protected boundary",
                );
              const oldRedacted = await prepareGitYamlSide(
                source.bytes,
                this.registry,
                context,
              );
              const newRedacted = await prepareGitYamlSide(
                candidate,
                this.registry,
                context,
              );
              const redactedDiff = canonicalUnifiedPatch(
                oldRedacted,
                newRedacted,
                parsed.data.path,
                poller,
              );
              poller.finish();
              await this.registry.assertFresh(context);
              const afterCatalog = await this.catalog.catalog(context);
              if (!catalogsMatchExactly(beforeCatalog, afterCatalog))
                throw error(
                  "stale_source",
                  "Repository catalog changed while preparing the proposal",
                );
              const now = this.now();
              const proposalId = randomUUID();
              const publicValue = proposalPublicSchema.parse({
                proposalId,
                idempotencyKey: parsed.data.idempotencyKey,
                state: "pending",
                path: parsed.data.path,
                expectedSha256: parsed.data.expectedSha256,
                candidateSha256,
                diffSha256: digest(exactDiffBytes),
                redactedDiff,
                createdAt: new Date(now).toISOString(),
                expiresAt: new Date(now + PROPOSAL_TTL_MS).toISOString(),
                risk: "high",
                validationPlan: [
                  "Validate Home Assistant configuration",
                  "Review exact protected diff before apply",
                ],
                reloadImpact: "restart_required",
                sourceEvidence:
                  "Protected /data proposal store and /homeassistant repository snapshot",
              });
              const protectedValue = protectedProposalPayloadSchema.parse({
                schemaVersion: 1,
                proposalId,
                idempotencyKey: parsed.data.idempotencyKey,
                candidateSha256,
                diffSha256: publicValue.diffSha256,
                encoding: "utf-8",
                exactCandidateBytesBase64: candidate.toString("base64"),
                exactDiffBytesBase64: exactDiffBytes.toString("base64"),
              });
              const stored = storageEnvelope(publicValue, protectedValue);
              await this.commitMutation(
                "ha_propose_config_change",
                stored,
                null,
                context,
              );
              return stored;
            } finally {
              exactDiffBytes.fill(0);
            }
          } finally {
            source.bytes.fill(0);
          }
        });
        await this.finishMutation(
          "ha_propose_config_change",
          proposal,
          context,
        );
        return proposal.public;
      } catch (cause) {
        await this.auditFailure("ha_propose_config_change", context, cause);
        throw normalize(cause);
      }
    } finally {
      candidate.fill(0);
    }
  }

  async discard(
    input: unknown,
    context: Phase2OperationContext,
  ): Promise<StoredProposal["public"]> {
    const parsed =
      phase2ToolInputSchemas.ha_discard_proposed_change.safeParse(input);
    if (!parsed.success)
      throw error("invalid_input", "Proposal discard input is invalid");
    await this.audit.append(
      this.attempt("ha_discard_proposed_change", context, {
        kind: "proposal",
        proposalId: parsed.data.proposalId,
      }),
      context,
    );
    try {
      const value = await this.store.serialized(async () => {
        const current = (await this.loadAndExpire(context)).find(
          (item) => item.public.proposalId === parsed.data.proposalId,
        );
        if (!current)
          throw error("proposal_not_found", "Proposal was not found");
        if (current.public.state === "expired")
          throw error("proposal_expired", "Proposal has expired");
        if (current.public.state === "discarded") return current;
        const updated = storageEnvelope(
          proposalPublicSchema.parse({ ...current.public, state: "discarded" }),
          current.protected,
        );
        await this.commitMutation(
          "ha_discard_proposed_change",
          updated,
          current,
          context,
        );
        return updated;
      });
      await this.finishMutation("ha_discard_proposed_change", value, context);
      return value.public;
    } catch (cause) {
      await this.auditFailure("ha_discard_proposed_change", context, cause);
      throw normalize(cause);
    }
  }

  close(): void {
    this.cursors.close();
  }

  private async readOperation<T>(
    tool: "ha_list_proposals" | "ha_get_pending_diff",
    target: unknown,
    context: Phase2OperationContext,
    effect: () => Promise<T>,
  ): Promise<T> {
    assertOperationActive(context);
    await this.audit.append(this.attempt(tool, context, target));
    try {
      const output = await effect();
      assertOperationActive(context);
      await this.audit.append(this.outcome(tool, context, "success"));
      return output;
    } catch (cause) {
      await this.auditFailure(tool, context, cause);
      throw normalize(cause);
    }
  }

  private async loadAndExpire(
    context: Phase2OperationContext,
  ): Promise<StoredProposal[]> {
    const values = await this.store.readAll();
    let work = 0;
    values.sort((left, right) => {
      if ((work & 255) === 0) assertOperationActive(context);
      work += 1;
      return Buffer.compare(
        Buffer.from(left.public.proposalId, "utf8"),
        Buffer.from(right.public.proposalId, "utf8"),
      );
    });
    const now = this.now();
    for (let index = 0; index < values.length; index += 1) {
      const current = values[index]!;
      if (
        current.public.state === "pending" &&
        now >= Date.parse(current.public.expiresAt)
      ) {
        assertOperationActive(context);
        const expired = storageEnvelope(
          proposalPublicSchema.parse({ ...current.public, state: "expired" }),
          current.protected,
        );
        await this.store.replace(expired, current, context);
        this.bumpGeneration();
        values[index] = expired;
      }
    }
    return values;
  }

  private async commitMutation(
    tool: "ha_propose_config_change" | "ha_discard_proposed_change",
    proposal: StoredProposal,
    previous: StoredProposal | null,
    context: Phase2OperationContext,
  ): Promise<void> {
    const journal = journalEnvelope({
      schemaVersion: 1,
      operationId: context.operationId,
      requestId: context.requestId,
      tool,
      phase: "prepared",
      beforeSha256: previous?.storageSha256 ?? null,
      proposal,
    });
    await this.store.createJournal(journal, context);
    await this.hooks.checkpoint?.("journal_prepared");
    try {
      if (previous) await this.store.replace(proposal, previous, context);
      else await this.store.create(proposal, context);
      this.bumpGeneration();
    } catch (cause) {
      if (cause instanceof ProtectedWriteError && cause.committed) {
        this.bumpGeneration();
        await this.audit.append(
          this.outcome(
            tool,
            context,
            "committed_response_unconfirmed",
            proposal,
          ),
        );
      }
      throw cause;
    }
    try {
      await this.hooks.checkpoint?.("effect_committed");
      const next = journalEnvelope({
        ...withoutJournalDigest(journal),
        phase: "effect_committed",
      });
      await this.store.replaceJournal(next, journal);
    } catch (cause) {
      if (!this.audit.hasOutcome(context.operationId))
        await this.audit.append(
          this.outcome(
            tool,
            context,
            "committed_response_unconfirmed",
            proposal,
          ),
        );
      throw cause;
    }
  }

  private async finishMutation(
    tool: "ha_propose_config_change" | "ha_discard_proposed_change",
    proposal: StoredProposal,
    context: Phase2OperationContext,
  ): Promise<void> {
    const journals = await this.store.readJournals();
    const journal = journals.find(
      (value) => value.operationId === context.operationId,
    );
    if (!journal) {
      await this.audit.append(this.outcome(tool, context, "success", proposal));
      return;
    }
    const cancelled =
      context.signal.aborted || Date.now() >= context.deadlineAt;
    await this.audit.append(
      this.outcome(
        tool,
        context,
        cancelled ? "committed_response_unconfirmed" : "success",
        proposal,
      ),
    );
    const done = journalEnvelope({
      ...withoutJournalDigest(journal),
      phase: "outcome_committed",
    });
    await this.store.replaceJournal(done, journal);
    await this.hooks.checkpoint?.("outcome_committed");
    await this.store.removeJournal(done);
    if (cancelled) assertOperationActive(context);
  }

  private async reconcile(): Promise<void> {
    await this.store.serialized(async () => {
      const proposals = await this.store.readAll();
      for (const journal of await this.store.readJournals()) {
        const current = proposals.find(
          (value) =>
            value.public.proposalId === journal.proposal.public.proposalId,
        );
        const committed =
          current?.storageSha256 === journal.proposal.storageSha256;
        const unchanged =
          journal.beforeSha256 === null
            ? current === undefined
            : current?.storageSha256 === journal.beforeSha256;
        if (!committed && !unchanged) {
          this.store.markUnhealthy();
          throw error(
            "service_unhealthy",
            "Proposal journal effect is ambiguous",
          );
        }
        if (!committed && journal.phase !== "prepared") {
          this.store.markUnhealthy();
          throw error(
            "service_unhealthy",
            "Proposal journal effect is missing or ambiguous",
          );
        }
        if (!this.audit.hasOutcome(journal.operationId)) {
          if (committed)
            await this.audit.append(
              this.outcome(
                journal.tool,
                journal,
                "reconciled",
                journal.proposal,
              ),
            );
          else
            await this.audit.append(
              this.outcome(
                journal.tool,
                journal,
                "failure",
                undefined,
                "service_unhealthy",
              ),
            );
        }
        if (committed && journal.phase !== "outcome_committed") {
          const done = journalEnvelope({
            ...withoutJournalDigest(journal),
            phase: "outcome_committed",
          });
          await this.store.replaceJournal(done, journal);
          await this.store.removeJournal(done);
        } else await this.store.removeJournal(journal);
      }
    });
  }

  private async settlePendingAuditAttempts(): Promise<void> {
    for (const attempt of this.audit.pendingAuditAttempts())
      await this.audit.append(
        this.outcome(
          attempt.tool,
          attempt,
          "failure",
          undefined,
          "service_unhealthy",
        ),
      );
  }

  private attempt(
    tool: Phase2ToolName,
    context: Pick<Phase2OperationContext, "requestId" | "operationId">,
    target: unknown,
  ): unknown {
    return {
      schemaVersion: 2,
      timestamp: new Date(this.now()).toISOString(),
      requestId: context.requestId,
      operationId: context.operationId,
      phase: "attempt",
      tool,
      risk:
        tool === "ha_propose_config_change" ||
        tool === "ha_discard_proposed_change"
          ? "proposal-metadata"
          : "read-only",
      target,
    };
  }

  private outcome(
    tool: Phase2ToolName,
    context: Pick<Phase2OperationContext, "requestId" | "operationId">,
    result:
      | "success"
      | "failure"
      | "committed_response_unconfirmed"
      | "reconciled",
    proposal?: StoredProposal,
    errorCode?: Phase2ErrorCode,
  ): unknown {
    const base: Record<string, unknown> = {
      schemaVersion: 2,
      timestamp: new Date(this.now()).toISOString(),
      requestId: context.requestId,
      operationId: context.operationId,
      phase: "outcome",
      tool,
      result,
    };
    if (result === "failure") base.errorCode = errorCode ?? "service_unhealthy";
    else if (tool === "ha_propose_config_change" && proposal)
      base.completion = completion(proposal, false);
    else if (tool === "ha_discard_proposed_change" && proposal)
      base.completion = completion(proposal, true);
    return base;
  }

  private async auditFailure(
    tool: Phase2ToolName,
    context: Phase2OperationContext,
    cause: unknown,
  ): Promise<void> {
    if (!this.audit.hasOutcome(context.operationId))
      await this.audit.append(
        this.outcome(tool, context, "failure", undefined, errorCode(cause)),
      );
  }

  private now(): number {
    return (this.hooks.now ?? Date.now)();
  }
  private bumpGeneration(): void {
    if (this.generation === 0xffffffff)
      throw error("service_unhealthy", "Proposal generation exhausted");
    this.generation += 1;
  }
}

function completion(
  value: StoredProposal,
  discarded: boolean,
): Record<string, unknown> {
  return discarded
    ? {
        proposalId: value.public.proposalId,
        state: "discarded",
        candidateSha256: value.public.candidateSha256,
        diffSha256: value.public.diffSha256,
      }
    : {
        proposalId: value.public.proposalId,
        candidateSha256: value.public.candidateSha256,
        diffSha256: value.public.diffSha256,
      };
}

function withoutJournalDigest(
  value: ProposalJournal,
): Omit<ProposalJournal, "journalSha256"> {
  const copy: Partial<ProposalJournal> = { ...value };
  delete copy.journalSha256;
  return copy as Omit<ProposalJournal, "journalSha256">;
}

async function validateCandidate(
  bytes: Uint8Array,
  context: Phase2OperationContext,
): Promise<void> {
  try {
    await validateStrictYaml(bytes, context);
  } catch (cause) {
    if (cause instanceof YamlGateError) {
      if (cause.code === "operation_cancelled")
        throw error("operation_cancelled", "Operation was cancelled");
      if (cause.code === "deadline_exceeded")
        throw error("deadline_exceeded", "Operation deadline expired");
      if (cause.code === "file_too_large")
        throw error("file_too_large", "YAML exceeds its size boundary");
      if (cause.code === "unsupported_encoding")
        throw error("unsupported_encoding", "YAML encoding is unsupported");
      throw error(
        "invalid_input",
        `YAML failed strict validation: ${cause.code}`,
      );
    }
    throw cause;
  }
}

function fatalText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw error("unsupported_encoding", "YAML is not strict UTF-8");
  }
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function error(code: Phase2ErrorCode, message: string): ProposalServiceError {
  return new ProposalServiceError(code, message);
}

function normalize(
  cause: unknown,
): ProposalServiceError | RepositoryBoundaryError {
  if (
    cause instanceof ProposalServiceError ||
    cause instanceof RepositoryBoundaryError
  )
    return cause;
  return error("service_unhealthy", "Proposal service failed safely");
}

function errorCode(cause: unknown): Phase2ErrorCode {
  if (cause instanceof ProposalServiceError) return cause.code;
  if (cause instanceof RepositoryBoundaryError) {
    return (phase2ErrorCodes as readonly string[]).includes(cause.code)
      ? (cause.code as Phase2ErrorCode)
      : "repository_unavailable";
  }
  return "service_unhealthy";
}
