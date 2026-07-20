import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { GitReadService } from "./git/gitReads.js";
import {
  phase2ErrorCodes,
  phase2SourceEvidence,
  phase2ToolInputSchemas,
  phase2ToolNames,
  phase2ToolOutputSchemas,
  type Phase2ErrorCode,
  type Phase2OperationContext,
  type Phase2ToolName,
} from "./phase2Contracts.js";
import { ProposalServiceError } from "./proposals/proposalService.js";
import type { ProposalService } from "./proposals/proposalService.js";
import type { RepositoryReadService } from "./repository/repositoryReads.js";
import type { RepositoryResourceService } from "./repository/resourceProjection.js";
import { RepositoryBoundaryError } from "./security/repositoryBoundary.js";
import type {
  ToolCallContext,
  ToolDescriptor,
  ToolRegistry,
  ToolResult,
} from "./toolRegistry.js";
import { YamlGateError } from "./yaml/strictYamlGate.js";

export const PHASE2_TOOL_TIMEOUT_MS = 30_000;

type Phase2Timer = ReturnType<typeof setTimeout>;

export interface Phase2ToolsClock {
  now(): number;
  setTimeout(callback: () => void, milliseconds: number): Phase2Timer;
  clearTimeout(timer: Phase2Timer): void;
}

export interface Phase2ToolsServices {
  readonly repositoryReadService: Pick<
    RepositoryReadService,
    "list" | "read" | "search"
  >;
  readonly repositoryResourceService: Pick<
    RepositoryResourceService,
    "list" | "get"
  >;
  readonly gitReadService: Pick<GitReadService, "status" | "diff">;
  readonly proposalService: Pick<
    ProposalService,
    "list" | "get" | "propose" | "discard"
  >;
}

export interface Phase2ToolsOptions {
  readonly clock?: Partial<Phase2ToolsClock>;
  readonly timeoutMs?: number;
  readonly createUuid?: () => string;
}

type Phase2Input<T extends Phase2ToolName> = z.infer<
  (typeof phase2ToolInputSchemas)[T]
>;

interface DispatchResult {
  readonly data: unknown;
  readonly evidenceSource: string;
  readonly warnings?: readonly string[];
  readonly nextCursor?: string | null;
}

const readOnlyDescription =
  "Read-only. Reads bounded Home Assistant repository, Git, or proposal-store state; does not modify live configuration, proposal state, reload, restart, or commit.";
const proposalOnlyDescription =
  "Proposal-only. Creates or discards protected proposal metadata; does not modify live Home Assistant configuration, reload, restart, or commit.";
const fixedErrorMessages: Record<Phase2ErrorCode, string> = Object.freeze({
  invalid_input: "Tool input failed schema validation",
  path_denied: "Repository path is denied",
  protected_resource: "Protected resource is unavailable",
  file_too_large: "Content exceeds Phase 2 size limits",
  unsupported_encoding: "Content encoding is unsupported",
  stale_source: "Source changed during operation",
  resource_not_found: "Resource was not found",
  repository_unavailable: "Repository is unavailable",
  proposal_not_found: "Proposal was not found",
  proposal_expired: "Proposal has expired",
  proposal_conflict: "Proposal conflict",
  deadline_exceeded: "Operation deadline expired",
  operation_cancelled: "Operation was cancelled",
  service_unhealthy: "Service is temporarily unhealthy",
});

class Phase2RegistryError extends Error {
  constructor(readonly code: Phase2ErrorCode) {
    super(code);
    this.name = "Phase2RegistryError";
  }
}

export class Phase2Tools implements ToolRegistry {
  private readonly clock: Phase2ToolsClock;
  private readonly timeoutMs: number;
  private readonly createUuid: () => string;

  constructor(
    private readonly services: Phase2ToolsServices,
    options: Phase2ToolsOptions = {},
  ) {
    this.clock = {
      now: options.clock?.now ?? Date.now,
      setTimeout: options.clock?.setTimeout ?? setTimeout,
      clearTimeout: options.clock?.clearTimeout ?? clearTimeout,
    };
    this.timeoutMs = options.timeoutMs ?? PHASE2_TOOL_TIMEOUT_MS;
    this.createUuid = options.createUuid ?? randomUUID;
  }

  names(): readonly string[] {
    return phase2ToolNames;
  }

  descriptors(): readonly ToolDescriptor[] {
    return Object.freeze(phase2ToolNames.map((name) => this.descriptor(name)!));
  }

  descriptor(name: string): ToolDescriptor | undefined {
    if (!isPhase2ToolName(name)) return undefined;
    return Object.freeze({
      name,
      description: isProposalMutation(name)
        ? proposalOnlyDescription
        : readOnlyDescription,
      inputSchema: phase2ToolInputSchemas[name],
      outputSchema: phase2ToolOutputSchemas[name],
    });
  }

  async call(
    name: string,
    rawInput: unknown,
    context?: ToolCallContext,
  ): Promise<ToolResult> {
    const requestId = this.createUuid();
    const operationId = this.createUuid();
    if (!isPhase2ToolName(name))
      return this.genericFailure(requestId, "invalid_input");

    const parsed = phase2ToolInputSchemas[name].safeParse(rawInput);
    if (!parsed.success) return this.failure(name, requestId, "invalid_input");

    try {
      const result = await this.withBoundedContext(
        requestId,
        operationId,
        context?.signal,
        (operation) => this.dispatch(name, parsed.data, operation),
      );
      return this.success(name, requestId, result);
    } catch (error) {
      return this.failure(name, requestId, errorCode(error));
    }
  }

  private async dispatch(
    name: Phase2ToolName,
    input: Phase2Input<Phase2ToolName>,
    context: Phase2OperationContext,
  ): Promise<DispatchResult> {
    switch (name) {
      case "ha_list_config_files": {
        const listInput = input as Phase2Input<"ha_list_config_files">;
        const page = await this.services.repositoryReadService.list(
          optionalCursorInput(listInput),
          context,
        );
        return {
          data: { items: page.items },
          nextCursor: page.nextCursor,
          evidenceSource: phase2SourceEvidence.configRepository,
        };
      }
      case "ha_read_config_file": {
        const file = await this.services.repositoryReadService.read(
          (input as Phase2Input<"ha_read_config_file">).path,
          context,
        );
        return {
          data: {
            ...file,
            sourceEvidence: phase2SourceEvidence.configRepository,
          },
          evidenceSource: phase2SourceEvidence.configRepository,
        };
      }
      case "ha_search_config": {
        const searchInput = input as Phase2Input<"ha_search_config">;
        const page = await this.services.repositoryReadService.search(
          {
            query: searchInput.query,
            ...optionalCursorInput(searchInput),
          },
          context,
        );
        return {
          data: { items: page.items },
          nextCursor: page.nextCursor,
          evidenceSource: phase2SourceEvidence.configRepository,
        };
      }
      case "ha_list_config_resources": {
        const resourceListInput =
          input as Phase2Input<"ha_list_config_resources">;
        const page = await this.services.repositoryResourceService.list(
          {
            resourceType: resourceListInput.resourceType,
            ...optionalCursorInput(resourceListInput),
          },
          context,
        );
        return {
          data: { items: page.items },
          nextCursor: page.nextCursor,
          evidenceSource: phase2SourceEvidence.configRepository,
        };
      }
      case "ha_get_config_resource": {
        const resourceInput = input as Phase2Input<"ha_get_config_resource">;
        const resource = await this.services.repositoryResourceService.get(
          resourceInput.resourceType,
          resourceInput.resourceId,
          context,
        );
        const { content, ...summary } = resource;
        return {
          data: {
            ...summary,
            redactedContent: content,
            sourceEvidence: phase2SourceEvidence.configRepository,
          },
          evidenceSource: phase2SourceEvidence.configRepository,
        };
      }
      case "ha_get_git_status": {
        const status = await this.services.gitReadService.status(context);
        return {
          data: {
            clean: status.entries.length === 0,
            branch: status.branch,
            changes: status.entries.map((entry) => ({
              path: entry.path,
              index: entry.index,
              worktree: entry.worktree,
            })),
            sourceEvidence: phase2SourceEvidence.gitRepository,
          },
          evidenceSource: phase2SourceEvidence.gitRepository,
        };
      }
      case "ha_get_git_diff": {
        const diffInput = input as Phase2Input<"ha_get_git_diff">;
        const diff = await this.services.gitReadService.diff(
          diffInput.paths === undefined
            ? { scope: diffInput.scope }
            : { scope: diffInput.scope, paths: diffInput.paths },
          context,
        );
        return {
          data: {
            redactedDiff: diff.patch,
            diffSha256: diff.diffSha256,
            truncated: diff.truncated,
            sourceEvidence: phase2SourceEvidence.gitRepository,
          },
          warnings: diff.warnings,
          evidenceSource: phase2SourceEvidence.gitRepository,
        };
      }
      case "ha_list_proposals": {
        const page = await this.services.proposalService.list(input, context);
        return {
          data: { items: page.items },
          nextCursor: page.nextCursor,
          evidenceSource: phase2SourceEvidence.proposalStore,
        };
      }
      case "ha_get_pending_diff":
        return {
          data: await this.services.proposalService.get(input, context),
          evidenceSource: phase2SourceEvidence.proposalStore,
        };
      case "ha_propose_config_change":
        return {
          data: await this.services.proposalService.propose(input, context),
          evidenceSource: phase2SourceEvidence.proposalStore,
        };
      case "ha_discard_proposed_change":
        return {
          data: await this.services.proposalService.discard(input, context),
          evidenceSource: phase2SourceEvidence.proposalStore,
        };
    }
  }

  private async withBoundedContext<T>(
    requestId: string,
    operationId: string,
    callerSignal: AbortSignal | undefined,
    action: (context: Phase2OperationContext) => Promise<T>,
  ): Promise<T> {
    const controller = new AbortController();
    const deadlineAt = this.clock.now() + this.timeoutMs;
    let settled = false;
    let rejectBound: ((error: Phase2RegistryError) => void) | undefined;
    const bounded = new Promise<never>((_, reject) => {
      rejectBound = reject;
    });
    const fail = (code: Phase2ErrorCode) => {
      if (settled) return;
      controller.abort();
      rejectBound?.(new Phase2RegistryError(code));
    };
    const onAbort = () => fail("operation_cancelled");
    callerSignal?.addEventListener("abort", onAbort, { once: true });
    if (callerSignal?.aborted) onAbort();
    const timer = this.clock.setTimeout(
      () => fail("deadline_exceeded"),
      Math.max(0, deadlineAt - this.clock.now()),
    );
    const operation = Promise.resolve().then(() =>
      action(
        Object.freeze({
          requestId,
          operationId,
          deadlineAt,
          signal: controller.signal,
        }),
      ),
    );
    operation.catch(() => undefined);
    try {
      return await Promise.race([operation, bounded]);
    } finally {
      settled = true;
      this.clock.clearTimeout(timer);
      callerSignal?.removeEventListener("abort", onAbort);
    }
  }

  private success(
    name: Phase2ToolName,
    requestId: string,
    result: DispatchResult,
  ): ToolResult {
    const envelope = {
      ok: true as const,
      requestId,
      data: result.data,
      warnings: [...(result.warnings ?? [])],
      evidence: [this.evidence(result.evidenceSource)],
      ...(result.nextCursor !== undefined
        ? { nextCursor: result.nextCursor }
        : {}),
    };
    const parsed = phase2ToolOutputSchemas[name].safeParse(envelope);
    return parsed.success
      ? (parsed.data as ToolResult)
      : this.failure(name, requestId, "service_unhealthy");
  }

  private failure(
    name: Phase2ToolName,
    requestId: string,
    code: Phase2ErrorCode,
  ): ToolResult {
    const envelope = {
      ok: false as const,
      requestId,
      error: { code, message: fixedErrorMessages[code] },
      warnings: [],
      evidence: [],
    };
    const parsed = phase2ToolOutputSchemas[name].safeParse(envelope);
    return parsed.success ? (parsed.data as ToolResult) : envelope;
  }

  private genericFailure(requestId: string, code: Phase2ErrorCode): ToolResult {
    return {
      ok: false,
      requestId,
      error: { code, message: fixedErrorMessages[code] },
      warnings: [],
      evidence: [],
    } as ToolResult;
  }

  private evidence(source: string): {
    readonly source: string;
    readonly observedAt: string;
  } {
    return { source, observedAt: new Date(this.clock.now()).toISOString() };
  }
}

function optionalCursorInput(input: {
  readonly limit: number;
  readonly cursor?: string | undefined;
}): { readonly limit: number; readonly cursor?: string } {
  return input.cursor === undefined
    ? { limit: input.limit }
    : { limit: input.limit, cursor: input.cursor };
}

function isPhase2ToolName(name: string): name is Phase2ToolName {
  return (phase2ToolNames as readonly string[]).includes(name);
}

function isProposalMutation(name: Phase2ToolName): boolean {
  return (
    name === "ha_propose_config_change" || name === "ha_discard_proposed_change"
  );
}

function errorCode(error: unknown): Phase2ErrorCode {
  if (error instanceof Phase2RegistryError) return error.code;
  if (error instanceof ProposalServiceError) return error.code;
  if (error instanceof RepositoryBoundaryError)
    return repositoryErrorCode(error.code);
  if (error instanceof YamlGateError) return yamlErrorCode(error.code);
  return "service_unhealthy";
}

function repositoryErrorCode(
  code: RepositoryBoundaryError["code"],
): Phase2ErrorCode {
  if (code === "capability_unavailable") return "repository_unavailable";
  return (phase2ErrorCodes as readonly string[]).includes(code)
    ? (code as Phase2ErrorCode)
    : "service_unhealthy";
}

function yamlErrorCode(code: YamlGateError["code"]): Phase2ErrorCode {
  if (
    code === "deadline_exceeded" ||
    code === "operation_cancelled" ||
    code === "file_too_large" ||
    code === "unsupported_encoding"
  )
    return code;
  if (code === "internal_failure") return "service_unhealthy";
  return "invalid_input";
}
