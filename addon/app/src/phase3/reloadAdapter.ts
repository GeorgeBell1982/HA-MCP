import {
  type Phase3PolicyPort,
  Phase3CoordinatorError,
  type Phase3OperationContext,
  type Phase3ReloadPort,
} from "./applyCoordinator.js";
import { phase3ReloadTargets, type Phase3ReloadTarget } from "./contracts.js";
import { canonicalPhase3Path } from "./resourceLocks.js";
import { randomUUID } from "node:crypto";
import type { RepositoryResourceService } from "../repository/resourceProjection.js";
import type { Phase3ProposalSnapshot } from "./contracts.js";

type AutomationTopologyReader = Pick<
  RepositoryResourceService,
  "inspectAutomationReload"
>;

export class AutomationPhase3AdmissionPolicy implements Phase3PolicyPort {
  constructor(
    private readonly base: Phase3PolicyPort,
    private readonly resources: AutomationTopologyReader,
  ) {}

  async evaluate(
    proposal: Phase3ProposalSnapshot,
    context?: Phase3OperationContext,
  ) {
    const base = await this.base.evaluate(proposal, context);
    if (!base.allowed) return base;
    if (
      proposal.path !== "automations.yaml" ||
      proposal.impact !== "domain_reload" ||
      proposal.reloadTarget !== "automation.reload"
    )
      return {
        allowed: false as const,
        code: "unsupported_automation",
        message: "Only explicit automation reload proposals are supported",
      };
    try {
      const evidence = await this.resources.inspectAutomationReload(
        topologyContext(context),
      );
      if (
        context?.signal.aborted ||
        (context && Date.now() >= context.deadlineAt)
      )
        throw new Error("Inactive operation");
      if (
        !evidence.supported ||
        evidence.sourceSha256 !== proposal.expectedSha256
      )
        return {
          allowed: false as const,
          code: "automation_topology_changed",
          message: "Automation topology or source is unavailable or changed",
        };
      return { allowed: true as const };
    } catch {
      if (context?.signal.aborted)
        return {
          allowed: false as const,
          code: "operation_cancelled",
          message: "Operation was cancelled",
        };
      if (context && Date.now() >= context.deadlineAt)
        return {
          allowed: false as const,
          code: "deadline_exceeded",
          message: "Operation deadline exceeded",
        };
      return {
        allowed: false as const,
        code: "automation_topology_unhealthy",
        message: "Automation topology could not be proved",
      };
    }
  }
}

export class AutomationPhase3ReloadCatalog implements Phase3ReloadCatalogPort {
  constructor(private readonly resources: AutomationTopologyReader) {}

  async resolve(
    path: string,
    context: Phase3OperationContext,
  ): Promise<Phase3ReloadResolution> {
    if (path !== "automations.yaml")
      return Object.freeze({ status: "unavailable" });
    try {
      const evidence = await this.resources.inspectAutomationReload(
        topologyContext(context),
      );
      return evidence.supported
        ? Object.freeze({ status: "resolved", target: "automation.reload" })
        : Object.freeze({ status: "unavailable" });
    } catch {
      return Object.freeze({ status: "unhealthy" });
    }
  }
}

function topologyContext(context?: Phase3OperationContext) {
  return {
    requestId: randomUUID(),
    operationId: randomUUID(),
    signal: context?.signal ?? new AbortController().signal,
    deadlineAt: context?.deadlineAt ?? Date.now() + 60_000,
  };
}

export const phase3ReloadResolutionStatuses = Object.freeze([
  "resolved",
  "unavailable",
  "ambiguous",
  "unhealthy",
] as const);
export type Phase3ReloadResolutionStatus =
  (typeof phase3ReloadResolutionStatuses)[number];

export const phase3ReloadDispatchOutcomes = Object.freeze([
  "completed",
  "not_dispatched",
  "outcome_unknown",
] as const);
export type Phase3ReloadDispatchOutcome =
  (typeof phase3ReloadDispatchOutcomes)[number];

export const phase3ReloadStages = Object.freeze([
  "input",
  "resolution",
  "dispatch",
] as const);
export type Phase3ReloadStage = (typeof phase3ReloadStages)[number];

export const phase3ReloadErrorCodes = Object.freeze([
  "invalid_path",
  "operation_cancelled",
  "deadline_exceeded",
  "reload_unavailable",
  "reload_ambiguous",
  "reload_catalog_unhealthy",
  "reload_target_mismatch",
  "reload_not_dispatched",
  "reload_outcome_unknown",
  "internal_failure",
] as const);
export type Phase3ReloadErrorCode = (typeof phase3ReloadErrorCodes)[number];

export type Phase3ReloadResolution =
  | Readonly<{ status: "resolved"; target: Phase3ReloadTarget }>
  | Readonly<{
      status: Exclude<Phase3ReloadResolutionStatus, "resolved">;
    }>;

export type Phase3ReloadDispatchResult = Readonly<{
  status: Phase3ReloadDispatchOutcome;
}>;

export interface Phase3ReloadCatalogPort {
  resolve(
    canonicalPath: string,
    context: Phase3OperationContext,
  ): Promise<Phase3ReloadResolution>;
}

export interface Phase3ReloadServicePort {
  reload(
    target: Phase3ReloadTarget,
    context: Phase3OperationContext,
  ): Promise<Phase3ReloadDispatchResult>;
}

type ResolutionEvidence =
  | Phase3ReloadResolutionStatus
  | "mismatch"
  | "not_attempted";
type DispatchEvidence = Phase3ReloadDispatchOutcome | "not_attempted";

export class Phase3ReloadError extends Phase3CoordinatorError {
  public readonly target?: Phase3ReloadTarget;

  constructor(
    public override readonly code: Phase3ReloadErrorCode,
    public readonly stage: Phase3ReloadStage,
    public readonly resolution: ResolutionEvidence = "not_attempted",
    public readonly dispatch: DispatchEvidence = "not_attempted",
    target?: Phase3ReloadTarget,
  ) {
    super(code, reloadMessage(code));
    this.name = "Phase3ReloadError";
    if (target !== undefined) this.target = target;
  }
}

export class NarrowPhase3ReloadAdapter implements Phase3ReloadPort {
  constructor(
    private readonly catalog: Phase3ReloadCatalogPort,
    private readonly service: Phase3ReloadServicePort,
  ) {}

  async reloadDomain(
    request: Readonly<{ path: string; target: Phase3ReloadTarget }>,
    context: Phase3OperationContext,
  ): Promise<void> {
    const canonicalPath = canonicalReloadPath(request.path);
    const target = canonicalReloadTarget(request.target);
    assertActive(context, "input");

    let resolution: Phase3ReloadResolution;
    try {
      const foreignResolution = await this.catalog.resolve(
        canonicalPath,
        context,
      );
      const parsedResolution = parseReloadResolution(foreignResolution);
      if (parsedResolution === undefined)
        throw new Error("invalid reload resolution");
      resolution = parsedResolution;
    } catch {
      throw new Phase3ReloadError("internal_failure", "resolution");
    }

    if (resolution.status !== "resolved")
      throw resolutionError(resolution.status);
    if (resolution.target !== target)
      throw new Phase3ReloadError(
        "reload_target_mismatch",
        "resolution",
        "mismatch",
        "not_attempted",
        target,
      );

    assertActive(context, "dispatch", target);
    let result: Phase3ReloadDispatchResult;
    try {
      const foreignResult = await this.service.reload(target, context);
      const parsedResult = parseDispatchResult(foreignResult);
      if (parsedResult === undefined)
        throw new Error("invalid reload dispatch result");
      result = parsedResult;
    } catch {
      throw new Phase3ReloadError(
        "reload_outcome_unknown",
        "dispatch",
        "resolved",
        "outcome_unknown",
        target,
      );
    }

    if (result.status === "completed") return;
    throw new Phase3ReloadError(
      result.status === "not_dispatched"
        ? "reload_not_dispatched"
        : "reload_outcome_unknown",
      "dispatch",
      "resolved",
      result.status,
      target,
    );
  }
}

function canonicalReloadTarget(target: Phase3ReloadTarget): Phase3ReloadTarget {
  if ((phase3ReloadTargets as readonly unknown[]).includes(target))
    return target;
  throw new Phase3ReloadError("internal_failure", "input");
}

function canonicalReloadPath(path: string): string {
  try {
    return canonicalPhase3Path(path);
  } catch {
    throw new Phase3ReloadError("invalid_path", "input");
  }
}

function assertActive(
  context: Phase3OperationContext,
  stage: Phase3ReloadStage,
  target?: Phase3ReloadTarget,
): void {
  if (context.signal.aborted)
    throw new Phase3ReloadError(
      "operation_cancelled",
      stage,
      target === undefined ? "not_attempted" : "resolved",
      "not_attempted",
      target,
    );
  if (!Number.isFinite(context.deadlineAt) || Date.now() >= context.deadlineAt)
    throw new Phase3ReloadError(
      "deadline_exceeded",
      stage,
      target === undefined ? "not_attempted" : "resolved",
      "not_attempted",
      target,
    );
}

function resolutionError(
  status: Exclude<Phase3ReloadResolutionStatus, "resolved">,
): Phase3ReloadError {
  const code: Phase3ReloadErrorCode =
    status === "unavailable"
      ? "reload_unavailable"
      : status === "ambiguous"
        ? "reload_ambiguous"
        : "reload_catalog_unhealthy";
  return new Phase3ReloadError(code, "resolution", status);
}

function parseReloadResolution(
  value: unknown,
): Phase3ReloadResolution | undefined {
  const status = frozenValue(value, "status");
  if (
    (status === "unavailable" ||
      status === "ambiguous" ||
      status === "unhealthy") &&
    hasExactKeys(value, ["status"])
  )
    return Object.freeze({ status });
  if (status !== "resolved") return undefined;
  const target = frozenValue(value, "target");
  if (
    !hasExactKeys(value, ["status", "target"]) ||
    !(phase3ReloadTargets as readonly unknown[]).includes(target)
  )
    return undefined;
  return Object.freeze({
    status,
    target: target as Phase3ReloadTarget,
  });
}

function parseDispatchResult(
  value: unknown,
): Phase3ReloadDispatchResult | undefined {
  const status = frozenValue(value, "status");
  if (
    !hasExactKeys(value, ["status"]) ||
    !(phase3ReloadDispatchOutcomes as readonly unknown[]).includes(status)
  )
    return undefined;
  return Object.freeze({ status: status as Phase3ReloadDispatchOutcome });
}

function hasExactKeys(
  value: unknown,
  expectedKeys: readonly string[],
): boolean {
  if (typeof value !== "object" || value === null || !Object.isFrozen(value))
    return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((expected) => keys.includes(expected))
  );
}

function frozenValue(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null || !Object.isFrozen(value))
    return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

function reloadMessage(code: Phase3ReloadErrorCode): string {
  return `Phase 3 domain reload failed: ${code}`;
}
