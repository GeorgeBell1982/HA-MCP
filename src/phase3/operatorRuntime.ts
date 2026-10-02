import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, lstat, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { Config } from "../config.js";
import type { ToolCallContext } from "../toolRegistry.js";
import {
  ProductionSecretValueProvider,
  PHASE2_FIXED_ADDON_PATHS,
  PHASE2_FIXED_ARTIFACT_PATHS,
} from "../phase2Activation.js";
import { ProtectedProposalStore } from "../proposals/storage.js";
import {
  NativeOpenat2Catalog,
  RepositoryCursorCodec,
} from "../repository/repositoryReads.js";
import { RepositoryResourceService } from "../repository/resourceProjection.js";
import {
  NativeOpenat2Reader,
  ProtectedIdentityRegistry,
} from "../security/repositoryBoundary.js";
import { strictPhase2Durability } from "../proposals/durability.js";
import {
  loadPhase3ApprovalKey,
  provisionPhase3ApprovalKey,
  PHASE3_APPROVAL_KEY_STATE_DIRECTORY,
  Phase3ApprovalKeyError,
} from "./approvalKey.js";
import {
  Phase3ApplyCoordinator,
  GuardedPhase3PolicyPort,
  Phase3CoordinatorError,
} from "./applyCoordinator.js";
import { NativePhase3AtomicApply } from "./atomicApply.js";
import { HomeAssistantAutomationBoundary } from "./automationHaBoundary.js";
import { HomeAssistantPhase3Client } from "./homeAssistantAdapter.js";
import {
  approveAndApplyProposal,
  approveAndApplyMcpProposal,
  Phase3OperatorError,
  type Phase3OperatorTerminal,
} from "./operatorApproval.js";
import { Phase3OperatorAudit } from "./operatorAudit.js";
import { approveAndRecoverPhase3 } from "./operatorRecovery.js";
import { acquirePhase3OperatorLease } from "./operatorLease.js";
import { ProtectedPhase3ProposalAdapter } from "./proposalAdapter.js";
import {
  AutomationPhase3AdmissionPolicy,
  AutomationPhase3ReloadCatalog,
  NarrowPhase3ReloadAdapter,
} from "./reloadAdapter.js";
import { Phase3ResourceLocks } from "./resourceLocks.js";
import { Phase3OfflineRetention, type Phase3EpochStores } from "./retention.js";
import { ProtectedPhase3SourceAdapter } from "./sourceAdapter.js";
import { NarrowPhase3VerificationAdapter } from "./verificationAdapter.js";

export const PHASE3_OPERATOR_PARENT = "/data/phase3-runtime";
const atomicHelper = "/app/native/openat2-replace";
export type Phase3OperatorCommand =
  | { readonly operation: "init" | "rotate" | "resume" }
  | { readonly operation: "recover" }
  | { readonly operation: "apply-proposal"; readonly proposalId: string };

/** There is no --yes, grant input, approver input, path override, or environment enablement. */
export function parsePhase3OperatorCommand(
  args: readonly string[],
): Phase3OperatorCommand {
  if (args.length === 1 && ["init", "rotate", "resume"].includes(args[0]!))
    return { operation: args[0] as "init" | "rotate" | "resume" };
  if (
    args.length === 2 &&
    args[0] === "recover" &&
    args[1] === "--enable-writes"
  )
    return { operation: "recover" };
  if (
    args.length === 3 &&
    args[0] === "apply-proposal" &&
    args[2] === "--enable-writes" &&
    z.string().uuid().safeParse(args[1]).success &&
    args[1] === args[1]!.toLowerCase()
  )
    return { operation: "apply-proposal", proposalId: args[1] };
  throw new Phase3OperatorError("invalid_command_or_writes_disabled");
}

/** Explicit local operator composition. */
export async function runPhase3OperatorCommand(
  args: readonly string[],
  config: Config,
  terminal: Phase3OperatorTerminal,
) {
  const command = parsePhase3OperatorCommand(args);
  if (!terminal.inputIsTTY || !terminal.outputIsTTY)
    throw new Phase3OperatorError("interactive_terminal_required");
  return runPhase3Command(command, config, { terminal });
}

/** Only the opt-in registry can reach this composition with transport approval. */
export async function runPhase3McpCommand(
  command:
    | { readonly operation: "apply-proposal"; readonly proposalId: string }
    | { readonly operation: "rotate" },
  config: Config,
  context: ToolCallContext,
) {
  if (
    !config.enableMcpWrites ||
    !config.enablePhase2 ||
    config.mode !== "addon"
  )
    throw new Phase3OperatorError("mcp_writes_disabled");
  if (!context.requestApproval)
    throw new Phase3OperatorError("chat_approval_unavailable");
  if (context.signal.aborted)
    throw new Phase3OperatorError("operation_inactive");
  if (command.operation !== "apply-proposal" && command.operation !== "rotate")
    throw new Phase3OperatorError("invalid_command");
  if (
    command.operation === "apply-proposal" &&
    (!z.string().uuid().safeParse(command.proposalId).success ||
      command.proposalId !== command.proposalId.toLowerCase())
  )
    throw new Phase3OperatorError("invalid_command");
  return runPhase3Command(command, config, { mcp: context });
}

async function runPhase3Command(
  command: Phase3OperatorCommand,
  config: Config,
  interaction:
    | { readonly terminal: Phase3OperatorTerminal }
    | { readonly mcp: ToolCallContext },
) {
  const terminal = "terminal" in interaction ? interaction.terminal : undefined;
  if (process.platform !== "linux" || config.mode !== "addon")
    throw new Phase3OperatorError("managed_linux_operator_required");
  await requireDirectory("/data", false);
  if (command.operation === "init") {
    await createDirectory(PHASE3_OPERATOR_PARENT);
  }
  const lease = await acquirePhase3OperatorLease(PHASE3_OPERATOR_PARENT);
  let key: Awaited<ReturnType<typeof loadPhase3ApprovalKey>> | undefined;
  let epoch: Phase3EpochStores | undefined;
  let cursors: RepositoryCursorCodec | undefined;
  let operationFailed = false;
  let settled: { transactionId: string; state: string } | undefined;
  let cleaned = true;
  const execute = async () => {
    try {
      // Initialization is explicit. Apply/recovery never invent or replace approval keys.
      if (command.operation === "init") {
        await assertPhase3BootstrapParentIsFresh(PHASE3_OPERATOR_PARENT, lease);
        await createDirectory(PHASE3_APPROVAL_KEY_STATE_DIRECTORY);
        try {
          key = await loadPhase3ApprovalKey();
        } catch (error) {
          if (
            !(error instanceof Error) ||
            !("code" in error) ||
            error.code !== "approval_key_missing"
          )
            throw error;
          await provisionPhase3ApprovalKey();
        }
      }
      key ??= await loadPhase3ApprovalKey();
      const retention = new Phase3OfflineRetention(
        PHASE3_OPERATOR_PARENT,
        key.key,
      );
      if (command.operation === "init") {
        epoch = await retention.initialize(lease);
        return { ok: true, operation: "init", writesEnabled: false };
      }
      for (const helper of [
        PHASE2_FIXED_ARTIFACT_PATHS.readHelperPath,
        PHASE2_FIXED_ARTIFACT_PATHS.catalogHelperPath,
      ])
        await requireHelper(helper);
      if (
        command.operation === "apply-proposal" ||
        command.operation === "recover"
      ) {
        await requireHelper(atomicHelper);
        try {
          await access(PHASE2_FIXED_ADDON_PATHS.repositoryRoot, constants.W_OK);
        } catch {
          throw new Phase3OperatorError("operator_repository_read_only");
        }
      }
      await requireDirectory(PHASE2_FIXED_ADDON_PATHS.proposalRoot);
      const store = new ProtectedProposalStore(
        PHASE2_FIXED_ADDON_PATHS.proposalRoot,
      );
      await store.initialize();
      const reader = new NativeOpenat2Reader({
        root: PHASE2_FIXED_ADDON_PATHS.repositoryRoot,
        helperPath: PHASE2_FIXED_ARTIFACT_PATHS.readHelperPath,
        maximumConcurrentHelpers: 1,
      });
      const catalog = new NativeOpenat2Catalog({
        root: PHASE2_FIXED_ADDON_PATHS.repositoryRoot,
        helperPath: PHASE2_FIXED_ARTIFACT_PATHS.catalogHelperPath,
        maximumConcurrentHelpers: 1,
      });
      const registry = new ProtectedIdentityRegistry(reader);
      const context = {
        signal:
          "mcp" in interaction
            ? interaction.mcp.signal
            : new AbortController().signal,
        deadlineAt: Date.now() + 300_000,
      };
      await registry.initialize(
        ["secrets.yaml"],
        new ProductionSecretValueProvider(),
        { ...context, operationId: randomUUID(), requestId: randomUUID() },
      );
      const cursorKey = randomBytes(32);
      try {
        cursors = new RepositoryCursorCodec(cursorKey);
      } finally {
        cursorKey.fill(0);
      }
      const resources = new RepositoryResourceService(
        catalog,
        reader,
        registry,
        cursors,
      );
      const source = new ProtectedPhase3SourceAdapter(catalog, registry);
      const proposals = new ProtectedPhase3ProposalAdapter(store);
      const boundary = new HomeAssistantAutomationBoundary(config, source);
      const locks = new Phase3ResourceLocks();
      const coordinator = (stores: Phase3EpochStores) =>
        new Phase3ApplyCoordinator({
          proposals,
          policy: new AutomationPhase3AdmissionPolicy(
            new GuardedPhase3PolicyPort({
              writesEnabled: true,
              applyCapability: true,
              domainReloadCapability: true,
            }),
            resources,
          ),
          approvals: stores.approvals,
          locks,
          source,
          validation: boundary,
          checkpoints: stores.checkpoints,
          atomicApply: new NativePhase3AtomicApply({
            root: PHASE2_FIXED_ADDON_PATHS.repositoryRoot,
            helperPath: atomicHelper,
            maxConcurrent: 1,
            maxWaiters: 1,
          }),
          reload: new NarrowPhase3ReloadAdapter(
            new AutomationPhase3ReloadCatalog(resources),
            new HomeAssistantPhase3Client(config),
          ),
          verification: new NarrowPhase3VerificationAdapter(source, boundary),
          journal: stores.journal,
        });
      if (command.operation === "rotate" || command.operation === "resume") {
        if ("mcp" in interaction) {
          const current = await retention.open(lease);
          try {
            if ((await current.journal.listRecoverable()).length !== 1)
              throw new Phase3OperatorError("completed_transaction_required");
          } finally {
            await current.approvals.close();
          }
        }
        const archive = await retention[command.operation](lease, (stores) =>
          coordinator(stores).recover(),
        );
        return { ok: true, operation: command.operation, archive };
      }
      epoch = await retention.open(lease);
      if (command.operation === "recover") {
        const result = await approveAndRecoverPhase3(
          {
            terminal: terminal!,
            journal: epoch.journal,
            coordinator: coordinator(epoch),
            audit: new Phase3OperatorAudit(
              join(epoch.root, "operator.jsonl"),
              lease,
            ),
          },
          context,
        );
        return {
          ok: !result.some((item) => item.manualAttentionRequired),
          operation: "recover",
          result,
        };
      }
      if ((await epoch.journal.listRecoverable()).length !== 0)
        throw new Phase3OperatorError("epoch_rotation_required");
      if (command.operation !== "apply-proposal")
        throw new Phase3OperatorError("invalid_command");
      const ports = {
        store,
        registry,
        proposals,
        approvals: epoch.approvals,
        coordinator: coordinator(epoch),
        audit: new Phase3OperatorAudit(
          join(epoch.root, "operator.jsonl"),
          lease,
        ),
      };
      const record =
        "mcp" in interaction
          ? await approveAndApplyMcpProposal(
              command.proposalId,
              ports,
              context,
              interaction.mcp.requestApproval!,
            )
          : await approveAndApplyProposal(
              command.proposalId,
              { ...ports, terminal: terminal! },
              context,
            );
      settled = { transactionId: record.transactionId, state: record.state };
      return {
        ok: record.state === "verification_succeeded",
        operation: "apply-proposal",
        transactionId: record.transactionId,
        state: record.state,
      };
    } catch (error) {
      operationFailed = true;
      throw error;
    } finally {
      cleaned = await completePhase3Cleanup([
        () => epoch?.approvals.close(),
        () => cursors?.close(),
        () => key?.release(),
        () => lease.release(),
      ]);
    }
  };
  const result = await execute();
  if (!cleaned && !operationFailed) {
    if (settled)
      throw new Phase3OperatorCleanupUncertain(
        settled.transactionId,
        settled.state,
      );
    throw new Phase3OperatorError("operator_cleanup_uncertain");
  }
  return result;
}

export class Phase3OperatorCleanupUncertain extends Phase3OperatorError {
  constructor(
    public readonly transactionId: string,
    public readonly state: string,
  ) {
    super("post_settlement_cleanup_uncertain");
  }
}

/** Every cleanup is attempted in order, including release of the shared OS lease. */
export async function completePhase3Cleanup(
  cleanups: readonly (() => void | Promise<void>)[],
): Promise<boolean> {
  let completed = true;
  for (const cleanup of cleanups) {
    try {
      await cleanup();
    } catch {
      completed = false;
    }
  }
  return completed;
}

export async function assertPhase3BootstrapParentIsFresh(
  parent: string,
  lease: { assertHeld(): Promise<void> },
) {
  await lease.assertHeld();
  if ((await readdir(parent)).some((name) => name !== "operator.lock"))
    throw new Phase3OperatorError("bootstrap_state_not_fresh");
}

export function phase3OperatorFailureDetails(error: unknown): {
  code: string;
  transactionId?: string;
  state?: string;
} {
  if (
    error instanceof Phase3OperatorError ||
    error instanceof Phase3ApprovalKeyError ||
    error instanceof Phase3CoordinatorError
  ) {
    const code = /^[a-z0-9_]{1,80}$/u.test(error.code)
      ? error.code
      : "operator_unavailable";
    const identity =
      error instanceof Phase3OperatorError &&
      "transactionId" in error &&
      typeof error.transactionId === "string" &&
      z.string().uuid().safeParse(error.transactionId).success
        ? { transactionId: error.transactionId }
        : {};
    const state =
      error instanceof Phase3OperatorError &&
      "state" in error &&
      typeof error.state === "string" &&
      /^[a-z_]{1,80}$/u.test(error.state)
        ? { state: error.state }
        : {};
    return { code, ...identity, ...state };
  }
  return { code: "operator_storage_or_boundary_unavailable" };
}

async function requireDirectory(path: string, privateDirectory = true) {
  const stat = await lstat(path, { bigint: true });
  if (
    !stat.isDirectory() ||
    stat.uid !== BigInt(process.getuid!()) ||
    (stat.mode & (privateDirectory ? 0o077n : 0o022n)) !== 0n
  )
    throw new Phase3OperatorError("operator_directory_unsafe");
}
async function createDirectory(path: string) {
  try {
    await mkdir(path, { mode: 0o700 });
    await strictPhase2Durability.syncDirectory("/data");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  await requireDirectory(path);
}
async function requireHelper(path: string) {
  const stat = await lstat(path, { bigint: true });
  if (
    !stat.isFile() ||
    stat.uid !== 0n ||
    stat.nlink !== 1n ||
    (stat.mode & 0o022n) !== 0n ||
    (stat.mode & 0o111n) === 0n
  )
    throw new Phase3OperatorError("operator_helper_unavailable");
}
