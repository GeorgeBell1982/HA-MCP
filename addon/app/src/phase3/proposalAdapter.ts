import { createHash } from "node:crypto";
import type { Phase3ProposalPort } from "./applyCoordinator.js";
import {
  phase3ProposalSnapshotSchema,
  phase3ReloadTargets,
  type Phase3ReloadTarget,
} from "./contracts.js";
import type {
  ProtectedProposalStore,
  StoredProposal,
} from "../proposals/storage.js";

export class Phase3ProposalAdapterError extends Error {
  constructor(
    public readonly code: "proposal_unavailable" | "proposal_identity_mismatch",
    message: string,
  ) {
    super(message);
    this.name = "Phase3ProposalAdapterError";
  }
}

export class ProtectedPhase3ProposalAdapter implements Phase3ProposalPort {
  constructor(private readonly store: ProtectedProposalStore) {}

  async load(proposalId: string) {
    const stored = await this.read(proposalId);
    const parsed = phase3ProposalSnapshotSchema.safeParse({
      proposalId: stored.public.proposalId,
      proposalStorageSha256: stored.storageSha256,
      state: stored.public.state,
      path: stored.public.path,
      expectedSha256: stored.public.expectedSha256,
      candidateSha256: stored.public.candidateSha256,
      diffSha256: stored.public.diffSha256,
      risk: stored.public.risk,
      impact: stored.public.reloadImpact,
      reloadTarget: phase3ReloadTarget(stored),
      expiresAt: stored.public.expiresAt,
    });
    if (!parsed.success)
      throw identityError("Protected proposal snapshot is invalid");
    return Object.freeze(parsed.data);
  }

  async loadCandidate(proposalId: string): Promise<Uint8Array> {
    const stored = await this.read(proposalId);
    let candidate: Buffer | undefined;
    let diff: Buffer | undefined;
    try {
      candidate = decodeProtectedText(
        stored.protected.exactCandidateBytesBase64,
      );
      diff = decodeProtectedText(stored.protected.exactDiffBytesBase64);
      if (
        digest(candidate) !== stored.public.candidateSha256 ||
        digest(diff) !== stored.public.diffSha256
      )
        throw identityError("Protected proposal content identity mismatch");
      return Uint8Array.from(candidate);
    } finally {
      candidate?.fill(0);
      diff?.fill(0);
    }
  }

  private async read(proposalId: string): Promise<StoredProposal> {
    let stored: StoredProposal;
    try {
      stored = await this.store.readExact(proposalId);
    } catch {
      throw new Phase3ProposalAdapterError(
        "proposal_unavailable",
        "Protected proposal is unavailable",
      );
    }
    if (
      stored.public.proposalId !== proposalId ||
      stored.protected.proposalId !== proposalId ||
      stored.public.idempotencyKey !== stored.protected.idempotencyKey ||
      stored.public.candidateSha256 !== stored.protected.candidateSha256 ||
      stored.public.diffSha256 !== stored.protected.diffSha256
    )
      throw identityError("Protected proposal identity mismatch");
    return stored;
  }
}

function decodeProtectedText(value: string): Buffer {
  const bytes = Buffer.from(value, "base64");
  try {
    if (bytes.toString("base64") !== value)
      throw identityError("Protected proposal encoding is invalid");
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return bytes;
  } catch (error) {
    bytes.fill(0);
    if (error instanceof Phase3ProposalAdapterError) throw error;
    throw identityError("Protected proposal encoding is invalid");
  }
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function phase3ReloadTarget(stored: StoredProposal): Phase3ReloadTarget | null {
  if (stored.public.reloadImpact !== "domain_reload") return null;
  const target = (stored.public as { readonly reloadTarget?: unknown })
    .reloadTarget;
  if ((phase3ReloadTargets as readonly unknown[]).includes(target))
    return target as Phase3ReloadTarget;
  return null;
}

function identityError(message: string): Phase3ProposalAdapterError {
  return new Phase3ProposalAdapterError("proposal_identity_mismatch", message);
}
