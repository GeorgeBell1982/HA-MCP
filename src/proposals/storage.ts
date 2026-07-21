import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, parse, resolve } from "node:path";
import { z } from "zod";
import {
  proposalPublicSchema,
  protectedProposalPayloadSchema,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import {
  RepositoryBoundaryError,
  assertOperationActive,
} from "../security/repositoryBoundary.js";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "./durability.js";

export class ProtectedWriteError extends RepositoryBoundaryError {
  constructor(
    public readonly committed: boolean,
    message: string,
  ) {
    super("service_unhealthy", message);
    this.name = "ProtectedWriteError";
  }
}
export const PROPOSAL_STORE_LIMITS = Object.freeze({
  proposals: 500,
  itemBytes: 2 * 1024 * 1024,
  aggregateBytes: 32 * 1024 * 1024,
  journals: 64,
  quarantine: 64,
  scanEntries: 4096,
});

const storageSchema = z
  .object({
    schemaVersion: z.literal(1),
    public: proposalPublicSchema,
    protected: protectedProposalPayloadSchema,
    storageSha256: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .strict();

export type StoredProposal = z.infer<typeof storageSchema>;
export interface ProtectedProposalStoreHooks {
  readonly beforeProtectedRead?: (path: string) => Promise<void>;
}
const journalSchema = z
  .object({
    schemaVersion: z.literal(1),
    operationId: z.string().uuid(),
    requestId: z.string().uuid(),
    tool: z.enum(["ha_propose_config_change", "ha_discard_proposed_change"]),
    phase: z.enum(["prepared", "effect_committed", "outcome_committed"]),
    beforeSha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/u)
      .nullable(),
    proposal: storageSchema,
    journalSha256: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .strict();

export type ProposalJournal = z.infer<typeof journalSchema>;

export function journalEnvelope(
  value: Omit<ProposalJournal, "journalSha256">,
): ProposalJournal {
  return Object.freeze({
    ...value,
    journalSha256: createHash("sha256")
      .update(canonicalJson(value))
      .digest("hex"),
  });
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function storageEnvelope(
  publicValue: StoredProposal["public"],
  protectedValue: StoredProposal["protected"],
): StoredProposal {
  const core = {
    schemaVersion: 1 as const,
    public: publicValue,
    protected: protectedValue,
  };
  return freezeStored({
    ...core,
    storageSha256: createHash("sha256")
      .update(canonicalJson(core))
      .digest("hex"),
  });
}

function currentUid(): bigint | undefined {
  return typeof process.getuid === "function"
    ? BigInt(process.getuid())
    : undefined;
}

function privateOwner(metadata: { readonly uid: bigint }): boolean {
  const uid = currentUid();
  return uid === undefined || metadata.uid === uid;
}
async function assertDirectory(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const metadata = await lstat(path, { bigint: true });
  if (
    !metadata.isDirectory() ||
    metadata.nlink < 1n ||
    !durability.privateMode(metadata.mode) ||
    !privateOwner(metadata)
  )
    throw unhealthy("Protected proposal directory is unsafe");
}

async function assertFile(
  path: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const metadata = await lstat(path, { bigint: true });
  if (
    !metadata.isFile() ||
    metadata.nlink !== 1n ||
    !durability.privateMode(metadata.mode) ||
    !privateOwner(metadata)
  )
    throw unhealthy("Protected proposal file is unsafe");
}

function isEintr(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === "EINTR"
  );
}

async function writeAllProtectedBytes(
  handle: FileHandle,
  bytes: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    try {
      const remaining = bytes.subarray(offset);
      const { bytesWritten } = await handle.write(
        remaining,
        0,
        remaining.byteLength,
        offset,
      );
      if (
        !Number.isSafeInteger(bytesWritten) ||
        bytesWritten <= 0 ||
        bytesWritten > bytes.byteLength - offset
      )
        throw unhealthy("Protected proposal write did not make progress");
      offset += bytesWritten;
    } catch (error) {
      if (isEintr(error)) continue;
      throw error;
    }
  }
}
export async function atomicProtectedWrite(
  path: string,
  bytes: Uint8Array,
  context?: Phase2OperationContext,
  checkpoint?: (
    stage: "written" | "synced" | "renamed" | "dirsynced",
  ) => Promise<void>,
  replacement:
    | { readonly kind: "create" }
    | { readonly kind: "replace"; readonly expectedSha256: string } = {
    kind: "create",
  },
  durability: Phase2DurabilityPort = strictPhase2Durability,
): Promise<void> {
  if (bytes.byteLength > PROPOSAL_STORE_LIMITS.itemBytes)
    throw unhealthy("Protected proposal item exceeds its safe boundary");
  const directory = dirname(path);
  await assertDirectory(directory, durability);
  if (context) assertOperationActive(context);
  const temporary = join(directory, `.tmp-${basename(path)}-${randomUUID()}`);
  let reservationCreated = false;
  let committed = false;
  const handle = await open(
    temporary,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
    0o600,
  );
  try {
    try {
      await writeAllProtectedBytes(handle, bytes);
      await checkpoint?.("written");
      if (context) assertOperationActive(context);
      await handle.sync();
      await checkpoint?.("synced");
    } finally {
      await handle.close();
    }
    await assertFile(temporary, durability);
  } catch (error) {
    await unlinkIfExists(temporary);
    throw error;
  }
  try {
    if (context) assertOperationActive(context);
    if (replacement.kind === "create") {
      const reservation = await open(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      try {
        await reservation.sync();
      } finally {
        await reservation.close();
      }
      reservationCreated = true;
    } else
      await assertExpectedFile(path, replacement.expectedSha256, durability);
    if (context) assertOperationActive(context);
    await rename(temporary, path);
    committed = true;
    await checkpoint?.("renamed");
    await durability.syncDirectory(directory);
    await checkpoint?.("dirsynced");
    await assertFile(path, durability);
  } catch (error) {
    if (!committed) {
      await unlinkIfExists(temporary);
      if (reservationCreated) await unlinkIfExists(path);
      throw error;
    }
    throw new ProtectedWriteError(
      true,
      "Protected write committed but durability confirmation failed",
    );
  }
}

async function unlinkIfExists(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function assertExpectedFile(
  path: string,
  expectedSha256: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  const bytes = await readProtectedFile(path, durability);
  try {
    if (createHash("sha256").update(bytes).digest("hex") !== expectedSha256)
      throw unhealthy("Protected proposal replacement identity changed");
  } finally {
    bytes.fill(0);
  }
}

async function readProtectedFile(
  path: string,
  durability: Phase2DurabilityPort,
  hooks?: ProtectedProposalStoreHooks,
): Promise<Buffer> {
  const before = await lstat(path, { bigint: true });
  if (
    !before.isFile() ||
    before.nlink !== 1n ||
    !durability.privateMode(before.mode) ||
    !privateOwner(before)
  )
    throw unhealthy("Protected proposal file is unsafe");
  if (before.size > BigInt(PROPOSAL_STORE_LIMITS.itemBytes))
    throw unhealthy("Protected proposal item exceeds its safe boundary");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened, durability))
      throw unhealthy("Protected proposal file identity changed");
    await hooks?.beforeProtectedRead?.(path);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const linked = await lstat(path, { bigint: true });
    if (
      !sameIdentity(opened, after, durability) ||
      !sameIdentity(opened, linked, durability)
    ) {
      bytes.fill(0);
      throw unhealthy("Protected proposal file identity changed");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function sameIdentity(
  left: { dev: bigint; ino: bigint; mode: bigint; nlink: bigint; uid: bigint },
  right: { dev: bigint; ino: bigint; mode: bigint; nlink: bigint; uid: bigint },
  durability: Phase2DurabilityPort,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    right.nlink === 1n &&
    durability.privateMode(right.mode) &&
    privateOwner(right)
  );
}

async function ensureProtectedRoot(
  root: string,
  durability: Phase2DurabilityPort,
): Promise<void> {
  if (!isAbsolute(root) || resolve(root) !== root)
    throw unhealthy(
      "Protected proposal root must be an absolute normalized path",
    );
  const parsed = parse(root);
  let current = parsed.root;
  for (const segment of root
    .slice(parsed.root.length)
    .split(/[\\/]/u)
    .filter(Boolean)) {
    current = join(current, segment);
    try {
      const metadata = await lstat(current, { bigint: true });
      if (!metadata.isDirectory())
        throw unhealthy("Protected proposal root traverses a non-directory");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(current, { mode: 0o700 });
    }
  }
  await assertDirectory(root, durability);
}

function fileSha256(value: StoredProposal): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}
export class ProtectedProposalStore {
  readonly proposalsPath: string;
  readonly journalsPath: string;
  readonly quarantinePath: string;
  private chain = Promise.resolve();
  private unhealthy = true;

  constructor(
    readonly root: string,
    private readonly durability: Phase2DurabilityPort = strictPhase2Durability,
    private readonly hooks: ProtectedProposalStoreHooks = {},
  ) {
    this.proposalsPath = join(root, "proposals");
    this.journalsPath = join(root, "journals");
    this.quarantinePath = join(root, "quarantine");
  }

  async initialize(): Promise<void> {
    this.unhealthy = true;
    try {
      await ensureProtectedRoot(this.root, this.durability);
      for (const path of [
        this.proposalsPath,
        this.journalsPath,
        this.quarantinePath,
      ]) {
        try {
          await mkdir(path, { mode: 0o700 });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        await assertDirectory(path, this.durability);
      }
      await this.scanBounded(
        this.quarantinePath,
        PROPOSAL_STORE_LIMITS.quarantine,
        true,
      );
      this.unhealthy = false;
      await this.readAll();
      await this.readJournals();
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, "Protected proposal store initialization failed");
    }
  }

  serialized<T>(task: () => Promise<T>): Promise<T> {
    this.assertHealthy();
    const result = this.chain.then(task, task);
    this.chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async readAll(): Promise<StoredProposal[]> {
    this.assertHealthy();
    return this.failClosedScan(
      () => this.scanProposals(),
      "Protected proposal scan failed",
    );
  }
  async readExact(proposalId: string): Promise<StoredProposal> {
    this.assertHealthy();
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        proposalId,
      )
    )
      throw unhealthy("Protected proposal identifier is invalid");
    let bytes: Uint8Array | undefined;
    try {
      bytes = await readProtectedFile(
        join(this.proposalsPath, `${proposalId}.json`),
        this.durability,
        this.hooks,
      );
      const proposal = parseStored(bytes);
      if (proposal.public.proposalId !== proposalId)
        throw unhealthy("Protected proposal identity mismatch");
      return proposal;
    } catch (error) {
      throw normalize(error, "Protected proposal read failed");
    } finally {
      bytes?.fill(0);
    }
  }

  private async scanProposals(): Promise<StoredProposal[]> {
    const names = (await readdir(this.proposalsPath)).sort();
    if (names.length > PROPOSAL_STORE_LIMITS.proposals)
      throw unhealthy("Proposal count limit exceeded");
    const output: StoredProposal[] = [];
    let total = 0;
    for (const name of names) {
      if (!/^[0-9a-f-]{36}\.json$/u.test(name))
        await this.quarantine(name, this.proposalsPath);
      else {
        const path = join(this.proposalsPath, name);
        let bytes: Uint8Array;
        try {
          bytes = await readProtectedFile(path, this.durability, this.hooks);
        } catch (error) {
          await this.quarantine(name, this.proposalsPath);
          throw error;
        }
        total += bytes.byteLength;
        if (total > PROPOSAL_STORE_LIMITS.aggregateBytes) {
          bytes.fill(0);
          throw unhealthy("Proposal storage byte limit exceeded");
        }
        try {
          output.push(parseStored(bytes));
        } catch (error) {
          await this.quarantine(name, this.proposalsPath);
          throw error;
        } finally {
          bytes.fill(0);
        }
      }
    }
    return output;
  }

  async create(
    value: StoredProposal,
    context: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    try {
      await atomicProtectedWrite(
        join(this.proposalsPath, `${value.public.proposalId}.json`),
        bytes,
        context,
        undefined,
        undefined,
        this.durability,
      );
    } finally {
      bytes.fill(0);
    }
  }

  async replace(
    value: StoredProposal,
    previous: StoredProposal,
    context: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    if (value.public.proposalId !== previous.public.proposalId)
      throw unhealthy("Protected proposal replacement identity is invalid");
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    try {
      await atomicProtectedWrite(
        join(this.proposalsPath, `${value.public.proposalId}.json`),
        bytes,
        context,
        undefined,
        { kind: "replace", expectedSha256: fileSha256(previous) },
        this.durability,
      );
    } finally {
      bytes.fill(0);
    }
  }

  async readJournals(): Promise<ProposalJournal[]> {
    this.assertHealthy();
    return this.failClosedScan(
      () => this.scanJournals(),
      "Protected proposal journal scan failed",
    );
  }

  private async scanJournals(): Promise<ProposalJournal[]> {
    const names = (await readdir(this.journalsPath)).sort();
    if (names.length > PROPOSAL_STORE_LIMITS.journals)
      throw unhealthy("Proposal journal count limit exceeded");
    const output: ProposalJournal[] = [];
    let total = 0;
    for (const name of names) {
      if (!/^[0-9a-f-]{36}\.json$/u.test(name))
        await this.quarantine(name, this.journalsPath);
      let bytes: Uint8Array;
      try {
        bytes = await readProtectedFile(
          join(this.journalsPath, name),
          this.durability,
          this.hooks,
        );
      } catch (error) {
        await this.quarantine(name, this.journalsPath);
        throw error;
      }
      total += bytes.byteLength;
      if (total > PROPOSAL_STORE_LIMITS.aggregateBytes) {
        bytes.fill(0);
        throw unhealthy("Proposal journal byte limit exceeded");
      }
      try {
        output.push(parseJournal(bytes));
      } catch {
        await this.quarantine(name, this.journalsPath);
      } finally {
        bytes.fill(0);
      }
    }
    return output;
  }

  async createJournal(
    value: ProposalJournal,
    context?: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    try {
      await atomicProtectedWrite(
        join(this.journalsPath, `${value.operationId}.json`),
        bytes,
        context,
        undefined,
        undefined,
        this.durability,
      );
    } finally {
      bytes.fill(0);
    }
  }

  async replaceJournal(
    value: ProposalJournal,
    previous: ProposalJournal,
    context?: Phase2OperationContext,
  ): Promise<void> {
    this.assertHealthy();
    if (value.operationId !== previous.operationId)
      throw unhealthy("Proposal journal replacement identity is invalid");
    const bytes = Buffer.from(canonicalJson(value), "utf8");
    try {
      await atomicProtectedWrite(
        join(this.journalsPath, `${value.operationId}.json`),
        bytes,
        context,
        undefined,
        {
          kind: "replace",
          expectedSha256: createHash("sha256")
            .update(canonicalJson(previous))
            .digest("hex"),
        },
        this.durability,
      );
    } finally {
      bytes.fill(0);
    }
  }

  async removeJournal(value: ProposalJournal): Promise<void> {
    this.assertHealthy();
    const path = join(this.journalsPath, `${value.operationId}.json`);
    await assertExpectedFile(
      path,
      createHash("sha256").update(canonicalJson(value)).digest("hex"),
      this.durability,
    );
    await unlink(path);
    await this.durability.syncDirectory(this.journalsPath);
  }
  markUnhealthy(): void {
    this.unhealthy = true;
  }
  assertHealthy(): void {
    if (this.unhealthy)
      throw unhealthy("Protected proposal store is unhealthy");
  }

  private async scanBounded(
    path: string,
    limit: number,
    quarantine: boolean,
  ): Promise<number> {
    const names = (await readdir(path)).sort();
    if (names.length > Math.min(limit, PROPOSAL_STORE_LIMITS.scanEntries))
      throw unhealthy("Protected store scan limit exceeded");
    let total = 0;
    for (const name of names) {
      if (name === "." || name === "..")
        throw unhealthy("Protected store entry is invalid");
      const bytes = await readProtectedFile(join(path, name), this.durability);
      total += bytes.byteLength;
      bytes.fill(0);
      if (total > PROPOSAL_STORE_LIMITS.aggregateBytes)
        throw unhealthy(
          `${quarantine ? "Quarantine" : "Journal"} byte limit exceeded`,
        );
    }
    return total;
  }

  private async failClosedScan<T>(
    task: () => Promise<T>,
    message: string,
  ): Promise<T> {
    try {
      return await task();
    } catch (error) {
      this.unhealthy = true;
      throw normalize(error, message);
    }
  }

  private async quarantine(name: string, from: string): Promise<never> {
    this.unhealthy = true;
    if (basename(name) !== name)
      throw unhealthy("Quarantine source name is invalid");
    const source = join(from, name);
    const metadata = await lstat(source, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink < 1n ||
      !this.durability.privateMode(metadata.mode) ||
      !privateOwner(metadata)
    )
      throw unhealthy("Protected proposal file is unsafe");
    if (metadata.size > BigInt(PROPOSAL_STORE_LIMITS.itemBytes))
      throw unhealthy("Protected proposal item exceeds its safe boundary");
    const existing = await readdir(this.quarantinePath);
    if (existing.length >= PROPOSAL_STORE_LIMITS.quarantine)
      throw unhealthy("Quarantine is full");
    const quarantinedBytes = await this.scanBounded(
      this.quarantinePath,
      PROPOSAL_STORE_LIMITS.quarantine,
      true,
    );
    if (
      BigInt(quarantinedBytes) + metadata.size >
      BigInt(PROPOSAL_STORE_LIMITS.aggregateBytes)
    )
      throw unhealthy("Quarantine byte limit exceeded");
    const destination = join(
      this.quarantinePath,
      `${Date.now()}-${randomUUID()}.quarantine`,
    );
    const reservation = await open(
      destination,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    try {
      await reservation.close();
    } catch (error) {
      throw normalize(error, "Quarantine reservation failed");
    }
    await rename(source, destination);
    await this.durability.syncDirectory(from);
    await this.durability.syncDirectory(this.quarantinePath);
    throw unhealthy("Unsafe protected proposal artifact was quarantined");
  }
}

function freezeStored(value: StoredProposal): StoredProposal {
  Object.freeze(value.public.validationPlan);
  Object.freeze(value.public);
  Object.freeze(value.protected);
  return Object.freeze(value);
}
function parseJournal(bytes: Uint8Array): ProposalJournal {
  let unknown: unknown;
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  try {
    unknown = JSON.parse(text);
  } catch {
    throw unhealthy("Protected proposal journal is invalid");
  }
  const parsed = journalSchema.safeParse(unknown);
  if (!parsed.success || canonicalJson(parsed.data) !== text)
    throw unhealthy("Protected proposal journal is non-canonical");
  const { journalSha256, ...core } = parsed.data;
  if (
    createHash("sha256").update(canonicalJson(core)).digest("hex") !==
    journalSha256
  )
    throw unhealthy("Protected proposal journal digest mismatch");
  freezeStored(parsed.data.proposal);
  return Object.freeze(parsed.data);
}
function parseStored(bytes: Uint8Array): StoredProposal {
  let unknown: unknown;
  try {
    unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    throw unhealthy("Protected proposal file is invalid");
  }
  const parsed = storageSchema.safeParse(unknown);
  if (
    !parsed.success ||
    canonicalJson(parsed.data) !== new TextDecoder().decode(bytes)
  )
    throw unhealthy("Protected proposal file is non-canonical");
  const { storageSha256, ...core } = parsed.data;
  if (
    createHash("sha256").update(canonicalJson(core)).digest("hex") !==
    storageSha256
  )
    throw unhealthy("Protected proposal file digest mismatch");
  return freezeStored(parsed.data);
}

function unhealthy(message: string): RepositoryBoundaryError {
  return new RepositoryBoundaryError("service_unhealthy", message);
}

function normalize(error: unknown, message: string): RepositoryBoundaryError {
  return error instanceof RepositoryBoundaryError ? error : unhealthy(message);
}
