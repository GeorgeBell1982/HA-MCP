import { randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { isAbsolute, join, parse, resolve } from "node:path";
import { z } from "zod";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "../proposals/durability.js";
import { DurablePhase3ApprovalGrants } from "./durableApproval.js";
import { DurablePhase3Checkpoints } from "./checkpoints.js";
import { DurablePhase3Journal } from "./journal.js";
import {
  sha256,
  type Phase3RecoveryResult,
  type Phase3TransactionRecord,
} from "./contracts.js";
import { validatePhase3OperatorAudit } from "./operatorAudit.js";

export interface Phase3OfflineLease {
  /** Must assert an actually held, process-exclusive operating-system lease. */
  readonly assertHeld: () => Promise<void>;
}

export interface Phase3EpochStores {
  readonly root: string;
  readonly journal: DurablePhase3Journal;
  readonly checkpoints: DurablePhase3Checkpoints;
  readonly approvals: DurablePhase3ApprovalGrants;
}

export type Phase3RetentionProof = (
  stores: Phase3EpochStores,
) => Promise<readonly Phase3RecoveryResult[]>;

export type Phase3RetentionStage =
  | "marker_synced"
  | "archive_renamed"
  | "archive_parent_synced"
  | "active_created"
  | "stores_initialized";

const markerSchema = z
  .object({
    version: z.literal(1),
    archive: z
      .string()
      .regex(
        /^archive-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
    device: z.string().regex(/^\d+$/),
    inode: z.string().regex(/^\d+$/),
  })
  .strict();
type RotationMarker = z.infer<typeof markerSchema>;
const archivePattern =
  /^archive-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const storeNames = ["journal", "checkpoints", "approvals"] as const;

/** Offline, one-transaction epochs. Archives are preserved, never pruned. */
export class Phase3OfflineRetention {
  private readonly durability: Phase2DurabilityPort;
  private readonly native: boolean;
  private readonly maximumArchives: number;
  private readonly maximumArchiveBytes: number;
  private readonly afterStage: (stage: Phase3RetentionStage) => Promise<void>;
  private busy = false;

  constructor(
    readonly parent: string,
    private readonly key: Uint8Array,
    options: {
      readonly durability?: Phase2DurabilityPort;
      readonly maximumArchives?: number;
      readonly maximumArchiveBytes?: number;
      readonly afterStage?: (stage: Phase3RetentionStage) => Promise<void>;
    } = {},
  ) {
    if (
      !isAbsolute(parent) ||
      resolve(parent) !== parent ||
      key.byteLength !== 32
    )
      throw new Error("Invalid Phase 3 retention configuration");
    this.native = options.durability === undefined;
    this.durability = options.durability ?? strictPhase2Durability;
    this.maximumArchives = options.maximumArchives ?? 256;
    this.maximumArchiveBytes = options.maximumArchiveBytes ?? 256 * 1024 * 1024;
    if (
      !Number.isSafeInteger(this.maximumArchives) ||
      this.maximumArchives < 1 ||
      this.maximumArchives > 512 ||
      !Number.isSafeInteger(this.maximumArchiveBytes) ||
      this.maximumArchiveBytes < 1 ||
      this.maximumArchiveBytes > 1024 * 1024 * 1024
    )
      throw new Error("Invalid Phase 3 archive budgets");
    this.afterStage = options.afterStage ?? (() => Promise.resolve());
  }

  /** Explicit bootstrap; existing or interrupted epochs are never repaired here. */
  initialize(lease: Phase3OfflineLease): Promise<Phase3EpochStores> {
    return this.exclusive(lease, async () => {
      const names = await this.parentEntries();
      if (names.some((name) => name !== "operator.lock"))
        throw new Error(
          "Phase 3 retention initialization requires an empty parent",
        );
      await this.createActive(lease);
      return this.stores(join(this.parent, "active"));
    });
  }

  open(lease: Phase3OfflineLease): Promise<Phase3EpochStores> {
    return this.exclusive(lease, async () => {
      const names = await this.parentEntries();
      if (names.includes("rotation.json") || !names.includes("active"))
        throw new Error("Phase 3 epoch requires explicit offline resume");
      await this.validateEpoch(join(this.parent, "active"));
      const stores = await this.stores(join(this.parent, "active"));
      try {
        if ((await stores.journal.listRecoverable()).length > 1)
          throw new Error("Phase 3 epoch contains multiple transactions");
        return stores;
      } catch (error) {
        await stores.approvals.close();
        throw error;
      }
    });
  }

  rotate(
    lease: Phase3OfflineLease,
    proof: Phase3RetentionProof,
  ): Promise<string> {
    return this.exclusive(lease, async () => {
      const names = await this.parentEntries();
      if (names.includes("rotation.json") || !names.includes("active"))
        throw new Error("Phase 3 epoch requires explicit offline resume");
      const active = join(this.parent, "active");
      await this.eligible(active, proof);
      await this.budget(active, names);
      const metadata = await this.directory(active);
      const marker: RotationMarker = {
        version: 1,
        archive: `archive-${randomUUID()}`,
        device: metadata.dev.toString(),
        inode: metadata.ino.toString(),
      };
      if (names.includes(marker.archive))
        throw new Error("Phase 3 rotation archive already exists");
      await lease.assertHeld();
      const handle = await open(
        join(this.parent, "rotation.json"),
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      try {
        await handle.writeFile(JSON.stringify(marker));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await this.durability.syncDirectory(this.parent);
      await this.afterStage("marker_synced");
      await this.finish(marker, lease, proof, true);
      return join(this.parent, marker.archive);
    });
  }

  resume(
    lease: Phase3OfflineLease,
    proof: Phase3RetentionProof,
  ): Promise<string> {
    return this.exclusive(lease, async () => {
      await this.parentEntries();
      const marker = markerSchema.parse(
        JSON.parse(
          (await this.file(join(this.parent, "rotation.json"), 1024)).toString(
            "utf8",
          ),
        ),
      );
      await this.finish(marker, lease, proof, false);
      return join(this.parent, marker.archive);
    });
  }

  private async finish(
    marker: RotationMarker,
    lease: Phase3OfflineLease,
    proof: Phase3RetentionProof,
    alreadyChecked: boolean,
  ): Promise<void> {
    const archive = join(this.parent, marker.archive);
    const active = join(this.parent, "active");
    let archived = await this.exists(archive);
    if (!archived) {
      const before = await this.directory(active);
      this.assertMarkerIdentity(before, marker);
      // Marker fsync may take time. Re-prove all evidence immediately before rename.
      if (!alreadyChecked)
        await this.budget(active, await this.parentEntries());
      await this.eligible(active, proof);
      const after = await this.directory(active);
      this.assertMarkerIdentity(after, marker);
      await lease.assertHeld();
      await rename(active, archive);
      await this.afterStage("archive_renamed");
      await this.durability.syncDirectory(this.parent);
      await this.afterStage("archive_parent_synced");
      archived = true;
    }
    if (archived) {
      this.assertMarkerIdentity(await this.directory(archive), marker);
      // A resume must re-prove current live state; never recover unsafe archives.
      if (!alreadyChecked) await this.eligible(archive, proof);
      if (await this.exists(active)) {
        await this.validateFreshActive(active);
      } else {
        await lease.assertHeld();
        await mkdir(active, { mode: 0o700 });
        await this.durability.syncDirectory(this.parent);
        await this.afterStage("active_created");
      }
      for (const name of storeNames) {
        if (!(await this.exists(join(active, name)))) {
          await lease.assertHeld();
          await mkdir(join(active, name), { mode: 0o700 });
        }
      }
      await this.durability.syncDirectory(active);
      const stores = await this.stores(active);
      await stores.approvals.close();
      await this.afterStage("stores_initialized");
      await lease.assertHeld();
      await unlink(join(this.parent, "rotation.json"));
      await this.durability.syncDirectory(this.parent);
    }
  }

  private async eligible(
    root: string,
    proof: Phase3RetentionProof,
  ): Promise<void> {
    await this.validateEpoch(root);
    const stores = await this.stores(root);
    try {
      const records = await stores.journal.listRecoverable();
      if (
        records.length > 1 ||
        records.some(
          (record) =>
            ![
              "verification_succeeded",
              "rollback_verification_succeeded",
            ].includes(record.state),
        )
      )
        throw new Error(
          "Phase 3 retention requires a sole automatic terminal transaction",
        );
      if ((await stores.approvals.retentionSummary()).liveUnused !== 0)
        throw new Error("Phase 3 retention has a live unused approval");
      await this.bindings(stores, records);
      const results = await proof(stores);
      if (results.length !== records.length)
        throw new Error("Phase 3 retention recovery proof is incomplete");
      const record = records[0];
      const result = results[0];
      if (
        record &&
        (!result ||
          result.transactionId !== record.transactionId ||
          result.record.transactionId !== record.transactionId ||
          result.record.version !== record.version ||
          result.record.state !== record.state ||
          result.terminalState !== record.state ||
          result.manualAttentionRequired ||
          result.observedDigest !==
            (result.observedSha256 === record.candidateSha256
              ? "candidate"
              : "expected_or_checkpoint") ||
          result.disposition !==
            (record.state === "verification_succeeded"
              ? "verified"
              : "rolled_back") ||
          result.observedSha256 !==
            (record.state === "verification_succeeded"
              ? record.candidateSha256
              : record.checkpointSha256))
      )
        throw new Error(
          "Phase 3 retention requires current live digest verification",
        );
    } finally {
      await stores.approvals.close();
    }
  }

  private async stores(root: string): Promise<Phase3EpochStores> {
    const options = this.native ? {} : { durability: this.durability };
    const journal = new DurablePhase3Journal(join(root, "journal"), options);
    const checkpoints = new DurablePhase3Checkpoints(
      join(root, "checkpoints"),
      options,
    );
    const approvals = new DurablePhase3ApprovalGrants(
      join(root, "approvals"),
      this.key,
      options,
    );
    try {
      await journal.initialize();
      await checkpoints.initialize();
      await approvals.initialize();
      return { root, journal, checkpoints, approvals };
    } catch (error) {
      await approvals.close();
      throw error;
    }
  }

  private async bindings(
    stores: Phase3EpochStores,
    records: readonly Phase3TransactionRecord[],
  ): Promise<void> {
    for (const record of records) {
      const checkpoint = await stores.checkpoints.load(record.checkpointId);
      try {
        const digest = sha256(checkpoint);
        if (
          digest !== record.checkpointSha256 ||
          digest !== record.expectedSha256
        )
          throw new Error(
            "Phase 3 retention checkpoint binding does not match transaction",
          );
      } finally {
        checkpoint.fill(0);
      }
      if (record.approvalGrantId !== undefined)
        await stores.approvals.assertConsumedGrant({
          grantId: record.approvalGrantId,
          proposalId: record.proposalId,
          proposalStorageSha256: record.proposalStorageSha256,
          candidateSha256: record.candidateSha256,
          diffSha256: record.diffSha256,
          impact: record.impact,
          reloadTarget: record.reloadTarget,
        });
    }
  }

  private async createActive(lease: Phase3OfflineLease): Promise<void> {
    await lease.assertHeld();
    await mkdir(join(this.parent, "active"), { mode: 0o700 });
    for (const name of storeNames) {
      await lease.assertHeld();
      await mkdir(join(this.parent, "active", name), { mode: 0o700 });
    }
    await this.durability.syncDirectory(join(this.parent, "active"));
    await this.durability.syncDirectory(this.parent);
  }

  private async validateFreshActive(root: string): Promise<void> {
    await this.directory(root);
    const names = await readdir(root);
    if (names.some((name) => !(storeNames as readonly string[]).includes(name)))
      throw new Error("Interrupted active epoch has unexpected data");
    for (const name of names) {
      const path = join(root, name);
      await this.directory(path);
      const children = await readdir(path);
      if (
        children.length !== 0 &&
        !(
          name === "approvals" &&
          children.length === 1 &&
          children[0] === "header.json"
        )
      )
        throw new Error("Interrupted active epoch is not fresh");
    }
  }

  private async validateEpoch(root: string): Promise<void> {
    await this.directory(root);
    const names = await readdir(root);
    if (
      storeNames.some((name) => !names.includes(name)) ||
      names.some(
        (name) =>
          !(storeNames as readonly string[]).includes(name) &&
          name !== "operator.jsonl",
      )
    )
      throw new Error("Phase 3 epoch topology is incomplete or unknown");
    for (const name of storeNames) await this.directory(join(root, name));
    // Only explicit bootstrap/resume initializes a new approval header.
    // An interrupted bootstrap or lost header requires manual review.
    await this.file(join(root, "approvals", "header.json"), 1024);
    if (names.includes("operator.jsonl"))
      await validatePhase3OperatorAudit(
        join(root, "operator.jsonl"),
        this.durability,
      );
  }

  private async budget(
    active: string,
    names: readonly string[],
  ): Promise<void> {
    const archives = names.filter((name) => archivePattern.test(name));
    if (archives.length >= this.maximumArchives)
      throw new Error("Phase 3 archive count budget exhausted");
    let bytes = await this.treeBytes(active);
    for (const name of archives) {
      const root = join(this.parent, name);
      await this.validateEpoch(root);
      const stores = await this.stores(root);
      try {
        await this.bindings(stores, await stores.journal.listRecoverable());
      } finally {
        await stores.approvals.close();
      }
      bytes += await this.treeBytes(root);
    }
    if (bytes > this.maximumArchiveBytes)
      throw new Error("Phase 3 archive byte budget exhausted");
  }

  private async treeBytes(root: string): Promise<number> {
    let entries = 0;
    let bytes = 0;
    const visit = async (path: string, depth: number): Promise<void> => {
      if (++entries > 4096 || depth > 4)
        throw new Error("Phase 3 archive scan bound exceeded");
      const stat = await lstat(path, { bigint: true });
      await this.metadata(stat);
      if (stat.isDirectory()) {
        const names = await readdir(path);
        if (names.length > 1024)
          throw new Error("Phase 3 archive scan bound exceeded");
        for (const name of names) await visit(join(path, name), depth + 1);
      } else if (stat.isFile() && stat.nlink === 1n) {
        bytes += Number(stat.size);
        if (!Number.isSafeInteger(bytes) || bytes > this.maximumArchiveBytes)
          throw new Error("Phase 3 archive byte budget exhausted");
      } else throw new Error("Phase 3 archive contains unsafe nodes");
    };
    await visit(root, 0);
    return bytes;
  }

  private async parentEntries(): Promise<string[]> {
    if (this.native && process.platform !== "linux")
      throw new Error("Native Phase 3 retention requires Linux");
    let current = parse(this.parent).root;
    for (const segment of this.parent
      .slice(current.length)
      .split(/[\\/]/)
      .filter(Boolean)) {
      current = join(current, segment);
      const stat = await lstat(current, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink())
        throw new Error("Unsafe Phase 3 retention ancestor");
    }
    await this.directory(this.parent);
    const names = await readdir(this.parent);
    if (
      names.length > 515 ||
      names.some(
        (name) =>
          !["active", "rotation.json", "operator.lock"].includes(name) &&
          !archivePattern.test(name),
      )
    )
      throw new Error("Unknown Phase 3 retention parent entries");
    for (const name of names) {
      if (name === "operator.lock")
        await this.file(join(this.parent, name), 1024);
      else if (name === "rotation.json")
        await this.file(join(this.parent, name), 1024);
      else await this.directory(join(this.parent, name));
    }
    return names;
  }

  private async metadata(stat: BigIntStats): Promise<void> {
    const parent = await lstat(this.parent, { bigint: true });
    if (
      stat.isSymbolicLink() ||
      !this.durability.privateMode(stat.mode) ||
      stat.dev !== parent.dev ||
      (this.native &&
        (typeof process.geteuid !== "function" ||
          stat.uid !== BigInt(process.geteuid())))
    )
      throw new Error(
        "Phase 3 retention node is not private on the same device",
      );
  }

  private async directory(path: string): Promise<BigIntStats> {
    const stat = await lstat(path, { bigint: true });
    await this.metadata(stat);
    if (!stat.isDirectory())
      throw new Error("Phase 3 retention requires a directory");
    return stat;
  }

  private async file(path: string, maximum: number): Promise<Buffer> {
    const before = await lstat(path, { bigint: true });
    await this.metadata(before);
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size > BigInt(maximum)
    )
      throw new Error("Unsafe Phase 3 retention metadata file");
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await handle.stat({ bigint: true });
      if (
        stat.dev !== before.dev ||
        stat.ino !== before.ino ||
        stat.size !== before.size
      )
        throw new Error("Phase 3 retention metadata changed");
      const bytes = await handle.readFile();
      if (bytes.length > maximum)
        throw new Error("Phase 3 retention metadata exceeded bound");
      return bytes;
    } finally {
      await handle.close();
    }
  }

  private assertMarkerIdentity(
    stat: BigIntStats,
    marker: RotationMarker,
  ): void {
    if (
      stat.dev.toString() !== marker.device ||
      stat.ino.toString() !== marker.inode
    )
      throw new Error("Phase 3 rotation archive identity changed");
  }

  private async exists(path: string): Promise<boolean> {
    try {
      await lstat(path);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  private async exclusive<T>(
    lease: Phase3OfflineLease,
    action: () => Promise<T>,
  ): Promise<T> {
    if (this.busy)
      throw new Error("Phase 3 retention operation already active");
    this.busy = true;
    try {
      await lease.assertHeld();
      return await action();
    } finally {
      this.busy = false;
    }
  }
}
