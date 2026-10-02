import { constants } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { z } from "zod";
import {
  strictPhase2Durability,
  type Phase2DurabilityPort,
} from "../proposals/durability.js";
import { phase3TransactionStates, sha256Schema } from "./contracts.js";
import {
  Phase3OperatorError,
  type Phase3OperatorAuditRecord,
} from "./operatorApproval.js";

const recordSchema = z
  .object({
    timestamp: z.string().datetime(),
    attemptId: z.string().uuid(),
    event: z.enum([
      "attempt",
      "displayed",
      "confirmed",
      "grant_issued",
      "settled",
      "failed",
      "audit_uncertain",
      "recovery_attempt",
      "recovery_displayed",
      "recovery_confirmed",
      "recovery_settled",
      "recovery_failed",
      "recovery_uncertain",
    ]),
    proposalId: z.string().uuid().optional(),
    proposalStorageSha256: sha256Schema.optional(),
    displayedSha256: sha256Schema.optional(),
    grantId: z.string().uuid().optional(),
    transactionId: z.string().uuid().optional(),
    state: z.enum(phase3TransactionStates).optional(),
  })
  .strict()
  .superRefine((record, context) => {
    const recovery = record.event.startsWith("recovery_");
    if (recovery) {
      if (
        !["recovery_attempt", "recovery_failed"].includes(record.event) &&
        !record.displayedSha256
      )
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Recovery review evidence is required",
        });
      return;
    }
    if (!record.proposalId)
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Proposal identity is required",
      });
    if (
      record.event !== "attempt" &&
      record.event !== "failed" &&
      (!record.proposalStorageSha256 || !record.displayedSha256)
    )
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Review evidence is required",
      });
    if (
      ["settled", "audit_uncertain"].includes(record.event) &&
      (!record.transactionId || !record.state || !record.grantId)
    )
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Transaction outcome is required",
      });
  });
export const PHASE3_OPERATOR_AUDIT_BYTES = 1024 * 1024;
const maximumRowBytes = 2048;

/** Read-only archive validation: complete rows must be valid; a torn tail is retained. */
export async function validatePhase3OperatorAudit(
  path: string,
  durability: Phase2DurabilityPort = strictPhase2Durability,
) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const scan = await scanAudit(path, handle, durability);
    try {
      return {
        completeRows: scan.completeRows,
        tornTailBytes: scan.bytes.length - scan.committedLength,
      };
    } finally {
      scan.bytes.fill(0);
    }
  } finally {
    await handle.close();
  }
}

async function scanAudit(
  path: string,
  handle: FileHandle,
  durability: Phase2DurabilityPort,
) {
  if (
    !isAbsolute(path) ||
    resolve(path) !== path ||
    (durability === strictPhase2Durability && process.platform !== "linux")
  )
    throw new Phase3OperatorError("operator_audit_unavailable");
  const parent = await lstat(dirname(path), { bigint: true });
  const metadata = await handle.stat({ bigint: true });
  const named = await lstat(path, { bigint: true });
  if (
    !parent.isDirectory() ||
    !durability.privateMode(parent.mode) ||
    (process.getuid && parent.uid !== BigInt(process.getuid())) ||
    !metadata.isFile() ||
    metadata.dev !== parent.dev ||
    metadata.dev !== named.dev ||
    metadata.ino !== named.ino ||
    metadata.nlink !== 1n ||
    !durability.privateMode(metadata.mode) ||
    metadata.uid !== parent.uid ||
    metadata.size > BigInt(PHASE3_OPERATOR_AUDIT_BYTES)
  )
    throw new Phase3OperatorError("operator_audit_unsafe");
  const bytes = await handle.readFile();
  try {
    const after = await handle.stat({ bigint: true });
    const afterName = await lstat(path, { bigint: true });
    if (
      BigInt(bytes.length) !== metadata.size ||
      after.size !== metadata.size ||
      after.mtimeNs !== metadata.mtimeNs ||
      after.ctimeNs !== metadata.ctimeNs ||
      afterName.dev !== metadata.dev ||
      afterName.ino !== metadata.ino
    )
      throw new Phase3OperatorError("operator_audit_changed");
    const committedLength = bytes.lastIndexOf(0x0a) + 1;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(0, committedLength),
    );
    const rows = text.split("\n").slice(0, -1);
    for (const row of rows) {
      if (Buffer.byteLength(row, "utf8") > maximumRowBytes)
        throw new Phase3OperatorError("operator_audit_unsafe");
      recordSchema.parse(JSON.parse(row));
    }
    const tail = bytes.subarray(committedLength);
    if (tail.length !== 0) {
      const prefix = '{"timestamp":';
      const tailText = tail.toString("ascii");
      if (
        tail.length > maximumRowBytes ||
        tail.some((byte) => byte < 0x20 || byte > 0x7e) ||
        (!prefix.startsWith(tailText) && !tailText.startsWith(prefix))
      )
        throw new Phase3OperatorError("operator_audit_torn_tail_invalid");
      let complete: unknown;
      try {
        complete = JSON.parse(tailText);
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
      if (complete !== undefined) recordSchema.parse(complete);
    }
    return { bytes, committedLength, completeRows: rows.length };
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

/** Metadata only; all callers must hold the epoch's exclusive operator lease. */
export class Phase3OperatorAudit {
  constructor(
    private readonly path: string,
    private readonly lease: { assertHeld(): Promise<void> },
    private readonly durability: Phase2DurabilityPort = strictPhase2Durability,
  ) {
    if (!isAbsolute(path) || resolve(path) !== path)
      throw new Phase3OperatorError("operator_audit_unsafe");
  }
  async append(record: Phase3OperatorAuditRecord): Promise<void> {
    const line =
      JSON.stringify(
        recordSchema.parse({ ...record, timestamp: new Date().toISOString() }),
      ) + "\n";
    await this.lease.assertHeld();
    if (
      this.durability === strictPhase2Durability &&
      process.platform !== "linux"
    )
      throw new Phase3OperatorError("operator_audit_unavailable");
    const handle = await open(
      this.path,
      constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    let bytes: Buffer | undefined;
    try {
      const scan = await scanAudit(this.path, handle, this.durability);
      bytes = scan.bytes;
      const committed = bytes.subarray(0, scan.committedLength);
      if (
        committed.length + Buffer.byteLength(line, "utf8") >
        PHASE3_OPERATOR_AUDIT_BYTES
      )
        throw new Phase3OperatorError("operator_audit_capacity");
      await this.lease.assertHeld();
      // A crash may leave only the trailing uncommitted line. Preserve all complete rows.
      if (committed.length !== bytes.length) {
        await handle.truncate(committed.length);
        await handle.sync();
      }
      const pending = Buffer.from(line, "utf8");
      try {
        for (let offset = 0; offset < pending.length; ) {
          const written = await handle.write(
            pending,
            offset,
            pending.length - offset,
            committed.length + offset,
          );
          if (written.bytesWritten <= 0)
            throw new Phase3OperatorError("operator_audit_write_failed");
          offset += written.bytesWritten;
        }
      } finally {
        pending.fill(0);
      }
      await handle.sync();
      await this.durability.syncDirectory(dirname(this.path));
    } finally {
      bytes?.fill(0);
      await handle.close();
    }
  }
}
