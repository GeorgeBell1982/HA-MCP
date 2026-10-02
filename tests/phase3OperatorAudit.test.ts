import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  Phase3OperatorAudit,
  PHASE3_OPERATOR_AUDIT_BYTES,
  validatePhase3OperatorAudit,
} from "../src/phase3/operatorAudit.js";
import type { Phase3OperatorAuditRecord } from "../src/phase3/operatorApproval.js";
import { sha256 } from "../src/phase3/contracts.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
const durability = { privateMode: () => true, syncDirectory: async () => {} };
const lease = { assertHeld: async () => {} };
const record: Phase3OperatorAuditRecord = {
  attemptId: "11111111-1111-4111-8111-111111111111",
  proposalId: "22222222-2222-4222-8222-222222222222",
  event: "attempt",
};
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "phase3-operator-audit-"));
  roots.push(root);
  await chmod(root, 0o700);
  const path = join(root, "operator.jsonl");
  return {
    root,
    path,
    audit: new Phase3OperatorAudit(path, lease, durability),
  };
}
describe("bounded durable operator audit", () => {
  it("persists metadata and recovers only a torn final row on restart", async () => {
    const f = await fixture();
    await f.audit.append(record);
    const committed = await readFile(f.path, "utf8");
    await writeFile(f.path, committed + '{"timestamp":"torn', { mode: 0o600 });
    const restarted = new Phase3OperatorAudit(f.path, lease, durability);
    await restarted.append({ ...record, event: "failed" });
    const after = await readFile(f.path, "utf8");
    expect(after.startsWith(committed)).toBe(true);
    expect(after).not.toContain("torn");
    expect(
      after
        .trim()
        .split("\n")
        .map((line) => (JSON.parse(line) as { event: string }).event),
    ).toEqual(["attempt", "failed"]);
  });
  it("read-only validation preserves recognized torn tail and rejects unknown tail", async () => {
    const f = await fixture();
    await f.audit.append(record);
    const before = (await readFile(f.path, "utf8")) + '{"timestamp":"torn';
    await writeFile(f.path, before, { mode: 0o600 });
    await expect(
      validatePhase3OperatorAudit(f.path, durability),
    ).resolves.toEqual({
      completeRows: 1,
      tornTailBytes: Buffer.byteLength('{"timestamp":"torn'),
    });
    expect(await readFile(f.path, "utf8")).toBe(before);
    await writeFile(f.path, '{"token":"unrecognized"}', { mode: 0o600 });
    await expect(
      validatePhase3OperatorAudit(f.path, durability),
    ).rejects.toThrow();
  });
  it("rejects malformed committed rows without changing evidence", async () => {
    const f = await fixture();
    const before = '{"bad":true}\n';
    await writeFile(f.path, before, { mode: 0o600 });
    await expect(f.audit.append(record)).rejects.toThrow();
    expect(await readFile(f.path, "utf8")).toBe(before);
  });
  it("refuses a missing lease before creating an audit file", async () => {
    const f = await fixture();
    const audit = new Phase3OperatorAudit(
      f.path,
      {
        assertHeld: async () => {
          throw new Error("not held");
        },
      },
      durability,
    );
    await expect(audit.append(record)).rejects.toThrow("not held");
    await expect(readFile(f.path)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it("refuses hardlinked evidence and unknown/secret record fields", async () => {
    const f = await fixture();
    await f.audit.append(record);
    await link(f.path, join(f.root, "alias"));
    await expect(f.audit.append(record)).rejects.toMatchObject({
      code: "operator_audit_unsafe",
    });
    const clean = await fixture();
    await expect(
      clean.audit.append({
        ...record,
        token: "never-print",
      } as Phase3OperatorAuditRecord),
    ).rejects.toThrow();
  });
  it("requires exact review and settled outcome fields", async () => {
    const f = await fixture();
    await expect(
      f.audit.append({ ...record, event: "displayed" }),
    ).rejects.toThrow();
    await expect(
      f.audit.append({
        ...record,
        event: "audit_uncertain",
        proposalStorageSha256: sha256("stored"),
        displayedSha256: sha256("display"),
      }),
    ).rejects.toThrow();
  });
  it("fails before modifying a full audit", async () => {
    const f = await fixture();
    const line =
      JSON.stringify({ ...record, timestamp: new Date().toISOString() }) + "\n";
    const before = line.repeat(
      Math.floor(PHASE3_OPERATOR_AUDIT_BYTES / Buffer.byteLength(line)),
    );
    await writeFile(f.path, before, { mode: 0o600 });
    await expect(f.audit.append(record)).rejects.toMatchObject({
      code: "operator_audit_capacity",
    });
    expect(await readFile(f.path, "utf8")).toBe(before);
  });
  it("rejects a directory masquerading as audit", async () => {
    const f = await fixture();
    await mkdir(f.path);
    await expect(f.audit.append(record)).rejects.toThrow();
  });
});
