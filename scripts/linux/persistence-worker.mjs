#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ProposalCursorCodec } from "../../dist/proposals/cursor.js";
import { ProposalService } from "../../dist/proposals/proposalService.js";
import {
  PHASE2_AUDIT_LIMITS,
  Phase2AuditAdapter,
} from "../../dist/proposals/phase2Audit.js";
import {
  ProtectedProposalStore,
  atomicProtectedWrite,
  canonicalJson,
  journalEnvelope,
  storageEnvelope,
} from "../../dist/proposals/storage.js";

const [action, root, checkpoint = ""] = process.argv.slice(2);
if (!action || !root) throw new Error("worker requires action and root");
const operationId = process.env.HA_OPERATION_ID ?? randomUUID();
const proposalId = process.env.HA_PROPOSAL_ID ?? randomUUID();
const auditPath = join(root, "audit", "phase2.jsonl");

async function awaitFaultArm() {
  if (!process.env.HA_FAULT_ARM) return;
  process.send?.({ type: "ready" });
  await new Promise((resolvePromise) =>
    process.once("message", (message) => {
      if (message?.type !== "arm") throw new Error("invalid arm message");
      resolvePromise();
    }),
  );
}

function context() {
  return {
    requestId: "00000000-0000-4000-8000-000000000001",
    operationId,
    deadlineAt: Date.now() + 60_000,
    signal: new AbortController().signal,
  };
}
function stored() {
  const candidate = Buffer.from("value: new\n"),
    diff = Buffer.from("safe\n");
  const candidateSha256 = createHash("sha256").update(candidate).digest("hex");
  const diffSha256 = createHash("sha256").update(diff).digest("hex");
  return storageEnvelope(
    {
      proposalId,
      idempotencyKey: "00000000-0000-4000-8000-000000000002",
      state: "pending",
      path: "configuration.yaml",
      expectedSha256: "a".repeat(64),
      candidateSha256,
      diffSha256,
      redactedDiff: "safe",
      createdAt: new Date(0).toISOString(),
      expiresAt: new Date(86400000).toISOString(),
      risk: "high",
      validationPlan: ["validate"],
      reloadImpact: "restart_required",
      sourceEvidence: "Linux persistence harness",
    },
    {
      schemaVersion: 1,
      proposalId,
      idempotencyKey: "00000000-0000-4000-8000-000000000002",
      candidateSha256,
      diffSha256,
      encoding: "utf-8",
      exactCandidateBytesBase64: candidate.toString("base64"),
      exactDiffBytesBase64: diff.toString("base64"),
    },
  );
}
function journal(proposal, phase = "prepared") {
  return journalEnvelope({
    schemaVersion: 1,
    operationId,
    requestId: context().requestId,
    tool: "ha_propose_config_change",
    phase,
    proposal,
    beforeSha256: null,
  });
}
function attempt() {
  return {
    schemaVersion: 2,
    timestamp: new Date(0).toISOString(),
    requestId: context().requestId,
    operationId,
    phase: "attempt",
    tool: "ha_propose_config_change",
    risk: "proposal-metadata",
    target: {
      kind: "proposal-create",
      idempotencyKey: "00000000-0000-4000-8000-000000000002",
      path: "configuration.yaml",
      expectedSha256: "a".repeat(64),
      candidateSha256: "b".repeat(64),
    },
  };
}
async function pauseAt(stage) {
  if (stage !== checkpoint) return;
  process.send?.({ type: "checkpoint", stage, operationId, proposalId });
  await new Promise(() => {});
}

async function buildService(withCheckpoint) {
  const serviceStore = new ProtectedProposalStore(join(root, "store"));
  const serviceAudit = new Phase2AuditAdapter(auditPath);
  const source = Buffer.from("value: old\n");
  const identity = Object.freeze({ device: "1", inode: "2" });
  const rootIdentity = Object.freeze({ device: "1", inode: "1" });
  const registry = {
    assertFresh: async () => undefined,
    readContent: async () =>
      Object.freeze({
        path: "configuration.yaml",
        rootIdentity,
        identity,
        bytes: Uint8Array.from(source),
      }),
    redactWholeText: (text) => text,
  };
  const catalog = {
    catalog: async () =>
      Object.freeze({
        rootIdentity,
        directories: Object.freeze([]),
        files: Object.freeze([
          Object.freeze({
            path: "configuration.yaml",
            identity,
            size: source.byteLength,
            mtimeNanoseconds: "1",
            ctimeNanoseconds: "1",
          }),
        ]),
      }),
  };
  const service = new ProposalService(
    serviceStore,
    serviceAudit,
    registry,
    catalog,
    new ProposalCursorCodec(Buffer.alloc(32, 1), Buffer.alloc(32, 2)),
    withCheckpoint ? { checkpoint: pauseAt, now: () => 0 } : { now: () => 0 },
  );
  await service.initialize();
  return { service, serviceStore, source };
}

async function inspectSubsystem(subsystem) {
  if (
    subsystem === "proposal" ||
    subsystem === "journal" ||
    subsystem === "quarantine"
  ) {
    const inspectionStore = new ProtectedProposalStore(join(root, "store"));
    let healthy = true;
    try {
      await inspectionStore.initialize();
      await inspectionStore.readAll();
      await inspectionStore.readJournals();
    } catch {
      healthy = false;
    }
    const list = async (path) => {
      try {
        return (await readdir(path)).sort();
      } catch {
        return [];
      }
    };
    return {
      healthy,
      proposals: await list(inspectionStore.proposalsPath),
      journals: await list(inspectionStore.journalsPath),
      quarantine: await list(inspectionStore.quarantinePath),
    };
  }

  const inspectionAudit = new Phase2AuditAdapter(auditPath);
  let healthy = true;
  try {
    await inspectionAudit.recover();
  } catch {
    healthy = false;
  }
  const files = await readdir(join(root, "audit")).catch(() => []);
  let records = 0;
  for (const file of files.sort()) {
    if (!file.endsWith(".jsonl")) continue;
    const text = await readFile(join(root, "audit", file), "utf8").catch(
      () => "",
    );
    records += text.split("\n").filter(Boolean).length;
  }
  return { healthy, files: files.sort(), records };
}

const store = new ProtectedProposalStore(join(root, "store"));
const audit = new Phase2AuditAdapter(auditPath, { checkpoint: pauseAt });
let evidence;

try {
  if (action === "proposal" || action === "proposal-paused") {
    await store.initialize();
    if (action === "proposal-paused") {
      process.send?.({ type: "fixture-ready" });
      await new Promise((resolvePromise) =>
        process.once("message", (message) => {
          if (message?.type !== "continue")
            throw new Error("invalid fixture message");
          resolvePromise();
        }),
      );
    }
    await awaitFaultArm();
    await store.create(stored(), context());
  } else if (action === "journal") {
    await store.initialize();
    await awaitFaultArm();
    await store.createJournal(journal(stored()), context());
  } else if (action === "audit") {
    await audit.recover();
    await awaitFaultArm();
    await audit.append(attempt(), context());
  } else if (action === "rotation") {
    await mkdir(join(root, "audit"), { recursive: true, mode: 0o700 });
    const records = [];
    let bytes = 0;
    for (let index = 0; ; index += 1) {
      const record = {
        ...attempt(),
        operationId: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
      };
      const line = `${canonicalJson(record)}\n`;
      if (bytes + Buffer.byteLength(line) > PHASE2_AUDIT_LIMITS.fileBytes - 256)
        break;
      records.push(line);
      bytes += Buffer.byteLength(line);
    }
    await writeFile(auditPath, records.join(""), { mode: 0o600 });
    await audit.recover();
    await awaitFaultArm();
    await audit.append(attempt(), context());
  } else if (action === "quarantine") {
    await store.initialize();
    await writeFile(join(store.proposalsPath, "unsafe"), "unsafe", {
      mode: 0o600,
    });
    await awaitFaultArm();
    try {
      await store.readAll();
    } catch {
      store.assertHealthy();
    }
  } else if (action === "transaction") {
    const fixture = await buildService(true);
    await fixture.service.propose(
      {
        idempotencyKey: "00000000-0000-4000-8000-000000000002",
        path: "configuration.yaml",
        expectedSha256: createHash("sha256")
          .update(fixture.source)
          .digest("hex"),
        proposedContent: "value: new\n",
      },
      context(),
    );
  } else if (action === "recover-transaction") {
    const fixture = await buildService(false);
    const proposals = await fixture.serviceStore.readAll();
    const records = (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
    const outcomes = records.filter(
      (record) =>
        record.phase === "outcome" && record.operationId === operationId,
    );
    evidence = {
      effects: proposals.length,
      outcomes: outcomes.length,
      outcomeResult: outcomes[0]?.result ?? null,
      journals: (await fixture.serviceStore.readJournals()).length,
    };
  } else if (action.startsWith("inspect-")) {
    evidence = await inspectSubsystem(action.slice("inspect-".length));
  } else if (action === "atomic") {
    await mkdir(root, { recursive: true, mode: 0o700 });
    await atomicProtectedWrite(
      join(root, "atomic.json"),
      Buffer.from("{}"),
      context(),
      pauseAt,
    );
  } else throw new Error(`unknown worker action ${action}`);

  process.send?.({
    type: "complete",
    action,
    operationId,
    proposalId,
    evidence,
  });
} catch (error) {
  let latched;
  if (action === "audit" || action === "rotation") latched = !audit.isHealthy();
  else {
    try {
      store.assertHealthy();
      latched = false;
    } catch {
      latched = true;
    }
  }
  process.send?.({
    type: "failure",
    action,
    latched,
    error: String(error?.message ?? error),
  });
  process.exitCode = 2;
}
