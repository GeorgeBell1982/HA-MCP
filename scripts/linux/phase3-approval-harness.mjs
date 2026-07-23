#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statfsSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** Frozen Phase 3M approval-evidence registry. Keep order stable. */
export const APPROVAL_EVIDENCE_IDS = Object.freeze([
  "env:linux",
  "env:native-fs",
  "env:root-private",
  "init:same-key-race",
  "init:different-key-race",
  "init:wrong-key-restart",
  "cross:issue-consume-replay",
  "race:issue-colliding-uuid",
  "race:consume",
  "tamper:header",
  "tamper:grant",
  "tamper:receipt",
  "exhaustion:header-same-instance-retry",
  "exhaustion:grant-same-instance-retry",
  "exhaustion:receipt-same-instance-retry",
  "topology:root-mode",
  "topology:root-owner",
  "topology:header-symlink",
  "topology:header-hardlink",
  "topology:header-nonregular",
  "topology:root-unknown-entry",
  "topology:root-entry-overflow",
  "topology:slot-entry-overflow",
  "kill:header:precommit",
  "kill:header:postcommit",
  "kill:header:parent-synced",
  "kill:grant:precommit",
  "kill:grant:postcommit",
  "kill:grant:parent-synced",
  "kill:receipt:precommit",
  "kill:receipt:postcommit",
  "kill:receipt:parent-synced",
  "fault:header:open",
  "fault:header:pwrite-fail",
  "fault:header:pwrite-short",
  "fault:header:pwrite-enospc",
  "fault:header:file-fsync",
  "fault:header:link-family",
  "fault:header:parent-fsync",
  "fault:grant:open",
  "fault:grant:pwrite-fail",
  "fault:grant:pwrite-short",
  "fault:grant:pwrite-enospc",
  "fault:grant:file-fsync",
  "fault:grant:stage-fsync",
  "fault:grant:rename",
  "fault:grant:parent-fsync",
  "fault:receipt:open",
  "fault:receipt:pwrite-fail",
  "fault:receipt:pwrite-short",
  "fault:receipt:pwrite-enospc",
  "fault:receipt:file-fsync",
  "fault:receipt:link-family",
  "fault:receipt:parent-fsync",
  "shim:link:fail",
  "shim:linkat:fail",
]);

const APPROVAL_EVIDENCE_ID_SET = new Set(APPROVAL_EVIDENCE_IDS);
const TERMINAL_STATUSES = new Set([
  "PASSED",
  "FAILED",
  "BLOCKED",
  "SKIPPED",
  "UNVERIFIED",
]);
const MANIFEST = Object.freeze({
  type: "manifest",
  version: 1,
  requiredRows: APPROVAL_EVIDENCE_IDS,
  adapters: Object.freeze({ filesystem: "default", durability: "default" }),
  prerequisites: Object.freeze(["linux", "uid0", "compiler", "process-groups"]),
  limitations: Object.freeze([
    "actual-power-cut-unverified",
    "grant-native-topology-unverified",
    "receipt-native-topology-unverified",
  ]),
});
const MAX_EVIDENCE_BYTES = 1_048_576;
const MAX_ROW_EVIDENCE_BYTES = 8_192;
const MAX_STDIO_BYTES = 65_536;
const MAX_IPC_BYTES = 262_144;
const MAX_IPC_MESSAGES = 128;
const WORKER_TIMEOUT_MS = 15_000;
const PROCESS_GROUP_POLLS = 50;
const PROCESS_GROUP_POLL_MS = 20;
const PROCESS_GROUP_PROBE_TIMEOUT_MS = 5_000;
const PROCESS_GROUP_PROBE_CLEANUP_MS = 2_000;
const MAX_DIAGNOSTIC_ITEMS = 8;
const MAX_DIAGNOSTIC_CHARACTERS = 256;
const PROTOCOL_VERSION = 1;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RELATIVE_ARTIFACT_PATTERN =
  /^(?!\/)(?!\.\.?$)(?!\.\.\/)(?!.*\/\.\.?(?:\/|$))[A-Za-z0-9._/-]+$/u;
const PUBLIC_CODES = new Set([
  "approval_cancelled",
  "approval_not_found",
  "approval_replayed",
  "approval_not_yet_valid",
  "approval_expired",
  "approval_wrong_binding",
  "approval_store_unhealthy",
  "approval_commit_unknown",
  "approval_capacity_exhausted",
  "proposal_not_pending",
  "proposal_expired",
]);

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function summaryStatus(rows) {
  if (rows.some((row) => row.status === "FAILED")) return "FAILED";
  if (rows.some((row) => row.status === "BLOCKED")) return "BLOCKED";
  if (rows.some((row) => row.status !== "PASSED")) return "UNVERIFIED";
  return "PASSED";
}

function parseRecord(line, lineNumber) {
  let record;
  try {
    record = JSON.parse(line);
  } catch (error) {
    throw new Error(`line ${lineNumber}: malformed JSON: ${error.message}`);
  }
  if (record === null || Array.isArray(record) || typeof record !== "object") {
    throw new Error(`line ${lineNumber}: record must be a JSON object`);
  }
  return record;
}

/** Strictly parse manifest-first, one-row-per-ID, summary-last JSONL evidence. */
export function parseApprovalEvidence(output) {
  if (typeof output !== "string") {
    throw new TypeError("approval evidence must be a string");
  }
  if (Buffer.byteLength(output, "utf8") > MAX_EVIDENCE_BYTES) {
    throw new Error("approval evidence exceeds the output limit");
  }
  if (!output.endsWith("\n")) {
    throw new Error("approval evidence must end with one JSONL newline");
  }
  const lines = output.split(/\r?\n/u);
  lines.pop();
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    throw new Error("approval evidence must contain non-empty JSONL records");
  }

  const records = lines.map((line, index) => parseRecord(line, index + 1));
  const manifest = records[0];
  const summary = records.at(-1);
  if (
    !exactKeys(manifest, [
      "type",
      "version",
      "requiredRows",
      "adapters",
      "prerequisites",
      "limitations",
    ]) ||
    manifest.type !== "manifest"
  ) {
    throw new Error("line 1: manifest record required first");
  }
  if (
    manifest.version !== MANIFEST.version ||
    !sameJson(manifest.requiredRows, APPROVAL_EVIDENCE_IDS) ||
    !sameJson(manifest.adapters, MANIFEST.adapters) ||
    !sameJson(manifest.prerequisites, MANIFEST.prerequisites) ||
    !sameJson(manifest.limitations, MANIFEST.limitations)
  ) {
    throw new Error("line 1: manifest does not match the frozen contract");
  }
  if (
    !exactKeys(summary, [
      "type",
      "status",
      "required",
      "executed",
      "passed",
      "nonPassed",
    ]) ||
    summary.type !== "summary"
  ) {
    throw new Error(`line ${records.length}: summary record required last`);
  }

  const rows = records.slice(1, -1);
  if (rows.length !== APPROVAL_EVIDENCE_IDS.length) {
    throw new Error(`expected ${APPROVAL_EVIDENCE_IDS.length} evidence rows`);
  }
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    const lineNumber = index + 2;
    if (
      !exactKeys(row, ["type", "id", "status", "evidence"]) ||
      row.type !== "row" ||
      !APPROVAL_EVIDENCE_ID_SET.has(row.id)
    ) {
      throw new Error(`line ${lineNumber}: unknown evidence row`);
    }
    if (row.id !== APPROVAL_EVIDENCE_IDS[index]) {
      throw new Error(`line ${lineNumber}: evidence row order mismatch`);
    }
    if (seen.has(row.id)) {
      throw new Error(`line ${lineNumber}: duplicate evidence row ${row.id}`);
    }
    if (!TERMINAL_STATUSES.has(row.status)) {
      throw new Error(`line ${lineNumber}: invalid evidence status`);
    }
    if (!exactKeys(row.evidence, Object.keys(row.evidence ?? {}))) {
      throw new Error(`line ${lineNumber}: row evidence must be an object`);
    }
    if (
      Buffer.byteLength(JSON.stringify(row.evidence), "utf8") >
      MAX_ROW_EVIDENCE_BYTES
    ) {
      throw new Error(`line ${lineNumber}: row evidence exceeds the limit`);
    }
    seen.add(row.id);
  }
  for (const id of APPROVAL_EVIDENCE_IDS) {
    if (!seen.has(id)) throw new Error(`missing evidence row ${id}`);
  }
  const nonPassed = rows
    .filter((row) => row.status !== "PASSED")
    .map((row) => row.id);
  const expectedStatus = summaryStatus(rows);
  if (
    summary.status !== expectedStatus ||
    summary.required !== APPROVAL_EVIDENCE_IDS.length ||
    summary.executed !== rows.length ||
    summary.passed !== rows.length - nonPassed.length ||
    !sameJson(summary.nonPassed, nonPassed)
  ) {
    throw new Error(
      `line ${records.length}: summary does not match evidence rows`,
    );
  }
  return { manifest, rows, summary };
}

export function appendBounded(chunks, chunk, limit, label) {
  if (!Array.isArray(chunks) || !Buffer.isBuffer(chunk)) {
    throw new TypeError("bounded capture requires a Buffer chunk array");
  }
  const current = chunks.reduce((total, value) => total + value.byteLength, 0);
  if (current + chunk.byteLength > limit)
    throw new Error(`${label} exceeded ${limit} bytes`);
  chunks.push(Buffer.from(chunk));
}

const HOOK_STAGES = new Set([
  "header_file_synced",
  "header_pre_commit",
  "header_post_commit",
  "header_parent_synced",
  "header_cleanup",
  "header_housekeeping_synced",
  "grant_file_synced",
  "grant_stage_synced",
  "grant_pre_commit",
  "grant_post_commit",
  "grant_parent_synced",
  "grant_cleanup",
  "grant_housekeeping_synced",
  "receipt_file_synced",
  "receipt_pre_commit",
  "receipt_post_commit",
  "receipt_parent_synced",
  "receipt_cleanup",
  "receipt_housekeeping_synced",
]);
const COMMIT_STATES = new Set([
  "not_committed",
  "possibly_committed",
  "durably_committed",
]);
const GRANT_KEYS = [
  "grantId",
  "proposalId",
  "proposalStorageSha256",
  "candidateSha256",
  "diffSha256",
  "operation",
  "risk",
  "impact",
  "reloadTarget",
  "issuedAt",
  "expiresAt",
];

function validateGrant(grant) {
  if (
    !exactKeys(grant, GRANT_KEYS) ||
    !UUID_PATTERN.test(grant.grantId) ||
    !UUID_PATTERN.test(grant.proposalId) ||
    !["proposalStorageSha256", "candidateSha256", "diffSha256"].every((key) =>
      /^[a-f0-9]{64}$/u.test(grant[key]),
    ) ||
    grant.operation !== "apply" ||
    grant.risk !== "high" ||
    grant.impact !== "restart_required" ||
    grant.reloadTarget !== null ||
    !Number.isSafeInteger(Date.parse(grant.issuedAt)) ||
    !Number.isSafeInteger(Date.parse(grant.expiresAt))
  )
    throw new Error("worker returned a malformed grant");
  return grant;
}

function validateHook(hook) {
  const keys =
    hook?.grantId === undefined
      ? ["stage", "commitState", "relativePending", "relativeFinal"]
      : ["stage", "commitState", "relativePending", "relativeFinal", "grantId"];
  if (
    !exactKeys(hook, keys) ||
    !HOOK_STAGES.has(hook.stage) ||
    !COMMIT_STATES.has(hook.commitState) ||
    !RELATIVE_ARTIFACT_PATTERN.test(hook.relativePending) ||
    !RELATIVE_ARTIFACT_PATTERN.test(hook.relativeFinal) ||
    (hook.grantId !== undefined && !UUID_PATTERN.test(hook.grantId))
  )
    throw new Error("worker returned a malformed hook");
  return hook;
}

export function validateWorkerMessage(message) {
  if (exactKeys(message, ["type", "protocol"]) && message.type === "ready") {
    if (message.protocol !== PROTOCOL_VERSION)
      throw new Error("worker protocol mismatch");
    return Object.freeze({ kind: "ready" });
  }
  if (
    exactKeys(message, ["type", "requestId", "hook"]) &&
    message.type === "hook" &&
    Number.isSafeInteger(message.requestId) &&
    message.requestId > 0
  )
    return Object.freeze({
      kind: "hook",
      requestId: message.requestId,
      hook: validateHook(message.hook),
    });
  if (
    exactKeys(message, ["type", "requestId", "command", "ok", "evidence"]) &&
    message.type === "result" &&
    Number.isSafeInteger(message.requestId) &&
    message.requestId > 0 &&
    ["initialize", "issue", "consume", "close"].includes(message.command) &&
    message.ok === true
  ) {
    if (
      message.command === "initialize" &&
      !(
        exactKeys(message.evidence, ["adapters"]) &&
        sameJson(message.evidence.adapters, MANIFEST.adapters)
      )
    )
      throw new Error("worker initialize evidence is malformed");
    if (
      (message.command === "issue" || message.command === "consume") &&
      !(
        exactKeys(message.evidence, ["grant"]) &&
        validateGrant(message.evidence.grant)
      )
    )
      throw new Error("worker grant evidence is malformed");
    if (
      message.command === "close" &&
      !(
        exactKeys(message.evidence, ["closed"]) &&
        message.evidence.closed === true
      )
    )
      throw new Error("worker close evidence is malformed");
    return Object.freeze({
      kind: "result",
      requestId: message.requestId,
      command: message.command,
      ok: true,
      evidence: message.evidence,
    });
  }
  if (
    exactKeys(message, ["type", "requestId", "command", "ok", "code"]) &&
    message.type === "result" &&
    Number.isSafeInteger(message.requestId) &&
    message.requestId > 0 &&
    ["initialize", "issue", "consume", "close"].includes(message.command) &&
    message.ok === false &&
    PUBLIC_CODES.has(message.code)
  )
    return Object.freeze({
      kind: "result",
      requestId: message.requestId,
      command: message.command,
      ok: false,
      code: message.code,
    });
  if (
    exactKeys(message, ["type", "code"]) &&
    message.type === "protocol-failure" &&
    ["invalid_request", "request_overlap"].includes(message.code)
  )
    return Object.freeze({ kind: "protocol-failure", code: message.code });
  throw new Error("worker IPC message is malformed");
}

function deferred() {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolveValue, reject) => {
    resolvePromise = resolveValue;
    rejectPromise = reject;
  });
  promise.catch(() => undefined);
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

function delay(milliseconds) {
  return new Promise((resolvePromise) =>
    setTimeout(resolvePromise, milliseconds),
  );
}

async function assertNoProcessGroup(pid) {
  for (let index = 0; index < PROCESS_GROUP_POLLS; index += 1) {
    try {
      process.kill(-pid, 0);
    } catch (error) {
      if (error?.code === "ESRCH") return;
      throw error;
    }
    await delay(PROCESS_GROUP_POLL_MS);
  }
  throw new Error(`worker process group ${pid} survived completion`);
}

function killProcessGroup(pid, signal = "SIGKILL") {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

export class WorkerClient {
  constructor(config, root, options = {}) {
    this.nextRequestId = 1;
    this.stdout = [];
    this.stderr = [];
    this.ipcBytes = 0;
    this.ipcMessages = 0;
    this.readyState = deferred();
    this.closedState = deferred();
    this.pending = undefined;
    this.cleanupFailures = [];
    this.processGroupAbsent = false;
    const timeoutMs = options.timeoutMs ?? WORKER_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs <= 0 ||
      timeoutMs > WORKER_TIMEOUT_MS
    )
      throw new Error("worker timeout is invalid");
    const args = [
      config.worker,
      "--root",
      root,
      "--key",
      options.key ?? "primary",
    ];
    for (const uuid of options.uuids ?? []) args.push("--uuid", uuid);
    this.child = spawn(config.node, args, {
      detached: true,
      env: { ...process.env, ...(options.env ?? {}) },
      shell: false,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    });
    this.child.stdout.on("data", (chunk) =>
      this.capture(this.stdout, chunk, "worker stdout"),
    );
    this.child.stderr.on("data", (chunk) =>
      this.capture(this.stderr, chunk, "worker stderr"),
    );
    this.child.on("message", (message) => this.onMessage(message));
    this.child.once("error", (error) => this.fail(error));
    this.child.once("close", (code, signal) => {
      clearTimeout(this.timer);
      this.closed = true;
      this.readyState.reject(new Error("worker closed before ready"));
      this.pending?.result.reject(new Error("worker closed before result"));
      this.pending?.hook?.reject(
        new Error("worker closed before requested hook"),
      );
      this.closedState.resolve({ kind: "close", code, signal });
    });
    this.timer = setTimeout(() => {
      this.timedOut = true;
      this.fail(new Error(`worker exceeded ${timeoutMs} ms`));
      this.closedState.resolve({ kind: "deadline", code: null, signal: null });
    }, timeoutMs);
    this.pid = this.child.pid;
    if (!Number.isSafeInteger(this.pid) || this.pid <= 0)
      this.fail(new Error("worker PID is unavailable"));
  }

  capture(target, chunk, label) {
    try {
      appendBounded(target, Buffer.from(chunk), MAX_STDIO_BYTES, label);
    } catch (error) {
      this.fail(error);
    }
  }

  onMessage(message) {
    try {
      const encoded = Buffer.from(JSON.stringify(message), "utf8");
      this.ipcMessages += 1;
      this.ipcBytes += encoded.byteLength;
      if (this.ipcMessages > MAX_IPC_MESSAGES || this.ipcBytes > MAX_IPC_BYTES)
        throw new Error("worker IPC exceeded its bound");
      const parsed = validateWorkerMessage(message);
      if (parsed.kind === "ready") {
        if (this.readySeen || this.pending)
          throw new Error("duplicate or late worker ready");
        this.readySeen = true;
        this.readyState.resolve();
        return;
      }
      if (parsed.kind === "protocol-failure")
        throw new Error(`worker protocol failure: ${parsed.code}`);
      if (!this.pending || parsed.requestId !== this.pending.requestId)
        throw new Error("worker response request ID mismatch");
      if (parsed.kind === "hook") {
        const prefix = `${
          this.pending.command === "initialize"
            ? "header"
            : this.pending.command === "issue"
              ? "grant"
              : this.pending.command === "consume"
                ? "receipt"
                : "close"
        }_`;
        if (!parsed.hook.stage.startsWith(prefix))
          throw new Error("unexpected worker hook");
        this.pending.hooks.push(parsed.hook);
        if (parsed.hook.stage === this.pending.pauseStage) {
          this.pending.hookSeen = true;
          this.pending.hook.resolve(parsed.hook);
        }
        return;
      }
      if (parsed.command !== this.pending.command)
        throw new Error("worker response command mismatch");
      if (this.pending.pauseStage && !this.pending.hookSeen)
        throw new Error("worker completed before the requested hook");
      const pending = this.pending;
      this.pending = undefined;
      pending.result.resolve({ ...parsed, hooks: pending.hooks });
    } catch (error) {
      this.fail(error);
    }
  }

  fail(error) {
    if (!this.failure)
      this.failure =
        error instanceof Error ? error : new Error("worker failed");
    this.readyState.reject(this.failure);
    this.pending?.result.reject(this.failure);
    this.pending?.hook?.reject(this.failure);
    if (!this.closed) this.terminate();
  }

  terminate() {
    if (!Number.isSafeInteger(this.pid) || this.pid <= 0) return;
    try {
      killProcessGroup(this.pid);
    } catch {
      this.cleanupFailures.push(
        new Error("worker process-group termination failed"),
      );
    }
  }

  async ready() {
    await this.readyState.promise;
  }

  async start(command, options = {}) {
    await this.ready();
    if (this.pending) throw new Error("worker request overlap");
    const requestId = this.nextRequestId++;
    const result = deferred();
    const hook = options.pauseStage ? deferred() : undefined;
    this.pending = {
      requestId,
      command,
      pauseStage: options.pauseStage,
      hook,
      result,
      hookSeen: false,
      hooks: [],
    };
    const message = {
      type: "request",
      requestId,
      command,
      ...(options.grantId ? { grantId: options.grantId } : {}),
      ...(options.pauseStage ? { pauseStage: options.pauseStage } : {}),
    };
    try {
      await new Promise((resolvePromise, reject) => {
        this.child.send(message, (error) =>
          error ? reject(error) : resolvePromise(),
        );
      });
    } catch (error) {
      this.fail(error);
      throw this.failure;
    }
    return { result: result.promise, ...(hook ? { hook: hook.promise } : {}) };
  }

  async request(command, options = {}) {
    const pending = await this.start(command, options);
    return await pending.result;
  }

  async requestPaused(command, pauseStage, options = {}) {
    const pending = await this.start(command, { ...options, pauseStage });
    pending.result.catch(() => undefined);
    return { hook: await pending.hook, result: pending.result };
  }

  resume(stage) {
    if (!this.pending?.hookSeen || this.pending.pauseStage !== stage)
      throw new Error("worker resume does not match a paused hook");
    this.child.send({
      type: "resume",
      requestId: this.pending.requestId,
      stage,
    });
  }

  async close() {
    const result = await this.request("close");
    if (!result.ok) throw new Error(`worker close failed: ${result.code}`);
    const completion = await this.waitClosed();
    if (completion.code !== 0 || completion.signal !== null)
      throw new Error("worker did not close cleanly");
    this.assertQuiet();
  }

  async kill() {
    this.terminate();
    const completion = await this.waitClosed();
    if (completion.signal !== "SIGKILL")
      throw new Error("worker was not killed by SIGKILL");
    this.assertQuiet();
    return completion;
  }

  async waitClosed() {
    const completion = await this.closedState.promise;
    if (Number.isSafeInteger(this.pid) && this.pid > 0)
      await assertNoProcessGroup(this.pid);
    this.processGroupAbsent = true;
    if (this.cleanupFailures.length > 0)
      throw new AggregateError(
        this.cleanupFailures,
        "worker process-group cleanup failed",
      );
    if (this.timedOut) throw this.failure ?? new Error("worker timed out");
    if (completion.kind !== "close")
      throw this.failure ?? new Error("worker lifecycle did not close");
    if (this.failure && completion.signal !== "SIGKILL") throw this.failure;
    return { code: completion.code, signal: completion.signal };
  }

  assertQuiet() {
    if (
      Buffer.concat(this.stdout).byteLength !== 0 ||
      Buffer.concat(this.stderr).byteLength !== 0
    )
      throw new Error("worker emitted unexpected stdio");
  }
}

class EvidenceError extends Error {
  constructor(status, reason, evidence = {}) {
    super(reason);
    this.status = status;
    this.evidence = evidence;
  }
}

class DiagnosticError extends Error {}

function normalizeDiagnostic(message, state) {
  let normalized = message.replaceAll("\r", " ").replaceAll("\n", " ");
  if (state?.base)
    normalized = normalized.replaceAll(state.base, "<native-root>");
  return normalized.slice(0, MAX_DIAGNOSTIC_CHARACTERS) || "evidence failed";
}

/** Return a bounded report containing only harness-owned diagnostic messages. */
export function buildDiagnosticReport(error, state = {}) {
  const details = [];
  let total = 0;
  const visit = (failure) => {
    if (failure instanceof AggregateError) {
      const nested = Array.isArray(failure.errors) ? failure.errors : [];
      if (nested.length === 0) visit(undefined);
      else for (const item of nested) visit(item);
      return;
    }
    total += 1;
    if (details.length >= MAX_DIAGNOSTIC_ITEMS) return;
    const message =
      failure instanceof DiagnosticError || failure instanceof EvidenceError
        ? failure.message
        : "unexpected evidence failure";
    details.push(normalizeDiagnostic(message, state));
  };
  visit(error);
  return Object.freeze({
    total,
    details: Object.freeze(details),
    truncated: total > details.length,
  });
}

export function buildNonPassingEvidence(error, state = {}) {
  const diagnostic = buildDiagnosticReport(error, state);
  const retained = error instanceof EvidenceError ? error.evidence : {};
  return {
    ...retained,
    reason: diagnostic.details[0] ?? "evidence failed",
    diagnostic,
  };
}

function expect(value, reason) {
  if (!value) throw new EvidenceError("FAILED", reason);
}

function blocked(prerequisite, state) {
  throw new EvidenceError("BLOCKED", `missing prerequisite: ${prerequisite}`, {
    prerequisite,
    ...(state?.preflightError ? { preflight: state.preflightError } : {}),
  });
}

function expectOk(result, operation) {
  expect(result?.ok === true, `${operation} did not succeed`);
  return result.evidence;
}

function expectCode(result, code, operation) {
  expect(
    result?.ok === false && result.code === code,
    `${operation} did not return ${code}`,
  );
}

const IDS = Object.freeze({
  headerA: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  headerB: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  collision: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  grantA: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  grantB: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  fallbackA: "11111111-2222-4333-8444-555555555555",
  fallbackB: "66666666-7777-4888-8999-aaaaaaaaaaaa",
});

const EMBEDDED_LINK_PROBE = String.raw`#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int directory, descriptor, result;
  if (argc != 3 || chdir(argv[2]) != 0) return 64;
  descriptor = open("source", O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (descriptor < 0 || write(descriptor, "x", 1) != 1 || close(descriptor) != 0) return 65;
  errno = 0;
  if (!strcmp(argv[1], "link")) result = link("source", "target-link");
  else if (!strcmp(argv[1], "linkat")) {
    directory = open(".", O_RDONLY | O_DIRECTORY);
    if (directory < 0) return 66;
    result = linkat(directory, "source", directory, "target-linkat", 0);
    if (close(directory) != 0) return 67;
  } else return 68;
  if (result != -1 || errno != EIO) return 69;
  if (access(!strcmp(argv[1], "link") ? "target-link" : "target-linkat", F_OK) == 0) return 70;
  return 0;
}
`;

function runSync(file, args, options = {}) {
  const result = spawnSync(file, args, {
    encoding: "utf8",
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: options.timeoutMs ?? 30_000,
    maxBuffer: options.maxBuffer ?? MAX_EVIDENCE_BYTES,
    env: options.env ?? process.env,
  });
  if (result.error) throw result.error;
  return result;
}

async function withinBounded(promise, milliseconds, timeoutKind) {
  let timer;
  const timeout = new Promise((resolvePromise) => {
    timer = setTimeout(
      () => resolvePromise({ kind: timeoutKind }),
      milliseconds,
    );
  });
  const result = await Promise.race([promise, timeout]);
  clearTimeout(timer);
  return result;
}

/**
 * Complete one created probe through bounded lifecycle, termination, close, and
 * absence observation. The optional controls are an import-only test seam; the
 * executable path never supplies them.
 */
export async function settleProcessGroupProbe(probe, controls = {}) {
  const failures = [...(controls.initialFailures ?? [])];
  const assertAbsent = controls.assertAbsent ?? assertNoProcessGroup;
  const terminate = controls.terminate ?? killProcessGroup;
  const completion = await withinBounded(
    probe.lifecycle,
    controls.probeTimeoutMs ?? PROCESS_GROUP_PROBE_TIMEOUT_MS,
    "deadline",
  );
  if (completion.kind === "deadline") {
    failures.push(new DiagnosticError("process-group probe timed out"));
  } else if (completion.kind === "error") {
    failures.push(
      new DiagnosticError("process-group probe failed to start", {
        cause: completion.error,
      }),
    );
  }

  const validPid = Number.isSafeInteger(probe.pid) && probe.pid > 0;
  let absenceProven = false;
  if (!validPid) {
    failures.push(new DiagnosticError("process-group probe has no PID"));
    failures.push(
      new DiagnosticError(
        "process-group probe cleanup has no PID; group absence was not claimed",
      ),
    );
  } else {
    try {
      await assertAbsent(probe.pid);
      absenceProven = true;
    } catch (error) {
      failures.push(
        new DiagnosticError(
          "process-group probe absence was not proven before cleanup",
          { cause: error },
        ),
      );
    }
    if (!absenceProven) {
      try {
        terminate(probe.pid);
      } catch (error) {
        failures.push(
          new DiagnosticError("process-group probe termination failed", {
            cause: error,
          }),
        );
      }
    }
  }

  const cleanupClose = await withinBounded(
    probe.closed,
    controls.cleanupTimeoutMs ?? PROCESS_GROUP_PROBE_CLEANUP_MS,
    "cleanup-deadline",
  );
  if (cleanupClose.kind === "cleanup-deadline") {
    failures.push(
      new DiagnosticError(
        "process-group probe close was not observed during cleanup",
      ),
    );
  } else if (cleanupClose.code !== 0 || cleanupClose.signal !== null) {
    failures.push(
      new DiagnosticError("process-group probe cleanup close was not clean"),
    );
  }

  if (validPid) {
    try {
      await assertAbsent(probe.pid);
      absenceProven = true;
    } catch (error) {
      absenceProven = false;
      failures.push(
        new DiagnosticError(
          "process-group probe absence was not proven after cleanup",
          { cause: error },
        ),
      );
    }
  }

  if (failures.length > 0)
    throw new AggregateError(failures, "process-group probe or cleanup failed");
  if (!absenceProven)
    throw new DiagnosticError("process-group probe absence was not proven");
}

async function proveProcessGroups(node) {
  let child;
  try {
    child = spawn(node, ["-e", "process.exit(0)"], {
      detached: true,
      shell: false,
      stdio: "ignore",
    });
  } catch (error) {
    throw new AggregateError(
      [
        new DiagnosticError("process-group probe failed to start", {
          cause: error,
        }),
        new DiagnosticError(
          "process-group probe cleanup has no child; group absence was not claimed",
        ),
      ],
      "process-group probe and cleanup failed",
    );
  }

  let resolveClosed;
  const closed = new Promise((resolvePromise) => {
    resolveClosed = resolvePromise;
  });
  const lifecycle = new Promise((resolvePromise) => {
    child.once("error", (error) => resolvePromise({ kind: "error", error }));
    child.once("close", (code, signal) => {
      const completion = { kind: "close", code, signal };
      resolveClosed(completion);
      resolvePromise(completion);
    });
  });
  const pid = child.pid;
  const initialFailures = [];
  try {
    child.unref();
  } catch (error) {
    initialFailures.push(
      new DiagnosticError("process-group probe lifecycle setup failed", {
        cause: error,
      }),
    );
  }
  await settleProcessGroupProbe(
    { pid, lifecycle, closed },
    { initialFailures },
  );
}

function parseArguments(argv) {
  const config = {
    node: process.execPath,
    worker: resolve("scripts/linux/phase3-approval-worker.mjs"),
    cc: "cc",
    nativeRoot: process.platform === "linux" ? "/var/tmp" : tmpdir(),
    allowTestFake: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--allow-test-fake") {
      config.allowTestFake = true;
      continue;
    }
    const value = argv[++index];
    if (value === undefined) throw new Error(`missing value for ${flag}`);
    if (flag === "--node") config.node = resolve(value);
    else if (flag === "--cc") config.cc = value;
    else if (flag === "--native-root") config.nativeRoot = resolve(value);
    else if (flag === "--output") config.output = resolve(value);
    else throw new Error(`unknown argument ${flag}`);
  }
  return config;
}

export function fakeEvidenceAllowed(environment, allowTestFake) {
  return environment.NODE_ENV === "test" && allowTestFake === true;
}

async function prepareState(config) {
  const state = {
    config,
    clients: new Set(),
    prerequisites: {
      linux: process.platform === "linux",
      uid0: process.getuid?.() === 0,
      compiler: false,
      processGroups: false,
      nativeFs: false,
    },
  };
  if (!state.prerequisites.linux) return state;
  if (!isAbsolute(config.nativeRoot) || !existsSync(config.nativeRoot))
    return state;
  try {
    const filesystem = statfsSync(config.nativeRoot);
    state.filesystemType = `0x${Number(filesystem.type).toString(16)}`;
    state.prerequisites.nativeFs = Number(filesystem.type) !== 0x01021994;
    if (!state.prerequisites.nativeFs) return state;
    state.base = mkdtempSync(join(config.nativeRoot, "ha-phase3m-"));
    chmodSync(state.base, 0o700);
    const compiler = runSync(config.cc, ["--version"], { timeoutMs: 10_000 });
    if (compiler.status !== 0) return state;
    state.shim = join(state.base, "phase3-fault-shim.so");
    state.probe = join(state.base, "phase3-link-probe");
    const probeSource = join(state.base, "phase3-link-probe.c");
    expect(
      Buffer.byteLength(EMBEDDED_LINK_PROBE, "utf8") <= 4_096,
      "embedded probe source is unbounded",
    );
    writeFileSync(probeSource, EMBEDDED_LINK_PROBE, { mode: 0o600 });
    const shimCompile = runSync(config.cc, [
      "-shared",
      "-fPIC",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      resolve("scripts/linux/persistence-fault-shim.c"),
      "-ldl",
      "-o",
      state.shim,
    ]);
    const probeCompile = runSync(config.cc, [
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      probeSource,
      "-o",
      state.probe,
    ]);
    state.prerequisites.compiler =
      shimCompile.status === 0 && probeCompile.status === 0;
    if (!state.prerequisites.compiler) return state;
    await proveProcessGroups(config.node);
    state.prerequisites.processGroups = true;
  } catch (error) {
    state.preflightError = buildDiagnosticReport(error, state);
  }
  return state;
}

function requireNative(state) {
  for (const [name, available] of Object.entries(state.prerequisites)) {
    if (!available) blocked(name, state);
  }
  if (!state.base || !state.shim || !state.probe)
    blocked("native-artifacts", state);
}

async function openWorker(state, root, options = {}) {
  requireNative(state);
  const client = new WorkerClient(state.config, root, options);
  state.clients.add(client);
  await client.ready();
  return client;
}

export async function closeWorker(state, client) {
  try {
    await client.close();
  } finally {
    if (client.processGroupAbsent) state.clients.delete(client);
  }
}

export async function terminateWorkers(state) {
  const failures = [];
  for (const client of [...state.clients]) {
    try {
      if (!client.processGroupAbsent) client.terminate();
      await client.waitClosed();
    } catch (error) {
      failures.push(error);
    }
    if (client.processGroupAbsent) state.clients.delete(client);
  }
  if (failures.length > 0)
    throw new AggregateError(failures, "worker cleanup failed");
}

async function withRoot(state, label, operation) {
  requireNative(state);
  const root = mkdtempSync(join(state.base, `${label.replaceAll(":", "-")}-`));
  chownSync(root, 0, 0);
  chmodSync(root, 0o700);
  let result;
  let operationFailure;
  try {
    result = await operation(root);
  } catch (error) {
    operationFailure = error;
  }
  let cleanupFailure;
  try {
    await terminateWorkers(state);
  } catch (error) {
    cleanupFailure = error;
  }
  if (state.clients.size === 0) {
    try {
      chownSync(root, 0, 0);
      chmodSync(root, 0o700);
    } catch {}
    rmSync(root, { recursive: true, force: true });
  }
  if (operationFailure && cleanupFailure)
    throw new AggregateError(
      [operationFailure, cleanupFailure],
      "operation and worker cleanup failed",
    );
  if (cleanupFailure) throw cleanupFailure;
  if (operationFailure) throw operationFailure;
  return result;
}

async function seedHeader(state, root, key = "primary") {
  const worker = await openWorker(state, root, { key, uuids: [IDS.headerA] });
  expectOk(await worker.request("initialize"), "header seed initialize");
  await closeWorker(state, worker);
}

async function seedGrant(state, root, grantId = IDS.grantA) {
  await seedHeader(state, root);
  const worker = await openWorker(state, root, { uuids: [grantId] });
  expectOk(await worker.request("initialize"), "grant seed initialize");
  const grant = expectOk(
    await worker.request("issue"),
    "grant seed issue",
  ).grant;
  await closeWorker(state, worker);
  return grant;
}

function mutate(path) {
  const bytes = readFileSync(path);
  expect(bytes.byteLength > 0, "tamper fixture is empty");
  bytes[Math.floor(bytes.byteLength / 2)] ^= 1;
  writeFileSync(path, bytes);
}

function faultPaths(root, rowId) {
  const directory = dirname(root);
  const suffix = basename(root);
  return {
    arm: join(directory, `${suffix}-${rowId.replaceAll(":", "-")}.arm`),
    proof: join(directory, `${suffix}-${rowId.replaceAll(":", "-")}.proof`),
  };
}

function faultEnv(state, root, fault, paths) {
  return {
    LD_PRELOAD: state.shim,
    HA_FAULT_ROOT: root,
    HA_FAULT_SYSCALL: fault.call,
    HA_FAULT_MODE: fault.mode,
    HA_FAULT_NTH: String(fault.nth),
    HA_FAULT_ARM: paths.arm,
    HA_FAULT_PROOF: paths.proof,
  };
}

function assertFaultProof(path, fault, expectedTarget) {
  expect(existsSync(path), "fault proof was not created");
  const lines = readFileSync(path, "utf8").trim().split("\n");
  expect(lines.length === 1, "fault proof count mismatch");
  let proof;
  try {
    proof = JSON.parse(lines[0]);
  } catch {
    throw new EvidenceError("FAILED", "fault proof is malformed");
  }
  expect(
    exactKeys(proof, ["syscall", "nth", "mode", "target"]),
    "fault proof shape mismatch",
  );
  const calls =
    fault.call === "link-family"
      ? ["link", "linkat"]
      : fault.call === "open-family"
        ? ["open", "open64", "openat", "openat64"]
        : [fault.call];
  expect(calls.includes(proof.syscall), "fault proof syscall mismatch");
  expect(
    proof.nth === fault.nth && proof.mode === fault.mode,
    "fault proof classification mismatch",
  );
  expect(
    RELATIVE_ARTIFACT_PATTERN.test(proof.target) || proof.target === ".",
    "fault proof path escaped root",
  );
  if (expectedTarget !== undefined)
    expect(proof.target === expectedTarget, "fault proof target mismatch");
  return proof;
}

const rowHandlers = new Map();
function row(id, handler) {
  if (rowHandlers.has(id)) throw new Error(`duplicate row handler ${id}`);
  rowHandlers.set(id, handler);
}

row("env:linux", async (state) => {
  if (!state.prerequisites.linux) blocked("linux", state);
  return {
    platform: process.platform,
    processGroups: state.prerequisites.processGroups,
  };
});

row("env:native-fs", async (state) => {
  if (!state.prerequisites.linux) blocked("linux", state);
  if (!state.prerequisites.nativeFs) blocked("nativeFs", state);
  return { filesystemType: state.filesystemType, adapters: MANIFEST.adapters };
});

row("env:root-private", async (state) => {
  requireNative(state);
  return await withRoot(state, "env-root", async (root) => {
    const metadata = lstatSync(root);
    expect(metadata.isDirectory(), "approval root is not a directory");
    expect((metadata.mode & 0o777) === 0o700, "approval root mode is not 0700");
    expect(
      metadata.uid === 0 && metadata.gid === 0,
      "approval root is not owned by UID/GID 0",
    );
    return { mode: "0700", uid: metadata.uid, gid: metadata.gid };
  });
});

row(
  "init:same-key-race",
  async (state) =>
    await withRoot(state, "init-same", async (root) => {
      const left = await openWorker(state, root, { uuids: [IDS.headerA] });
      const right = await openWorker(state, root, { uuids: [IDS.headerB] });
      const results = await Promise.all([
        left.request("initialize"),
        right.request("initialize"),
      ]);
      results.forEach((result) => expectOk(result, "same-key initialize"));
      await Promise.all([closeWorker(state, left), closeWorker(state, right)]);
      const fresh = await openWorker(state, root);
      expectOk(await fresh.request("initialize"), "same-key fresh initialize");
      await closeWorker(state, fresh);
      return { successes: 2, fresh: "healthy" };
    }),
);

row(
  "init:different-key-race",
  async (state) =>
    await withRoot(state, "init-different", async (root) => {
      const left = await openWorker(state, root, {
        key: "primary",
        uuids: [IDS.headerA],
      });
      const right = await openWorker(state, root, {
        key: "secondary",
        uuids: [IDS.headerB],
      });
      const results = await Promise.all([
        left.request("initialize"),
        right.request("initialize"),
      ]);
      expect(
        results.filter((result) => result.ok).length === 1,
        "different-key race did not have one winner",
      );
      const loserIndex = results.findIndex((result) => !result.ok);
      expectCode(
        results[loserIndex],
        "approval_commit_unknown",
        "different-key loser",
      );
      const winnerKey = loserIndex === 0 ? "secondary" : "primary";
      const loserKey = loserIndex === 0 ? "primary" : "secondary";
      await Promise.all([closeWorker(state, left), closeWorker(state, right)]);
      const loser = await openWorker(state, root, { key: loserKey });
      expectCode(
        await loser.request("initialize"),
        "approval_store_unhealthy",
        "fresh losing key",
      );
      await closeWorker(state, loser);
      const winner = await openWorker(state, root, { key: winnerKey });
      expectOk(await winner.request("initialize"), "fresh winning key");
      await closeWorker(state, winner);
      return { winnerKey, loser: "unhealthy", winner: "healthy" };
    }),
);

row(
  "init:wrong-key-restart",
  async (state) =>
    await withRoot(state, "init-wrong", async (root) => {
      await seedHeader(state, root);
      const wrong = await openWorker(state, root, { key: "secondary" });
      expectCode(
        await wrong.request("initialize"),
        "approval_store_unhealthy",
        "wrong-key restart",
      );
      await closeWorker(state, wrong);
      const correct = await openWorker(state, root, { key: "primary" });
      expectOk(await correct.request("initialize"), "correct-key restart");
      await closeWorker(state, correct);
      return { wrong: "unhealthy", correct: "healthy" };
    }),
);

row(
  "cross:issue-consume-replay",
  async (state) =>
    await withRoot(state, "cross", async (root) => {
      const grant = await seedGrant(state, root);
      const consumer = await openWorker(state, root);
      expectOk(await consumer.request("initialize"), "consumer initialize");
      expectOk(
        await consumer.request("consume", { grantId: grant.grantId }),
        "cross-process consume",
      );
      await closeWorker(state, consumer);
      const replay = await openWorker(state, root);
      expectOk(await replay.request("initialize"), "replay initialize");
      expectCode(
        await replay.request("consume", { grantId: grant.grantId }),
        "approval_replayed",
        "cross-process replay",
      );
      await closeWorker(state, replay);
      return {
        grantId: grant.grantId,
        consume: "success",
        replay: "approval_replayed",
      };
    }),
);

row(
  "race:issue-colliding-uuid",
  async (state) =>
    await withRoot(state, "race-issue", async (root) => {
      await seedHeader(state, root);
      const left = await openWorker(state, root, {
        uuids: [IDS.collision, IDS.fallbackA],
      });
      const right = await openWorker(state, root, {
        uuids: [IDS.collision, IDS.fallbackB],
      });
      expectOk(await left.request("initialize"), "left issue-race initialize");
      expectOk(
        await right.request("initialize"),
        "right issue-race initialize",
      );
      const results = await Promise.all([
        left.request("issue"),
        right.request("issue"),
      ]);
      const grants = results.map(
        (result) => expectOk(result, "colliding issue").grant,
      );
      expect(
        new Set(grants.map((grant) => grant.grantId)).size === 2,
        "colliding UUID race duplicated a grant ID",
      );
      expect(
        grants.some((grant) => grant.grantId === IDS.collision),
        "colliding UUID winner is absent",
      );
      await Promise.all([closeWorker(state, left), closeWorker(state, right)]);
      const fresh = await openWorker(state, root);
      expectOk(
        await fresh.request("initialize"),
        "colliding UUID fresh authentication",
      );
      await closeWorker(state, fresh);
      return {
        grantIds: grants.map((grant) => grant.grantId).sort(),
        unique: 2,
      };
    }),
);

row(
  "race:consume",
  async (state) =>
    await withRoot(state, "race-consume", async (root) => {
      const grant = await seedGrant(state, root);
      const left = await openWorker(state, root);
      const right = await openWorker(state, root);
      expectOk(
        await left.request("initialize"),
        "left consume-race initialize",
      );
      expectOk(
        await right.request("initialize"),
        "right consume-race initialize",
      );
      const results = await Promise.all([
        left.request("consume", { grantId: grant.grantId }),
        right.request("consume", { grantId: grant.grantId }),
      ]);
      expect(
        results.filter((result) => result.ok).length === 1,
        "consume race did not have one winner",
      );
      expect(
        results.filter(
          (result) => !result.ok && result.code === "approval_replayed",
        ).length === 1,
        "consume race loser was not replay",
      );
      await Promise.all([closeWorker(state, left), closeWorker(state, right)]);
      return { success: 1, replay: 1 };
    }),
);

async function tamperRow(state, artifact) {
  return await withRoot(state, `tamper-${artifact}`, async (root) => {
    let path;
    if (artifact === "header") {
      await seedHeader(state, root);
      path = join(root, "header.json");
    } else {
      const grant = await seedGrant(state, root);
      path = join(
        root,
        "slot-000",
        artifact === "grant" ? "grant.json" : "used.json",
      );
      if (artifact === "receipt") {
        const consumer = await openWorker(state, root);
        expectOk(
          await consumer.request("initialize"),
          "tamper receipt initialize",
        );
        expectOk(
          await consumer.request("consume", { grantId: grant.grantId }),
          "tamper receipt seed",
        );
        await closeWorker(state, consumer);
      }
    }
    mutate(path);
    const fresh = await openWorker(state, root);
    expectCode(
      await fresh.request("initialize"),
      "approval_store_unhealthy",
      `${artifact} tamper initialize`,
    );
    await closeWorker(state, fresh);
    return { artifact, classification: "approval_store_unhealthy" };
  });
}

row("tamper:header", async (state) => await tamperRow(state, "header"));
row("tamper:grant", async (state) => await tamperRow(state, "grant"));
row("tamper:receipt", async (state) => await tamperRow(state, "receipt"));

row(
  "exhaustion:header-same-instance-retry",
  async (state) =>
    await withRoot(state, "exhaust-header", async (root) => {
      for (let index = 0; index < 4; index += 1)
        writeFileSync(join(root, `.header-stage-${index}`), "", {
          mode: 0o600,
        });
      const worker = await openWorker(state, root, {
        uuids: [IDS.headerA, IDS.headerB],
      });
      expectCode(
        await worker.request("initialize"),
        "approval_capacity_exhausted",
        "header exhaustion",
      );
      rmSync(join(root, ".header-stage-0"));
      expectOk(
        await worker.request("initialize"),
        "header same-instance retry",
      );
      await closeWorker(state, worker);
      return { fixtures: 4, removed: 1, retry: "success" };
    }),
);

row(
  "exhaustion:grant-same-instance-retry",
  async (state) =>
    await withRoot(state, "exhaust-grant", async (root) => {
      await seedHeader(state, root);
      const worker = await openWorker(state, root, {
        uuids: [IDS.grantA, IDS.grantB],
      });
      expectOk(
        await worker.request("initialize"),
        "grant exhaustion initialize",
      );
      for (let index = 0; index < 32; index += 1)
        mkdirSync(
          join(root, `.grant-stage-${String(index).padStart(2, "0")}`),
          { mode: 0o700 },
        );
      expectCode(
        await worker.request("issue"),
        "approval_capacity_exhausted",
        "grant exhaustion",
      );
      rmSync(join(root, ".grant-stage-00"), { recursive: true });
      expectOk(await worker.request("issue"), "grant same-instance retry");
      await closeWorker(state, worker);
      return { fixtures: 32, removed: 1, retry: "success" };
    }),
);

row(
  "exhaustion:receipt-same-instance-retry",
  async (state) =>
    await withRoot(state, "exhaust-receipt", async (root) => {
      const grant = await seedGrant(state, root);
      const worker = await openWorker(state, root);
      expectOk(
        await worker.request("initialize"),
        "receipt exhaustion initialize",
      );
      for (let index = 0; index < 4; index += 1)
        writeFileSync(join(root, "slot-000", `.used-stage-${index}`), "", {
          mode: 0o600,
        });
      expectCode(
        await worker.request("consume", { grantId: grant.grantId }),
        "approval_capacity_exhausted",
        "receipt exhaustion",
      );
      rmSync(join(root, "slot-000", ".used-stage-0"));
      expectOk(
        await worker.request("consume", { grantId: grant.grantId }),
        "receipt same-instance retry",
      );
      await closeWorker(state, worker);
      return { fixtures: 4, removed: 1, retry: "success" };
    }),
);

async function expectTopologyFailure(state, label, fixture) {
  return await withRoot(state, label, async (root) => {
    await fixture(root);
    const worker = await openWorker(state, root, { uuids: [IDS.headerA] });
    expectCode(
      await worker.request("initialize"),
      "approval_store_unhealthy",
      `${label} topology`,
    );
    await closeWorker(state, worker);
    return { topology: label, classification: "approval_store_unhealthy" };
  });
}

row(
  "topology:root-mode",
  async (state) =>
    await expectTopologyFailure(state, "root-mode", async (root) =>
      chmodSync(root, 0o755),
    ),
);
row(
  "topology:root-owner",
  async (state) =>
    await expectTopologyFailure(state, "root-owner", async (root) =>
      chownSync(root, 65_534, 65_534),
    ),
);
row(
  "topology:header-symlink",
  async (state) =>
    await expectTopologyFailure(state, "header-symlink", async (root) => {
      await seedHeader(state, root);
      const outside = `${root}-header-copy`;
      copyFileSync(join(root, "header.json"), outside);
      rmSync(join(root, "header.json"));
      symlinkSync(outside, join(root, "header.json"));
    }),
);
row(
  "topology:header-hardlink",
  async (state) =>
    await expectTopologyFailure(state, "header-hardlink", async (root) => {
      await seedHeader(state, root);
      linkSync(join(root, "header.json"), `${root}-header-link`);
    }),
);
row(
  "topology:header-nonregular",
  async (state) =>
    await expectTopologyFailure(state, "header-nonregular", async (root) => {
      await seedHeader(state, root);
      rmSync(join(root, "header.json"));
      mkdirSync(join(root, "header.json"), { mode: 0o700 });
    }),
);
row(
  "topology:root-unknown-entry",
  async (state) =>
    await expectTopologyFailure(state, "root-unknown", async (root) => {
      writeFileSync(join(root, "unknown"), "", { mode: 0o600 });
    }),
);
row(
  "topology:root-entry-overflow",
  async (state) =>
    await expectTopologyFailure(state, "root-overflow", async (root) => {
      for (let index = 0; index < 294; index += 1)
        writeFileSync(
          join(root, `overflow-${String(index).padStart(3, "0")}`),
          "",
          { mode: 0o600 },
        );
    }),
);
row(
  "topology:slot-entry-overflow",
  async (state) =>
    await expectTopologyFailure(state, "slot-overflow", async (root) => {
      await seedGrant(state, root);
      for (let index = 0; index < 6; index += 1)
        writeFileSync(join(root, "slot-000", `overflow-${index}`), "", {
          mode: 0o600,
        });
    }),
);

function killExpectation(stage) {
  if (stage.endsWith("pre_commit")) return "not_committed";
  if (stage.endsWith("post_commit")) return "possibly_committed";
  return "durably_committed";
}

async function killRow(state, artifact, point) {
  const stage = `${artifact}_${point === "precommit" ? "pre_commit" : point === "postcommit" ? "post_commit" : "parent_synced"}`;
  return await withRoot(state, `kill-${artifact}-${point}`, async (root) => {
    let grantId = IDS.grantA;
    if (artifact === "grant") await seedHeader(state, root);
    if (artifact === "receipt")
      grantId = (await seedGrant(state, root)).grantId;
    const worker = await openWorker(state, root, {
      uuids:
        artifact === "header"
          ? [IDS.headerA]
          : artifact === "grant"
            ? [grantId]
            : [],
    });
    if (artifact !== "header")
      expectOk(
        await worker.request("initialize"),
        `${artifact} kill initialize`,
      );
    const command =
      artifact === "header"
        ? "initialize"
        : artifact === "grant"
          ? "issue"
          : "consume";
    const paused = await worker.requestPaused(
      command,
      stage,
      artifact === "receipt" ? { grantId } : {},
    );
    expect(
      paused.hook.commitState === killExpectation(stage),
      `${stage} commit-state mismatch`,
    );
    const relativeFinal = paused.hook.relativeFinal;
    await worker.kill();
    state.clients.delete(worker);
    const finalPath = join(root, ...relativeFinal.split("/"));
    expect(
      existsSync(finalPath) === (point !== "precommit"),
      `${stage} final-artifact state mismatch`,
    );

    const fresh = await openWorker(state, root, {
      uuids:
        artifact === "header" && point === "precommit"
          ? [IDS.headerB]
          : artifact === "grant" && point === "precommit"
            ? [IDS.grantB]
            : [],
    });
    expectOk(await fresh.request("initialize"), `${stage} fresh initialize`);
    let recovery;
    if (artifact === "grant") {
      if (point === "precommit") {
        expectOk(await fresh.request("issue"), `${stage} retry issue`);
        recovery = "retry-success";
      } else {
        expectOk(
          await fresh.request("consume", { grantId }),
          `${stage} fresh consume`,
        );
        recovery = "authenticated-consume";
      }
    } else if (artifact === "receipt") {
      const result = await fresh.request("consume", { grantId });
      if (point === "precommit") {
        expectOk(result, `${stage} retry consume`);
        recovery = "retry-success";
      } else {
        expectCode(result, "approval_replayed", `${stage} fresh replay`);
        recovery = "authenticated-replay";
      }
    } else
      recovery =
        point === "precommit" ? "retry-success" : "authenticated-header";
    await closeWorker(state, fresh);
    return {
      stage,
      commitState: paused.hook.commitState,
      finalPresent: point !== "precommit",
      recovery,
    };
  });
}

for (const artifact of ["header", "grant", "receipt"])
  for (const point of ["precommit", "postcommit", "parent-synced"])
    row(
      `kill:${artifact}:${point}`,
      async (state) => await killRow(state, artifact, point),
    );

const faultDefinitions = Object.freeze({
  "open-header": Object.freeze({ call: "open-family", mode: "fail", nth: 1 }),
  "open-grant": Object.freeze({ call: "open-family", mode: "fail", nth: 2 }),
  "open-receipt": Object.freeze({ call: "open-family", mode: "fail", nth: 3 }),
  "pwrite-fail": Object.freeze({ call: "pwrite", mode: "fail", nth: 1 }),
  "pwrite-short": Object.freeze({ call: "pwrite", mode: "short", nth: 1 }),
  "pwrite-enospc": Object.freeze({ call: "pwrite", mode: "enospc", nth: 1 }),
  "file-fsync": Object.freeze({ call: "fsync", mode: "fail", nth: 1 }),
  "link-family": Object.freeze({ call: "link-family", mode: "fail", nth: 1 }),
  "parent-fsync-header": Object.freeze({ call: "fsync", mode: "fail", nth: 2 }),
  "stage-fsync": Object.freeze({ call: "fsync", mode: "fail", nth: 2 }),
  rename: Object.freeze({ call: "rename", mode: "fail", nth: 1 }),
  "parent-fsync-grant": Object.freeze({ call: "fsync", mode: "fail", nth: 3 }),
  "parent-fsync-receipt": Object.freeze({
    call: "fsync",
    mode: "fail",
    nth: 2,
  }),
});

async function authenticateAfterFault(
  state,
  root,
  artifact,
  grantId,
  expected,
) {
  const fresh = await openWorker(state, root);
  expectOk(
    await fresh.request("initialize"),
    `${artifact} post-fault authentication`,
  );
  if (artifact === "grant")
    expectOk(
      await fresh.request("consume", { grantId }),
      "grant post-fault authentication",
    );
  if (artifact === "receipt")
    expectCode(
      await fresh.request("consume", { grantId }),
      expected === "short" ? "approval_replayed" : "approval_replayed",
      "receipt post-fault authentication",
    );
  await closeWorker(state, fresh);
}

async function faultRow(state, artifact, name) {
  const definitionName =
    name === "parent-fsync"
      ? `parent-fsync-${artifact}`
      : name === "open"
        ? `open-${artifact}`
        : name;
  const fault = faultDefinitions[definitionName];
  expect(fault, `missing fault definition ${definitionName}`);
  return await withRoot(state, `fault-${artifact}-${name}`, async (root) => {
    const paths = faultPaths(root, `${artifact}-${name}`);
    let grantId = IDS.grantA;
    if (artifact !== "header") await seedHeader(state, root);
    const worker = await openWorker(state, root, {
      uuids: artifact === "header" ? [IDS.headerA] : [grantId],
      env: faultEnv(state, root, fault, paths),
    });
    if (artifact !== "header") {
      expectOk(
        await worker.request("initialize"),
        `${artifact} fault initialize`,
      );
      if (artifact === "receipt") {
        const grant = expectOk(
          await worker.request("issue"),
          "receipt fault seed issue",
        ).grant;
        grantId = grant.grantId;
      }
    }
    writeFileSync(paths.arm, "armed", { mode: 0o600 });
    const result =
      artifact === "header"
        ? await worker.request("initialize")
        : artifact === "grant"
          ? await worker.request("issue")
          : await worker.request("consume", { grantId });
    const isShort = name === "pwrite-short";
    const isParent = name === "parent-fsync";
    if (isShort) expectOk(result, `${artifact} short-write operation`);
    else
      expectCode(
        result,
        isParent ? "approval_commit_unknown" : "approval_store_unhealthy",
        `${artifact} ${name} fault`,
      );
    const expectedTarget =
      name === "parent-fsync"
        ? artifact === "receipt"
          ? "slot-000"
          : "."
        : name === "link-family"
          ? artifact === "header"
            ? "header.json"
            : "slot-000/used.json"
          : name === "rename"
            ? "slot-000"
            : name === "stage-fsync"
              ? ".grant-stage-00"
              : artifact === "header"
                ? ".header-stage-0"
                : artifact === "grant"
                  ? ".grant-stage-00/grant.json"
                  : "slot-000/.used-stage-0";
    const proof = assertFaultProof(paths.proof, fault, expectedTarget);
    await closeWorker(state, worker);
    if (isShort || isParent)
      await authenticateAfterFault(
        state,
        root,
        artifact,
        grantId,
        isShort ? "short" : "parent",
      );
    return {
      artifact,
      fault: name,
      syscall: proof.syscall,
      target: proof.target,
      outcome: isShort
        ? "success-authenticated"
        : isParent
          ? "approval_commit_unknown"
          : "approval_store_unhealthy",
    };
  });
}

const artifactFaults = Object.freeze({
  header: Object.freeze([
    "open",
    "pwrite-fail",
    "pwrite-short",
    "pwrite-enospc",
    "file-fsync",
    "link-family",
    "parent-fsync",
  ]),
  grant: Object.freeze([
    "open",
    "pwrite-fail",
    "pwrite-short",
    "pwrite-enospc",
    "file-fsync",
    "stage-fsync",
    "rename",
    "parent-fsync",
  ]),
  receipt: Object.freeze([
    "open",
    "pwrite-fail",
    "pwrite-short",
    "pwrite-enospc",
    "file-fsync",
    "link-family",
    "parent-fsync",
  ]),
});
for (const [artifact, names] of Object.entries(artifactFaults))
  for (const name of names)
    row(
      `fault:${artifact}:${name}`,
      async (state) => await faultRow(state, artifact, name),
    );

async function shimRow(state, call) {
  return await withRoot(state, `shim-${call}`, async (root) => {
    const paths = faultPaths(root, `shim-${call}`);
    const fault = { call, mode: "fail", nth: 1 };
    writeFileSync(paths.arm, "armed", { mode: 0o600 });
    const result = runSync(state.probe, [call, root], {
      env: { ...process.env, ...faultEnv(state, root, fault, paths) },
      timeoutMs: 10_000,
    });
    expect(
      result.status === 0 && result.signal === null,
      `${call} shim probe failed`,
    );
    expect(
      result.stdout === "" && result.stderr === "",
      `${call} shim probe emitted output`,
    );
    const proof = assertFaultProof(
      paths.proof,
      fault,
      call === "link" ? "target-link" : "target-linkat",
    );
    return { syscall: proof.syscall, errno: "EIO", target: proof.target };
  });
}

row("shim:link:fail", async (state) => await shimRow(state, "link"));
row("shim:linkat:fail", async (state) => await shimRow(state, "linkat"));

function buildSummary(rows) {
  const nonPassed = rows
    .filter((rowValue) => rowValue.status !== "PASSED")
    .map((rowValue) => rowValue.id);
  return {
    type: "summary",
    status: summaryStatus(rows),
    required: APPROVAL_EVIDENCE_IDS.length,
    executed: rows.length,
    passed: rows.length - nonPassed.length,
    nonPassed,
  };
}

function sanitizeFailure(error, state) {
  let reason =
    error instanceof Error ? error.message : "unexpected evidence failure";
  if (state?.base) reason = reason.replaceAll(state.base, "<native-root>");
  reason = reason.replaceAll("\r", " ").replaceAll("\n", " ").slice(0, 512);
  return reason || "unexpected evidence failure";
}

function writeRecord(record, capture) {
  const line = `${JSON.stringify(record)}\n`;
  if (Buffer.byteLength(capture.value + line, "utf8") > MAX_EVIDENCE_BYTES)
    throw new Error("approval evidence exceeded its output bound");
  capture.value += line;
  process.stdout.write(line);
}

async function runNativeHarness(config) {
  const capture = { value: "" };
  writeRecord(MANIFEST, capture);
  let state;
  const results = [];
  let runFailure;
  try {
    state = await prepareState(config);
    if (!sameJson([...rowHandlers.keys()], APPROVAL_EVIDENCE_IDS))
      throw new Error("mandatory Phase 3M row registry mismatch");
    for (const id of APPROVAL_EVIDENCE_IDS) {
      let result;
      try {
        const evidence = await rowHandlers.get(id)(state);
        result = {
          type: "row",
          id,
          status: "PASSED",
          evidence: evidence ?? {},
        };
      } catch (error) {
        const status = TERMINAL_STATUSES.has(error?.status)
          ? error.status
          : "FAILED";
        result = {
          type: "row",
          id,
          status,
          evidence: buildNonPassingEvidence(error, state),
        };
      } finally {
        if (state) {
          try {
            await terminateWorkers(state);
          } catch (error) {
            result = {
              ...result,
              status: "FAILED",
              evidence: {
                ...result.evidence,
                cleanup: sanitizeFailure(error, state),
              },
            };
          }
        }
      }
      results.push(result);
      writeRecord(result, capture);
    }
    const summary = buildSummary(results);
    writeRecord(summary, capture);
    parseApprovalEvidence(capture.value);
    if (config.output)
      writeFileSync(config.output, capture.value, { flag: "wx", mode: 0o600 });
    process.exitCode = summary.status === "PASSED" ? 0 : 1;
  } catch (error) {
    runFailure = error;
  }
  let cleanupFailure;
  if (state) {
    try {
      await terminateWorkers(state);
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (state?.base && state.clients.size === 0)
    rmSync(state.base, { recursive: true, force: true });
  if (runFailure && cleanupFailure)
    throw new AggregateError(
      [runFailure, cleanupFailure],
      "harness execution and worker cleanup failed",
    );
  if (cleanupFailure) throw cleanupFailure;
  if (runFailure) throw runFailure;
}

function runFakeEvidence(config, encoded) {
  if (!fakeEvidenceAllowed(process.env, config.allowTestFake))
    throw new Error(
      "test fake evidence requires NODE_ENV=test and --allow-test-fake",
    );
  if (encoded.length > Math.ceil((MAX_EVIDENCE_BYTES * 4) / 3) + 8)
    throw new Error("test fake evidence exceeds the encoded input bound");
  const output = Buffer.from(encoded, "base64").toString("utf8");
  const parsed = parseApprovalEvidence(output);
  process.stdout.write(output);
  if (config.output)
    writeFileSync(config.output, output, { flag: "wx", mode: 0o600 });
  process.exitCode = parsed.summary.status === "PASSED" ? 0 : 1;
}

async function main() {
  const config = parseArguments(process.argv.slice(2));
  const fake = process.env.HA_PHASE3_APPROVAL_HARNESS_FAKE_OUTPUT_BASE64;
  if (fake !== undefined) runFakeEvidence(config, fake);
  else await runNativeHarness(config);
}

const isEntryPoint =
  typeof process.argv[1] === "string" &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isEntryPoint)
  await main().catch((error) => {
    process.stderr.write(
      `phase3 approval harness failed: ${sanitizeFailure(error)}\n`,
    );
    process.exitCode = 65;
  });
