#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, join, posix, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

export const PHASE3_WORKFLOW_POC_ACK = "--ack-disposable-phase3-poc";
export const PHASE3_WORKFLOW_POC_ROWS = Object.freeze([
  "environment:linux-unprivileged",
  "workspace:private-mounted-safe",
  "native:helpers-provenance",
  "scenario:success",
  "scenario:rollback",
  "scenario:true-restart-commit-kill",
  "scenario:true-restart-recovery",
  "cleanup:proved",
]);

const STATUS = new Set(["PASSED", "FAILED", "SKIPPED", "BLOCKED"]);
const DENIED_ROOTS = Object.freeze([
  "/homeassistant",
  "/config",
  "/data",
  "/app",
  "/mnt/data/supervisor/homeassistant",
  "/usr/share/hassio/homeassistant",
]);
const DENIED_ENV = Object.freeze([
  "SUPERVISOR_TOKEN",
  "HASSIO_TOKEN",
  "HOME_ASSISTANT_TOKEN",
  "HA_TOKEN",
  "LONG_LIVED_ACCESS_TOKEN",
]);
const ARTIFACTS = Object.freeze({
  list: "native/openat2-list",
  read: "native/openat2-read",
  replace: "native/openat2-replace",
  nonce: ".phase3-poc-nonce",
});
export const PHASE3_WORKFLOW_POC_MANIFEST = Object.freeze({
  type: "manifest",
  version: 1,
  requiredRows: PHASE3_WORKFLOW_POC_ROWS,
  proposalProducer: "fixture_via_exported_store_api",
  sourceEvidence: "schema_required_legacy_literal_not_poc_evidence",
  stateLimitation: "domain_reload_is_frozen_harness_proposal_fixture",
  prerequisites: Object.freeze([
    "linux",
    "unprivileged_equal_real_effective_uid",
    "node_22_through_24",
    "cc",
    "readelf",
    "libcrypto_so_3",
  ]),
  limitations: Object.freeze([
    "disposable_scenario_and_native_state_only",
    "sigkill_is_process_death_not_power_loss",
    "no_home_assistant_or_supervisor_call",
    "same_uid_transient_swap_restore_not_defeated_by_path_cleanup",
    "not_production_evidence",
  ]),
});
const MANIFEST = PHASE3_WORKFLOW_POC_MANIFEST;
const PROTOCOL = 1;
const RELATIVE_ARTIFACT_PATTERN =
  /^(?!\/)(?!\.\.?$)(?!\.\.\/)(?!.*\/\.\.?(?:\/|$))[A-Za-z0-9._/-]+$/u;
const MAX_EVIDENCE_BYTES = 1_048_576;
const MAX_ROW_BYTES = 8_192;
const MAX_IPC_BYTES = 16_384;
const MAX_IPC_MESSAGES = 16;
const MAX_STDIO_BYTES = 16_384;
const WORKER_TIMEOUT_MS = 45_000;
const WORKER_DEADLINE_MS = 30_000;
const HELPER_SCAN_POLL_MS = 20;
const CHILD_CLOSE_TIMEOUT_MS = 5_000;
const PROCESS_PROOF_DEADLINE_MS = 5_000;
const MAX_PROC_PID_ENTRIES = 32_768;
const MAX_HELPER_EXECUTABLE_BYTES = 1_048_576;
const MAX_PROC_SCAN_MS = 1_000;
const SCRIPT_ROOT = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_ROOT, "..", "..");
const WORKER_PATH = join(SCRIPT_ROOT, "phase3-workflow-poc-worker.mjs");
const SOURCE_PATHS = Object.freeze({
  list: join(REPOSITORY_ROOT, "src", "repository", "native", "openat2-list.c"),
  read: join(REPOSITORY_ROOT, "src", "security", "native", "openat2-read.c"),
  replace: join(
    REPOSITORY_ROOT,
    "src",
    "phase3",
    "native",
    "openat2-replace.c",
  ),
});
let cleanupFailureClassification = "not_started";

export function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === "string") &&
    expected.every((key) => keys.includes(key))
  );
}

export function isClosedArtifactName(value) {
  return (
    typeof value === "string" &&
    RELATIVE_ARTIFACT_PATTERN.test(value) &&
    Object.values(ARTIFACTS).includes(value)
  );
}

export function pathsIntersect(left, right) {
  const a = posix.resolve(left);
  const b = posix.resolve(right);
  return (
    a === "/" ||
    b === "/" ||
    a === b ||
    a.startsWith(`${b}/`) ||
    b.startsWith(`${a}/`)
  );
}

export function assertWorkspacePathAllowed(path) {
  if (
    typeof path !== "string" ||
    !posix.isAbsolute(path) ||
    posix.resolve(path) !== path ||
    DENIED_ROOTS.some((denied) => pathsIntersect(path, denied))
  )
    throw safeFailure("workspace_denied");
  return path;
}

export function validateEnvironmentBoundary(boundaries) {
  const { platform, uid, euid, nodeVersion, environment } = boundaries;
  if (platform !== "linux") throw safeFailure("linux_required");
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(euid))
    throw safeFailure("uid_api_unavailable");
  if (uid !== euid) throw safeFailure("uid_euid_mismatch");
  if (uid === 0) throw safeFailure("root_rejected");
  const major = Number(String(nodeVersion).split(".")[0]);
  if (!Number.isInteger(major) || major < 22 || major > 24)
    throw safeFailure("node_version_rejected");
  for (const name of DENIED_ENV)
    if (Object.hasOwn(environment, name))
      throw safeFailure("credential_environment_present");
  return Object.freeze({ uidEqual: true, uidNonzero: true, nodeMajor: major });
}

function decodeMountField(value) {
  return value.replace(/\\(040|011|012|134)/gu, (match, code) => {
    const decoded = { "040": " ", "011": "\t", "012": "\n", 134: "\\" };
    return decoded[code] ?? match;
  });
}

export function parseMountInfo(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_194_304
  )
    throw safeFailure("mountinfo_invalid");
  const mountpoints = [];
  for (const line of value.trimEnd().split("\n")) {
    const fields = line.split(" ");
    const separator = fields.indexOf("-");
    if (separator < 6 || fields.length < separator + 3 || !fields[4])
      throw safeFailure("mountinfo_invalid");
    const mountpoint = decodeMountField(fields[4]);
    if (!mountpoint.startsWith("/") || posix.resolve(mountpoint) !== mountpoint)
      throw safeFailure("mountinfo_invalid");
    mountpoints.push(mountpoint);
  }
  return Object.freeze(mountpoints);
}

export function assertNoMountAtOrBelow(workspace, mountInfo) {
  const root = assertWorkspacePathAllowed(workspace);
  const found = parseMountInfo(mountInfo).some(
    (mountpoint) => mountpoint === root || mountpoint.startsWith(`${root}/`),
  );
  if (found) throw safeFailure("workspace_mount_detected");
}

function forbiddenString(value) {
  if (Buffer.byteLength(value, "utf8") > 512) return true;
  if (/^[A-Za-z]:[\\/]/u.test(value) || /^\\\\/u.test(value)) return true;
  if (
    /(^|[\s"'=(])\/(?:[^/\s"'=]+\/?)*($|[\s"',;)])/u.test(value) ||
    DENIED_ROOTS.some((root) => value.includes(root))
  )
    return true;
  if (
    /(?:bearer\s+[A-Za-z0-9._~-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{16,}\.)/iu.test(
      value,
    )
  )
    return true;
  return false;
}

export function sanitizeEvidence(value) {
  const seen = new WeakSet();
  let nodes = 0;
  const visit = (candidate) => {
    nodes += 1;
    if (nodes > 512) throw safeFailure("evidence_oversized");
    if (
      candidate === null ||
      typeof candidate === "boolean" ||
      (typeof candidate === "number" && Number.isSafeInteger(candidate))
    )
      return candidate;
    if (typeof candidate === "string") {
      if (forbiddenString(candidate)) throw safeFailure("evidence_rejected");
      return candidate;
    }
    if (
      typeof candidate !== "object" ||
      Buffer.isBuffer(candidate) ||
      ArrayBuffer.isView(candidate)
    )
      throw safeFailure("evidence_rejected");
    if (seen.has(candidate)) throw safeFailure("evidence_rejected");
    seen.add(candidate);
    if (Array.isArray(candidate)) {
      if (candidate.length > 128) throw safeFailure("evidence_oversized");
      return Object.freeze(candidate.map(visit));
    }
    const output = Object.create(null);
    const keys = Object.keys(candidate);
    if (
      keys.length > 64 ||
      Reflect.ownKeys(candidate).length !== keys.length ||
      keys.some(
        (key) =>
          !/^[A-Za-z][A-Za-z0-9]*$/u.test(key) ||
          /(?:password|credential|token|privateKey|secretBytes|keyBytes|candidateBytes|diffBytes)/iu.test(
            key,
          ),
      )
    )
      throw safeFailure("evidence_rejected");
    for (const key of keys) output[key] = visit(candidate[key]);
    return Object.freeze(output);
  };
  const sanitized = visit(value);
  if (Buffer.byteLength(JSON.stringify(sanitized), "utf8") > MAX_ROW_BYTES)
    throw safeFailure("evidence_oversized");
  return sanitized;
}

function parseJson(line, lineNumber) {
  try {
    const value = JSON.parse(line);
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new Error("record");
    return value;
  } catch {
    throw new Error(`line ${lineNumber}: malformed JSON`);
  }
}

export function parseWorkflowEvidence(output) {
  if (
    typeof output !== "string" ||
    Buffer.byteLength(output, "utf8") > MAX_EVIDENCE_BYTES ||
    !output.endsWith("\n")
  )
    throw new Error("workflow evidence boundary failed");
  const lines = output.split(/\r?\n/u);
  lines.pop();
  if (lines.some((line) => line.length === 0))
    throw new Error("workflow evidence contains an empty record");
  const records = lines.map(parseJson);
  const manifest = records[0];
  const summary = records.at(-1);
  if (
    !exactKeys(manifest, Object.keys(MANIFEST)) ||
    JSON.stringify(manifest) !== JSON.stringify(MANIFEST)
  )
    throw new Error("manifest mismatch");
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
  )
    throw new Error("summary mismatch");
  const rows = records.slice(1, -1);
  if (rows.length !== PHASE3_WORKFLOW_POC_ROWS.length)
    throw new Error("mandatory row count mismatch");
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    if (
      !exactKeys(row, ["type", "id", "status", "evidence"]) ||
      row.type !== "row" ||
      row.id !== PHASE3_WORKFLOW_POC_ROWS[index] ||
      !STATUS.has(row.status) ||
      seen.has(row.id)
    )
      throw new Error(`row ${index + 1} mismatch`);
    sanitizeEvidence(row.evidence);
    seen.add(row.id);
  }
  const nonPassed = rows
    .filter((row) => row.status !== "PASSED")
    .map((row) => row.id);
  const expectedStatus = nonPassed.length === 0 ? "PASSED" : "FAILED";
  if (
    summary.status !== expectedStatus ||
    summary.required !== rows.length ||
    summary.executed !== rows.length ||
    summary.passed !== rows.length - nonPassed.length ||
    JSON.stringify(summary.nonPassed) !== JSON.stringify(nonPassed)
  )
    throw new Error("summary mismatch");
  return Object.freeze({ manifest, rows, summary });
}

export function validateWorkerMessage(message, nonce, scenario) {
  if (
    exactKeys(message, ["type", "protocol"]) &&
    message.type === "boot" &&
    message.protocol === PROTOCOL
  )
    return Object.freeze({ kind: "boot" });
  if (
    exactKeys(message, ["type", "protocol", "nonce", "scenario", "evidence"]) &&
    message.type === "committed" &&
    message.protocol === PROTOCOL &&
    message.nonce === nonce &&
    message.scenario === scenario &&
    exactKeys(message.evidence, ["status", "helperClosed"]) &&
    message.evidence.status === "committed" &&
    message.evidence.helperClosed === true
  )
    return Object.freeze({ kind: "committed", evidence: message.evidence });
  if (
    exactKeys(message, [
      "type",
      "protocol",
      "nonce",
      "scenario",
      "ok",
      "evidence",
    ]) &&
    message.type === "result" &&
    message.protocol === PROTOCOL &&
    message.nonce === nonce &&
    message.scenario === scenario &&
    message.ok === true
  )
    return Object.freeze({
      kind: "result",
      evidence: sanitizeEvidence(message.evidence),
    });
  if (
    exactKeys(message, [
      "type",
      "protocol",
      "nonce",
      "scenario",
      "ok",
      "code",
    ]) &&
    message.type === "result" &&
    message.protocol === PROTOCOL &&
    message.nonce === nonce &&
    message.scenario === scenario &&
    message.ok === false &&
    typeof message.code === "string" &&
    /^[a-z0-9_]{1,64}$/u.test(message.code)
  )
    return Object.freeze({ kind: "failure", code: message.code });
  throw safeFailure("worker_protocol");
}

function safeFailure(code) {
  const error = new Error("Phase 3 workflow POC failed safely");
  Object.defineProperty(error, "pocCode", {
    value: code,
    enumerable: false,
  });
  return error;
}

function errorCode(error) {
  try {
    const descriptor =
      typeof error === "object" && error !== null
        ? Object.getOwnPropertyDescriptor(error, "pocCode")
        : undefined;
    return descriptor &&
      "value" in descriptor &&
      typeof descriptor.value === "string"
      ? descriptor.value
      : "operation_failed";
  } catch {
    return "operation_failed";
  }
}

function identity(path) {
  const value = lstatSync(path, { bigint: true });
  return {
    dev: value.dev,
    ino: value.ino,
    uid: value.uid,
    mode: value.mode,
    nlink: value.nlink,
    size: value.size,
    type: value.isDirectory() ? "directory" : value.isFile() ? "file" : "other",
  };
}

export function capturePinnedIdentity(path) {
  return Object.freeze(identity(path));
}

function fileSha256(path, expected) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const openedMetadata = {
      dev: opened.dev,
      ino: opened.ino,
      uid: opened.uid,
      mode: opened.mode,
      nlink: opened.nlink,
      size: opened.size,
      type: opened.isFile() ? "file" : "other",
    };
    if (expected && !sameIdentity(openedMetadata, expected))
      throw safeFailure("cleanup_unproved");
    const sha256 = createHash("sha256")
      .update(readFileSync(descriptor))
      .digest("hex");
    if (expected) assertPinned(path, expected);
    return sha256;
  } finally {
    closeSync(descriptor);
  }
}

function serializedIdentity(value) {
  return Object.freeze({
    dev: value.dev.toString(),
    ino: value.ino.toString(),
    uid: value.uid.toString(),
    mode: value.mode.toString(),
    nlink: value.nlink.toString(),
    size: value.size.toString(),
    type: value.type,
  });
}

function serializedFileProof(value) {
  return Object.freeze({
    ...serializedIdentity(value.metadata),
    sha256: value.sha256,
  });
}

function sameIdentity(left, right, includeNlink = true) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    (!includeNlink || left.nlink === right.nlink) &&
    (left.type !== "file" || left.size === right.size) &&
    left.type === right.type
  );
}

function assertPinned(path, expected, includeNlink = true) {
  let observed;
  try {
    observed = identity(path);
  } catch {
    throw safeFailure("topology_substituted");
  }
  if (!sameIdentity(observed, expected, includeNlink))
    throw safeFailure("topology_substituted");
  return observed;
}

export function assertPinnedIdentity(path, expected) {
  assertPinned(path, expected);
}

export class AppendOnlyTopologyRegistry {
  #ancestor;
  #root;
  #nonce;
  #entries = new Map();
  #sourcePins;
  #helperProofs;
  #sealed = false;

  constructor({ ancestor, root, nonce }) {
    this.#ancestor = Object.freeze({
      path: ancestor.path,
      metadata: Object.freeze({ ...ancestor.metadata }),
    });
    this.#root = Object.freeze({
      path: root.path,
      metadata: Object.freeze({ ...root.metadata }),
    });
    this.#nonce = Object.freeze({
      path: nonce.path,
      metadata: Object.freeze({ ...nonce.metadata }),
      value: nonce.value,
      sha256: nonce.sha256,
    });
    Object.freeze(this);
  }

  get rootPath() {
    return this.#root.path;
  }

  workerPins() {
    if (!this.#helperProofs) throw safeFailure("cleanup_unproved");
    const currentRoot = assertPinned(
      this.#root.path,
      this.#root.metadata,
      false,
    );
    return Object.freeze({
      ancestor: Object.freeze({
        path: this.#ancestor.path,
        ...serializedIdentity(this.#ancestor.metadata),
      }),
      root: serializedIdentity(currentRoot),
      nonce: Object.freeze({
        ...serializedIdentity(this.#nonce.metadata),
        sha256: this.#nonce.sha256,
      }),
      helpers: Object.freeze(
        Object.fromEntries(
          Object.entries(this.#helperProofs).map(([name, proof]) => [
            name,
            serializedFileProof(proof),
          ]),
        ),
      ),
    });
  }

  helperProofs() {
    if (!this.#helperProofs) throw safeFailure("cleanup_unproved");
    return this.#helperProofs;
  }

  registerHelpers(native) {
    if (this.#sealed || this.#helperProofs || !native?.sourcePins)
      throw safeFailure("cleanup_unproved");
    this.#sourcePins = native.sourcePins;
    this.#helperProofs = native.outputs;
    this.captureStage(true);
    for (const [name, proof] of Object.entries(this.#helperProofs)) {
      const entry = this.#entries.get(ARTIFACTS[name]);
      if (
        !entry ||
        !sameIdentity(entry.metadata, proof.metadata) ||
        entry.sha256 !== proof.sha256
      )
        throw safeFailure("cleanup_unproved");
    }
  }

  #verifyBase() {
    assertPinned(this.#ancestor.path, this.#ancestor.metadata);
    const currentRoot = assertPinned(
      this.#root.path,
      this.#root.metadata,
      false,
    );
    assertPinned(this.#nonce.path, this.#nonce.metadata);
    const bytes = readFileSync(this.#nonce.path);
    if (
      !bytes.equals(this.#nonce.value) ||
      createHash("sha256").update(bytes).digest("hex") !== this.#nonce.sha256
    )
      throw safeFailure("cleanup_unproved");
    return currentRoot;
  }

  #verifySources() {
    if (!this.#sourcePins || !this.#helperProofs)
      throw safeFailure("cleanup_unproved");
    for (const proof of Object.values(this.#sourcePins)) {
      const observed = pinnedSource(proof.path);
      if (
        observed.sha256 !== proof.sha256 ||
        !sameIdentity(observed.metadata, proof.metadata)
      )
        throw safeFailure("cleanup_unproved");
    }
  }

  captureStage(allowNew) {
    if (this.#sealed || typeof allowNew !== "boolean")
      throw safeFailure("cleanup_unproved");
    const currentRoot = this.#verifyBase();
    const observed = new Set();
    let directDirectories = 0n;
    const walk = (directory) => {
      for (const name of readdirSync(directory).sort()) {
        if (
          name === "." ||
          name === ".." ||
          name.includes("/") ||
          name.includes("\\")
        )
          throw safeFailure("cleanup_unproved");
        const path = join(directory, name);
        const metadata = identity(path);
        const rel = relative(this.#root.path, path).replaceAll("\\", "/");
        if (
          metadata.type === "other" ||
          metadata.uid !== BigInt(process.getuid()) ||
          (metadata.type === "file" && metadata.nlink !== 1n) ||
          !allowedTopology(rel, metadata.type)
        )
          throw safeFailure("cleanup_unproved");
        observed.add(rel);
        if (metadata.type === "directory" && dirname(path) === this.#root.path)
          directDirectories += 1n;
        const existing = this.#entries.get(rel);
        const sha256 =
          metadata.type === "file" ? fileSha256(path, metadata) : undefined;
        if (existing) {
          if (
            !sameIdentity(metadata, existing.metadata) ||
            existing.sha256 !== sha256
          )
            throw safeFailure("cleanup_unproved");
        } else {
          if (!allowNew) throw safeFailure("cleanup_unproved");
          this.#entries.set(
            rel,
            Object.freeze({
              path,
              metadata: Object.freeze({ ...metadata }),
              sha256,
            }),
          );
        }
        if (metadata.type === "directory") walk(path);
      }
    };
    walk(this.#root.path);
    if (
      this.#entries.size !== observed.size ||
      [...this.#entries.keys()].some((name) => !observed.has(name))
    )
      throw safeFailure("cleanup_unproved");
    const expectedRootNlink =
      this.#root.metadata.nlink > 1n
        ? this.#root.metadata.nlink + directDirectories
        : this.#root.metadata.nlink;
    if (currentRoot.nlink !== expectedRootNlink)
      throw safeFailure("cleanup_unproved");
    return currentRoot;
  }

  seal() {
    const currentRoot = this.captureStage(false);
    this.#verifySources();
    assertRequiredTopologyMembership(this.#entries);
    this.#sealed = true;
    return Object.freeze({
      ancestor: this.#ancestor,
      root: Object.freeze({
        path: this.#root.path,
        metadata: Object.freeze({ ...currentRoot }),
        initialMetadata: this.#root.metadata,
      }),
      nonce: this.#nonce,
      entries: Object.freeze([...this.#entries.values()]),
      helperProofs: this.#helperProofs,
      sourcePins: this.#sourcePins,
    });
  }
}

function assertRequiredTopologyMembership(entries) {
  const names = new Set(entries.keys());
  const required = new Set([
    ARTIFACTS.nonce,
    "native",
    ARTIFACTS.list,
    ARTIFACTS.read,
    ARTIFACTS.replace,
  ]);
  for (const scenario of ["success", "rollback", "restart"]) {
    for (const tail of [
      "",
      "repo",
      "repo/automations",
      "repo/secrets.yaml",
      "repo/automations/poc.yaml",
      "proposal-store",
      "proposal-store/proposals",
      "proposal-store/journals",
      "proposal-store/quarantine",
      "journal",
      "checkpoints",
      "approval",
      "approval/header.json",
      "key-state",
      "key-state/approval.key",
    ])
      required.add(tail === "" ? scenario : `${scenario}/${tail}`);
  }
  required.add("restart/control.json");
  if ([...required].some((name) => !names.has(name)))
    throw safeFailure("cleanup_unproved");
  for (const scenario of ["success", "rollback", "restart"]) {
    const prefix = `${scenario}/`;
    const scenarioNames = [...names].filter((name) => name.startsWith(prefix));
    if (
      !scenarioNames.some((name) =>
        /^.+\/proposal-store\/proposals\/[0-9a-f-]{36}\.json$/u.test(name),
      ) ||
      !scenarioNames.some((name) =>
        /^.+\/journal\/[0-9a-f-]{36}\.[0-9]{12}\.entry$/u.test(name),
      ) ||
      !scenarioNames.some((name) =>
        /^.+\/checkpoints\/[0-9a-f-]{36}$/u.test(name),
      ) ||
      !scenarioNames.some((name) =>
        /^.+\/approval\/slot-[0-9]{3}\/used\.json$/u.test(name),
      )
    )
      throw safeFailure("cleanup_unproved");
  }
}

function canonicalTemporaryAncestor() {
  for (const candidate of ["/tmp", "/var/tmp"]) {
    try {
      const metadata = identity(candidate);
      if (
        metadata.type === "directory" &&
        metadata.uid === 0n &&
        (metadata.mode & 0o7777n) === 0o1777n &&
        metadata.nlink >= 1n &&
        metadata.nlink <= 1_048_576n &&
        realpathSync(candidate) === candidate
      )
        return Object.freeze({ path: candidate, metadata });
    } catch {
      // Try the other frozen temporary ancestor.
    }
  }
  throw safeFailure("temporary_ancestor_unavailable");
}

function assertEnvironment() {
  if (!process.getuid || !process.geteuid)
    throw safeFailure("uid_api_unavailable");
  const validated = validateEnvironmentBoundary({
    platform: process.platform,
    uid: process.getuid(),
    euid: process.geteuid(),
    nodeVersion: process.versions.node,
    environment: process.env,
  });
  const compiler = command(["cc", "--version"], 10_000);
  const text = `${compiler.stdout}\n${compiler.stderr}`;
  const family = /clang/iu.test(text)
    ? "clang"
    : /gcc|GNU Compiler|Free Software Foundation/iu.test(text)
      ? "gcc"
      : undefined;
  if (!family) throw safeFailure("compiler_family_rejected");
  command(["readelf", "--version"], 10_000);
  parseMountInfo(readFileSync("/proc/self/mountinfo", "utf8"));
  return Object.freeze({ ...validated, compilerFamily: family });
}

function command([file, ...args], timeout) {
  const result = spawnSync(file, args, {
    cwd: "/",
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
    },
    encoding: "utf8",
    shell: false,
    timeout,
    maxBuffer: 1_048_576,
  });
  if (result.status !== 0 || result.signal !== null || result.error)
    throw safeFailure("native_command_failed");
  return result;
}

function setupWorkspace(ancestor) {
  assertPinned(ancestor.path, ancestor.metadata);
  const root = mkdtempSync(join(ancestor.path, "ha-phase3-poc-"));
  chmodSync(root, 0o700);
  if (
    dirname(root) !== ancestor.path ||
    realpathSync(root) !== root ||
    basename(root).length > 128
  )
    throw safeFailure("workspace_canonicalization");
  assertWorkspacePathAllowed(root);
  const rootMetadata = identity(root);
  if (
    rootMetadata.type !== "directory" ||
    rootMetadata.uid !== BigInt(process.getuid()) ||
    (rootMetadata.mode & 0o7777n) !== 0o700n ||
    rootMetadata.nlink < 2n
  )
    throw safeFailure("workspace_metadata");
  const nonce = randomBytes(32).toString("hex");
  const noncePath = join(root, ARTIFACTS.nonce);
  const descriptor = openSync(
    noncePath,
    constants.O_CREAT |
      constants.O_EXCL |
      constants.O_WRONLY |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const written = Buffer.from(`${nonce}\n`, "ascii");
    const { writeSync, fsyncSync } = awaitFsHelpers();
    if (writeSync(descriptor, written, 0, written.length, 0) !== written.length)
      throw safeFailure("nonce_write");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const nonceMetadata = identity(noncePath);
  if (
    nonceMetadata.type !== "file" ||
    nonceMetadata.nlink !== 1n ||
    nonceMetadata.uid !== BigInt(process.getuid()) ||
    (nonceMetadata.mode & 0o7777n) !== 0o600n
  )
    throw safeFailure("nonce_metadata");
  assertNoMountAtOrBelow(root, readFileSync("/proc/self/mountinfo", "utf8"));
  const ancestorAfterCreate = identity(ancestor.path);
  if (
    ancestorAfterCreate.dev !== ancestor.metadata.dev ||
    ancestorAfterCreate.ino !== ancestor.metadata.ino ||
    ancestorAfterCreate.uid !== ancestor.metadata.uid ||
    ancestorAfterCreate.mode !== ancestor.metadata.mode ||
    ancestorAfterCreate.type !== "directory" ||
    ancestorAfterCreate.nlink !==
      (ancestor.metadata.nlink > 1n
        ? ancestor.metadata.nlink + 1n
        : ancestor.metadata.nlink)
  )
    throw safeFailure("temporary_ancestor_changed");
  const nonceValue = Buffer.from(`${nonce}\n`, "ascii");
  const registry = new AppendOnlyTopologyRegistry({
    ancestor: { path: ancestor.path, metadata: ancestorAfterCreate },
    root: { path: root, metadata: rootMetadata },
    nonce: {
      path: noncePath,
      metadata: nonceMetadata,
      value: nonceValue,
      sha256: createHash("sha256").update(nonceValue).digest("hex"),
    },
  });
  registry.captureStage(true);
  return { root, nonce, nonceMetadata, rootMetadata, registry };
}

function awaitFsHelpers() {
  // Kept as a helper so tests can verify nonce writes use a pinned descriptor.
  return { writeSync: globalWriteSync, fsyncSync: globalFsyncSync };
}

import {
  fsyncSync as globalFsyncSync,
  writeSync as globalWriteSync,
} from "node:fs";

function pinnedSource(path) {
  const before = identity(path);
  if (
    before.type !== "file" ||
    before.nlink !== 1n ||
    before.uid !== BigInt(process.getuid())
  )
    throw safeFailure("source_metadata");
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const openedIdentity = {
      dev: opened.dev,
      ino: opened.ino,
      uid: opened.uid,
      mode: opened.mode,
      nlink: opened.nlink,
      size: opened.size,
      type: opened.isFile() ? "file" : "other",
    };
    if (!sameIdentity(before, openedIdentity))
      throw safeFailure("source_substituted");
    const bytes = readFileSync(descriptor);
    return Object.freeze({
      metadata: before,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  } finally {
    closeSync(descriptor);
  }
}

function compileHelpers(workspace, compilerFamily) {
  const nativeRoot = join(workspace, "native");
  const mkdir = spawnSync("mkdir", ["-m", "700", nativeRoot], {
    cwd: "/",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    shell: false,
  });
  if (mkdir.status !== 0) throw safeFailure("native_directory_create");
  const pins = Object.fromEntries(
    Object.entries(SOURCE_PATHS).map(([name, path]) => [
      name,
      Object.freeze({ path, ...pinnedSource(path) }),
    ]),
  );
  const flags = [
    "-std=c11",
    "-O2",
    "-fPIE",
    "-fstack-protector-strong",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wformat=2",
    "-Wformat-security",
    "-pie",
    "-Wl,-z,relro,-z,now",
    "-Wl,-z,noexecstack",
  ];
  const outputs = {};
  for (const name of ["list", "read", "replace"]) {
    const target = join(workspace, ARTIFACTS[name]);
    const link = name === "replace" ? ["-l:libcrypto.so.3"] : [];
    command(
      ["cc", ...flags, SOURCE_PATHS[name], ...link, "-o", target],
      30_000,
    );
    const after = pinnedSource(SOURCE_PATHS[name]);
    if (
      after.sha256 !== pins[name].sha256 ||
      !sameIdentity(after.metadata, pins[name].metadata)
    )
      throw safeFailure("source_changed_during_compile");
    chmodSync(target, 0o555);
    const metadata = identity(target);
    if (
      metadata.type !== "file" ||
      metadata.nlink !== 1n ||
      metadata.uid !== BigInt(process.getuid()) ||
      (metadata.mode & 0o7777n) !== 0o555n ||
      (metadata.mode & 0o222n) !== 0n ||
      (metadata.mode & 0o111n) !== 0o111n
    )
      throw safeFailure("binary_metadata");
    outputs[name] = Object.freeze({
      metadata,
      sha256: createHash("sha256").update(readFileSync(target)).digest("hex"),
    });
    const programHeaders = command(
      ["readelf", "-W", "-l", target],
      10_000,
    ).stdout;
    const stackLines = programHeaders
      .split("\n")
      .filter((line) => line.trimStart().startsWith("GNU_STACK"));
    if (stackLines.length !== 1) throw safeFailure("gnu_stack_missing");
    const stackFields = stackLines[0].trim().split(/\s+/u);
    const stackFlags = stackFields.at(-2);
    if (
      typeof stackFlags !== "string" ||
      !/^[RW]+$/u.test(stackFlags) ||
      stackFlags.includes("E")
    )
      throw safeFailure("executable_stack");
  }
  const dynamic = command(
    ["readelf", "-d", join(workspace, ARTIFACTS.replace)],
    10_000,
  ).stdout;
  const needed = [...dynamic.matchAll(/\(NEEDED\).*\[([^\]]+)\]/gu)].map(
    (match) => match[1],
  );
  if (
    needed.filter((name) => name === "libcrypto.so.3").length !== 1 ||
    needed.some(
      (name) => name?.startsWith("libcrypto") && name !== "libcrypto.so.3",
    )
  )
    throw safeFailure("libcrypto_dependency");
  return Object.freeze({
    compilerFamily,
    sourceSha256: Object.freeze(
      Object.fromEntries(
        Object.entries(pins).map(([name, pin]) => [name, pin.sha256]),
      ),
    ),
    binarySha256: Object.freeze(
      Object.fromEntries(
        Object.entries(outputs).map(([name, output]) => [name, output.sha256]),
      ),
    ),
    cryptoNeeded: "libcrypto.so.3",
    nonExecutableStack: true,
    strictMetadata: true,
    outputs,
    sourcePins: Object.freeze(pins),
  });
}

class WorkerClient {
  constructor(workspace, nonce, scenario, pins, expectedKill = false) {
    this.workspace = workspace;
    this.nonce = nonce;
    this.scenario = scenario;
    this.pins = pins;
    this.expectedKill = expectedKill;
    this.messages = 0;
    this.ipcBytes = 0;
    this.stdoutBytes = 0;
    this.stderrBytes = 0;
    this.committed = false;
    this.settled = false;
    this.ownershipAuthorizationFailed = false;
    this.child = spawn(process.execPath, [WORKER_PATH], {
      cwd: "/",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
      },
      detached: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    });
    this.pid = this.child.pid;
    this.live = true;
    try {
      this.ownership = captureProcessOwnership(this.pid);
    } catch {
      this.ownership = undefined;
    }
    this.closed = new Promise((resolvePromise) => {
      this.child.once("close", (code, signal) => {
        this.live = false;
        resolvePromise(Object.freeze({ code, signal }));
      });
    });
    this.completion = new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        reject(safeFailure("worker_timeout"));
      }, WORKER_TIMEOUT_MS);
      const reject = (error) => {
        if (this.settled) return;
        this.settled = true;
        clearTimeout(timer);
        try {
          this.terminate();
          rejectPromise(error);
        } catch {
          rejectPromise(safeFailure("cleanup_unproved"));
        }
      };
      this.rejectCompletion = reject;
      this.child.stdout.on("data", (chunk) => {
        this.stdoutBytes += chunk.byteLength;
        if (this.stdoutBytes > MAX_STDIO_BYTES)
          reject(safeFailure("worker_stdio"));
      });
      this.child.stderr.on("data", (chunk) => {
        this.stderrBytes += chunk.byteLength;
        if (this.stderrBytes > MAX_STDIO_BYTES)
          reject(safeFailure("worker_stdio"));
      });
      this.child.on("error", () => reject(safeFailure("worker_spawn")));
      this.child.on("message", (message) => {
        try {
          this.messages += 1;
          this.ipcBytes += Buffer.byteLength(JSON.stringify(message), "utf8");
          if (this.messages > MAX_IPC_MESSAGES || this.ipcBytes > MAX_IPC_BYTES)
            throw safeFailure("worker_ipc_boundary");
          const parsed = validateWorkerMessage(message, nonce, scenario);
          if (parsed.kind === "boot") {
            const authorized = authorizeWorkerRun(this, {
              type: "run",
              protocol: PROTOCOL,
              nonce,
              workspace,
              scenario,
              deadlineAt: Date.now() + WORKER_DEADLINE_MS,
              artifacts: ARTIFACTS,
              pins,
            });
            if (!authorized) this.ownershipAuthorizationFailed = true;
          } else if (parsed.kind === "committed") {
            this.committed = true;
          } else if (parsed.kind === "failure") {
            reject(safeFailure(parsed.code));
          } else if (parsed.kind === "result") {
            this.result = parsed.evidence;
          }
        } catch (error) {
          reject(error);
        }
      });
      this.child.on("close", (code, signal) => {
        if (this.settled) return;
        this.settled = true;
        clearTimeout(timer);
        if (
          this.stdoutBytes !== 0 ||
          this.stderrBytes !== 0 ||
          (expectedKill
            ? signal !== "SIGKILL" || code !== null || !this.committed
            : signal !== null || code !== 0 || this.result === undefined)
        ) {
          rejectPromise(safeFailure("worker_exit"));
          return;
        }
        resolvePromise(
          expectedKill
            ? Object.freeze({
                sigkillObserved: true,
                committedCheckpoint: true,
                helperClosed: true,
              })
            : this.result,
        );
      });
    });
  }

  send(message) {
    if (Buffer.byteLength(JSON.stringify(message), "utf8") > MAX_IPC_BYTES)
      throw safeFailure("worker_ipc_boundary");
    this.child.send(message, (error) => {
      if (error) this.rejectCompletion(safeFailure("worker_ipc"));
    });
  }

  terminate() {
    return signalLiveOwnedProcessGroup(this);
  }
}

export function authorizeWorkerRun(client, message) {
  if (
    client?.live !== true ||
    !client.ownership ||
    typeof client.send !== "function"
  )
    return false;
  try {
    if (
      client.ownership.pid !== client.pid ||
      client.ownership.pgrp !== client.pid ||
      client.ownership.session !== client.pid ||
      !ownershipMatchesLiveLeader(client.ownership)
    )
      return false;
  } catch {
    return false;
  }
  if (client.live !== true) return false;
  client.send(message);
  return true;
}

async function runWorker(
  workspace,
  nonce,
  scenario,
  expectedKill = false,
  captureTopology = true,
) {
  const registry = workspace.registry;
  const client = new WorkerClient(
    workspace.root,
    nonce,
    scenario,
    registry.workerPins(),
    expectedKill,
  );
  let result;
  let failure;
  try {
    result = await client.completion;
  } catch (error) {
    failure = error;
  }
  try {
    await settleWorkerProcess(client, registry.helperProofs());
  } catch {
    throw safeFailure("cleanup_unproved");
  }
  if (failure) throw failure;
  if (captureTopology) registry.captureStage(true);
  return result;
}

export async function settleWorkerProcess(client, helperProofs) {
  if (
    !client ||
    !Number.isSafeInteger(client.pid) ||
    client.pid <= 0 ||
    !client.closed ||
    typeof client.terminate !== "function"
  )
    throw safeFailure("cleanup_unproved");
  if (client.live === true) client.terminate();
  const closed = await Promise.race([
    client.closed,
    delay(CHILD_CLOSE_TIMEOUT_MS).then(() => undefined),
  ]);
  if (
    !closed ||
    client.live !== false ||
    !client.ownership ||
    client.ownershipAuthorizationFailed === true
  )
    throw safeFailure("cleanup_unproved");
  const deadlineAt = performance.now() + PROCESS_PROOF_DEADLINE_MS;
  await proveCapturedProcessGroupAbsent(client.ownership, { deadlineAt });
  await proveHelpersAbsent(helperProofs, { deadlineAt });
}

function readProcessStat(pid) {
  const value = readFileSync(`/proc/${pid}/stat`, "utf8");
  const separator = value.lastIndexOf(") ");
  if (separator < 3) throw safeFailure("cleanup_unproved");
  const fields = value
    .slice(separator + 2)
    .trim()
    .split(/\s+/u);
  const pgrp = Number(fields[2]);
  const session = Number(fields[3]);
  const startTime = fields[19];
  if (
    !Number.isSafeInteger(pgrp) ||
    pgrp <= 0 ||
    !Number.isSafeInteger(session) ||
    session <= 0 ||
    !/^[0-9]+$/u.test(startTime ?? "")
  )
    throw safeFailure("cleanup_unproved");
  return Object.freeze({ pgrp, session, startTime });
}

function openedExecutableMetadata(pid) {
  const descriptor = openSync(`/proc/${pid}/exe`, constants.O_RDONLY);
  try {
    const value = fstatSync(descriptor, { bigint: true });
    if (!value.isFile()) throw safeFailure("cleanup_unproved");
    return Object.freeze({
      dev: value.dev,
      ino: value.ino,
      size: value.size,
      type: "file",
    });
  } finally {
    closeSync(descriptor);
  }
}

export function captureProcessOwnership(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0)
    throw safeFailure("cleanup_unproved");
  const processStat = readProcessStat(pid);
  if (processStat.pgrp !== pid || processStat.session !== pid)
    throw safeFailure("cleanup_unproved");
  return Object.freeze({
    pid,
    pgrp: processStat.pgrp,
    session: processStat.session,
    startTime: processStat.startTime,
    executable: openedExecutableMetadata(pid),
  });
}

function sameExecutableMetadata(actual, expected) {
  return (
    actual?.type === "file" &&
    expected?.type === "file" &&
    actual.dev === expected.dev &&
    actual.ino === expected.ino &&
    actual.size === expected.size
  );
}

function ownershipMatchesLiveLeader(ownership) {
  const processStat = readProcessStat(ownership.pid);
  return (
    processStat.pgrp === ownership.pgrp &&
    processStat.session === ownership.session &&
    processStat.startTime === ownership.startTime &&
    sameExecutableMetadata(
      openedExecutableMetadata(ownership.pid),
      ownership.executable,
    )
  );
}

export function signalLiveOwnedProcessGroup(
  client,
  signalProcess = process.kill,
) {
  if (client?.live !== true) return false;
  const ownership = client.ownership;
  if (
    !ownership ||
    ownership.pid !== client.pid ||
    ownership.pgrp !== client.pid ||
    ownership.session !== client.pid ||
    !ownershipMatchesLiveLeader(ownership)
  )
    throw safeFailure("cleanup_unproved");
  if (client.live !== true) return false;
  try {
    signalProcess(-ownership.pgrp, "SIGKILL");
  } catch {
    throw safeFailure("cleanup_unproved");
  }
  return true;
}

function validatedHelperProofs(helperProofs) {
  if (
    helperProofs === null ||
    typeof helperProofs !== "object" ||
    !exactKeys(helperProofs, ["list", "read", "replace"])
  )
    throw safeFailure("cleanup_unproved");
  for (const proof of Object.values(helperProofs))
    if (
      !proof ||
      typeof proof.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(proof.sha256) ||
      proof.metadata?.type !== "file" ||
      proof.metadata.nlink !== 1n ||
      typeof proof.metadata.dev !== "bigint" ||
      typeof proof.metadata.ino !== "bigint" ||
      typeof proof.metadata.size !== "bigint" ||
      proof.metadata.size < 1n
    )
      throw safeFailure("cleanup_unproved");
  return helperProofs;
}

function scanBounds(options = {}) {
  const values = {
    maxPidEntries: options.maxPidEntries ?? MAX_PROC_PID_ENTRIES,
    maxExecutableBytes:
      options.maxExecutableBytes ?? MAX_HELPER_EXECUTABLE_BYTES,
    maxScanMs: options.maxScanMs ?? MAX_PROC_SCAN_MS,
    deadlineAt:
      options.deadlineAt ?? performance.now() + PROCESS_PROOF_DEADLINE_MS,
  };
  if (
    !Number.isSafeInteger(values.maxPidEntries) ||
    values.maxPidEntries < 0 ||
    !Number.isSafeInteger(values.maxExecutableBytes) ||
    values.maxExecutableBytes < 0 ||
    !Number.isFinite(values.maxScanMs) ||
    values.maxScanMs < 0 ||
    !Number.isFinite(values.deadlineAt)
  )
    throw safeFailure("cleanup_unproved");
  return Object.freeze(values);
}

function assertScanWithinBounds(startedAt, bounds) {
  const now = performance.now();
  if (
    bounds.maxScanMs === 0 ||
    now - startedAt > bounds.maxScanMs ||
    now > bounds.deadlineAt
  )
    throw safeFailure("cleanup_unproved");
}

function openedMatchingExecutableProof(pid, proofs, bounds) {
  const descriptor = openSync(`/proc/${pid}/exe`, constants.O_RDONLY);
  try {
    const value = fstatSync(descriptor, { bigint: true });
    if (!value.isFile()) throw safeFailure("cleanup_unproved");
    const potential = proofs.find(
      (expected) =>
        value.dev === expected.metadata.dev &&
        value.ino === expected.metadata.ino &&
        value.size === expected.metadata.size,
    );
    if (!potential) return false;
    if (
      value.size > BigInt(bounds.maxExecutableBytes) ||
      potential.metadata.size > BigInt(bounds.maxExecutableBytes)
    )
      throw safeFailure("cleanup_unproved");
    const bytes = readFileSync(descriptor);
    if (bytes.byteLength !== Number(value.size))
      throw safeFailure("cleanup_unproved");
    return (
      createHash("sha256").update(bytes).digest("hex") === potential.sha256
    );
  } finally {
    closeSync(descriptor);
  }
}

function numericProcEntries(bounds) {
  const entries = readdirSync("/proc").filter((name) =>
    /^[1-9][0-9]*$/u.test(name),
  );
  if (entries.length > bounds.maxPidEntries)
    throw safeFailure("cleanup_unproved");
  return entries;
}

export function procHelperPids(helperProofs, options = {}) {
  const proofs = Object.values(validatedHelperProofs(helperProofs));
  const bounds = scanBounds(options);
  const startedAt = performance.now();
  const matches = [];
  for (const name of numericProcEntries(bounds)) {
    assertScanWithinBounds(startedAt, bounds);
    try {
      const pid = Number(name);
      const status = readFileSync(`/proc/${name}/status`, "utf8");
      if (Buffer.byteLength(status, "utf8") > 16_384)
        throw safeFailure("cleanup_unproved");
      const uidLine = status
        .split("\n")
        .find((line) => line.startsWith("Uid:"));
      const uid = Number(uidLine?.trim().split(/\s+/u)[1]);
      if (uid !== process.getuid()) continue;
      if (openedMatchingExecutableProof(pid, proofs, bounds)) matches.push(pid);
      assertScanWithinBounds(startedAt, bounds);
    } catch {
      try {
        lstatSync(`/proc/${name}`);
      } catch {
        continue;
      }
      throw safeFailure("cleanup_unproved");
    }
  }
  return matches;
}

function processGroupPresent(ownership, options = {}) {
  const bounds = scanBounds(options);
  const startedAt = performance.now();
  for (const name of numericProcEntries(bounds)) {
    assertScanWithinBounds(startedAt, bounds);
    try {
      const pid = Number(name);
      const processStat = readProcessStat(pid);
      if (
        processStat.pgrp === ownership.pgrp ||
        processStat.session === ownership.session
      )
        return true;
      if (
        pid === ownership.pid &&
        processStat.startTime === ownership.startTime
      ) {
        if (
          !sameExecutableMetadata(
            openedExecutableMetadata(pid),
            ownership.executable,
          )
        )
          throw safeFailure("cleanup_unproved");
        return true;
      }
    } catch {
      try {
        lstatSync(`/proc/${name}`);
      } catch {
        continue;
      }
      throw safeFailure("cleanup_unproved");
    }
  }
  return false;
}

async function proveCapturedProcessGroupAbsent(ownership, options = {}) {
  const bounds = scanBounds(options);
  while (performance.now() <= bounds.deadlineAt) {
    if (!processGroupPresent(ownership, bounds)) return;
    await delay(HELPER_SCAN_POLL_MS);
  }
  throw safeFailure("cleanup_unproved");
}

export async function proveHelpersAbsent(helperProofs, options = {}) {
  const proofs = validatedHelperProofs(helperProofs);
  const bounds = scanBounds(options);
  while (performance.now() <= bounds.deadlineAt) {
    if (procHelperPids(proofs, bounds).length === 0) return;
    await delay(HELPER_SCAN_POLL_MS);
  }
  throw safeFailure("cleanup_unproved");
}

export function allowedTopology(relativePath, type) {
  const parts = relativePath.split("/");
  if (relativePath === ARTIFACTS.nonce) return type === "file";
  if (relativePath === "native") return type === "directory";
  if (
    parts[0] === "native" &&
    parts.length === 2 &&
    ["openat2-list", "openat2-read", "openat2-replace"].includes(parts[1])
  )
    return type === "file";
  if (!["success", "rollback", "restart"].includes(parts[0])) return false;
  if (parts.length === 1) return type === "directory";
  const fixedDirectories = new Set([
    "repo",
    "repo/automations",
    "proposal-store",
    "proposal-store/proposals",
    "proposal-store/journals",
    "proposal-store/quarantine",
    "journal",
    "checkpoints",
    "approval",
    "key-state",
  ]);
  const tail = parts.slice(1).join("/");
  if (fixedDirectories.has(tail)) return type === "directory";
  if (
    (tail === "repo/secrets.yaml" ||
      tail === "repo/automations/poc.yaml" ||
      (parts[0] === "restart" && tail === "control.json") ||
      tail === "approval/header.json" ||
      tail === "key-state/approval.key") &&
    type === "file"
  )
    return true;
  if (
    /^proposal-store\/proposals\/[0-9a-f-]{36}\.json$/u.test(tail) &&
    type === "file"
  )
    return true;
  if (
    /^journal\/[0-9a-f-]{36}\.[0-9]{12}\.entry$/u.test(tail) &&
    type === "file"
  )
    return true;
  if (/^checkpoints\/[0-9a-f-]{36}$/u.test(tail) && type === "file")
    return true;
  if (/^approval\/slot-[0-9]{3}$/u.test(tail) && type === "directory")
    return true;
  if (
    /^approval\/slot-[0-9]{3}\/(?:grant|used)\.json$/u.test(tail) &&
    type === "file"
  )
    return true;
  return false;
}

export function cleanupTopology(registry) {
  cleanupFailureClassification = "seal";
  const snapshot = registry.seal();
  cleanupFailureClassification = "mount";
  assertNoMountAtOrBelow(
    snapshot.root.path,
    readFileSync("/proc/self/mountinfo", "utf8"),
  );
  const files = snapshot.entries
    .filter((entry) => entry.metadata.type === "file")
    .sort((left, right) => right.path.length - left.path.length);
  cleanupFailureClassification = "files";
  for (const entry of files) {
    assertPinned(snapshot.ancestor.path, snapshot.ancestor.metadata);
    assertPinned(snapshot.root.path, snapshot.root.metadata);
    assertPinned(entry.path, entry.metadata);
    unlinkSync(entry.path);
  }
  const directories = snapshot.entries
    .filter((entry) => entry.metadata.type === "directory")
    .sort(
      (left, right) =>
        right.path.split(/[\\/]/u).length - left.path.split(/[\\/]/u).length,
    );
  const directoryExpected = new Map(
    directories.map((entry) => [entry.path, { ...entry.metadata }]),
  );
  directoryExpected.set(snapshot.root.path, { ...snapshot.root.metadata });
  cleanupFailureClassification = "directories";
  for (const entry of directories) {
    const expected = directoryExpected.get(entry.path);
    const parentPath = dirname(entry.path);
    const parentExpected = directoryExpected.get(parentPath);
    if (!expected || !parentExpected) throw safeFailure("cleanup_unproved");
    assertPinned(snapshot.ancestor.path, snapshot.ancestor.metadata);
    assertPinned(entry.path, expected);
    assertPinned(parentPath, parentExpected);
    rmdirSync(entry.path);
    parentExpected.nlink =
      parentExpected.nlink > 1n ? parentExpected.nlink - 1n : 1n;
    assertPinned(parentPath, parentExpected);
  }
  cleanupFailureClassification = "root";
  assertPinned(snapshot.root.path, directoryExpected.get(snapshot.root.path));
  const ancestorNow = identity(snapshot.ancestor.path);
  rmdirSync(snapshot.root.path);
  const ancestorAfter = identity(snapshot.ancestor.path);
  if (
    ancestorAfter.dev !== ancestorNow.dev ||
    ancestorAfter.ino !== ancestorNow.ino ||
    ancestorAfter.uid !== ancestorNow.uid ||
    ancestorAfter.mode !== ancestorNow.mode ||
    ancestorAfter.type !== "directory" ||
    ancestorAfter.nlink !==
      (ancestorNow.nlink > 1n ? ancestorNow.nlink - 1n : 1n)
  )
    throw safeFailure("cleanup_unproved");
  cleanupFailureClassification = "complete";
  return Object.freeze({
    topologySealed: true,
    regularFilesUnlinked: files.length,
    directoriesRemoved: directories.length + 1,
    recursiveRemoval: false,
    mountpointsBelowWorkspace: 0,
  });
}

function emit(record) {
  const line = `${JSON.stringify(record)}\n`;
  if (Buffer.byteLength(line, "utf8") > MAX_ROW_BYTES)
    throw safeFailure("evidence_oversized");
  process.stdout.write(line);
}

function row(id, status, evidence) {
  return Object.freeze({
    type: "row",
    id,
    status,
    evidence: sanitizeEvidence(evidence),
  });
}

function skipped(id, dependency) {
  return row(id, "SKIPPED", { dependency });
}

function summary(rows) {
  const nonPassed = rows
    .filter((item) => item.status !== "PASSED")
    .map((item) => item.id);
  return Object.freeze({
    type: "summary",
    status: nonPassed.length === 0 ? "PASSED" : "FAILED",
    required: PHASE3_WORKFLOW_POC_ROWS.length,
    executed: rows.length,
    passed: rows.length - nonPassed.length,
    nonPassed,
  });
}

async function main() {
  const publicArgs = process.argv.slice(2);
  const acknowledged =
    (publicArgs.length === 1 && publicArgs[0] === PHASE3_WORKFLOW_POC_ACK) ||
    (publicArgs.length === 2 &&
      publicArgs[0] === "--" &&
      publicArgs[1] === PHASE3_WORKFLOW_POC_ACK);
  if (!acknowledged) {
    process.stderr.write(
      "exact disposable Phase 3 POC acknowledgement required\n",
    );
    process.exitCode = 64;
    return;
  }

  emit(MANIFEST);
  const rows = [];
  let environment;
  let ancestor;
  let workspace;
  let native;
  let dependency;
  try {
    try {
      environment = assertEnvironment();
      ancestor = canonicalTemporaryAncestor();
      rows.push(row(PHASE3_WORKFLOW_POC_ROWS[0], "PASSED", environment));
    } catch (error) {
      dependency = errorCode(error);
      rows.push(
        row(PHASE3_WORKFLOW_POC_ROWS[0], "BLOCKED", { code: dependency }),
      );
    }

    if (!dependency) {
      try {
        workspace = setupWorkspace(ancestor);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[1], "PASSED", {
            canonicalTemporaryAncestor: true,
            privateMode: true,
            ownerMatched: true,
            noncePinned: true,
            deniedRootsDisjoint: true,
            mountpointsBelowWorkspace: 0,
          }),
        );
      } catch (error) {
        dependency = errorCode(error);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[1], "FAILED", { code: dependency }),
        );
      }
    } else rows.push(skipped(PHASE3_WORKFLOW_POC_ROWS[1], dependency));

    if (!dependency) {
      try {
        native = compileHelpers(workspace.root, environment.compilerFamily);
        workspace.registry.registerHelpers(native);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[2], "PASSED", {
            compilerFamily: native.compilerFamily,
            sourceSha256: native.sourceSha256,
            binarySha256: native.binarySha256,
            cryptoNeeded: native.cryptoNeeded,
            nonExecutableStack: native.nonExecutableStack,
            strictMetadata: native.strictMetadata,
          }),
        );
      } catch (error) {
        dependency = errorCode(error);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[2], "FAILED", { code: dependency }),
        );
      }
    } else rows.push(skipped(PHASE3_WORKFLOW_POC_ROWS[2], dependency));

    for (const [index, scenario] of [
      "success",
      "rollback",
      "restart-prepare",
    ].entries()) {
      const rowIndex = index + 3;
      if (dependency) {
        rows.push(skipped(PHASE3_WORKFLOW_POC_ROWS[rowIndex], dependency));
        continue;
      }
      try {
        if (scenario === "restart-prepare") {
          const prepared = await runWorker(
            workspace,
            workspace.nonce,
            scenario,
            false,
            false,
          );
          if (
            prepared.headerAuthenticated !== true ||
            prepared.grantIssued !== true
          )
            throw safeFailure("restart_prepare_evidence");
          const killed = await runWorker(
            workspace,
            workspace.nonce,
            "restart-apply",
            true,
            false,
          );
          rows.push(
            row(PHASE3_WORKFLOW_POC_ROWS[rowIndex], "PASSED", {
              initialAuthorityClosed: true,
              freshApplyWorker: true,
              synchronizedKey: true,
              authenticatedHeader: true,
              durableIntentPrepared: true,
              candidateDigestRecorded: true,
              sigkillObserved: killed.sigkillObserved,
              helperClosedBeforeSigkill: killed.helperClosed,
              evidenceClass: "process_death_only",
            }),
          );
        } else {
          const result = await runWorker(workspace, workspace.nonce, scenario);
          rows.push(row(PHASE3_WORKFLOW_POC_ROWS[rowIndex], "PASSED", result));
        }
      } catch (error) {
        dependency = errorCode(error);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[rowIndex], "FAILED", {
            code: dependency,
          }),
        );
      }
    }

    if (!dependency) {
      try {
        const recovered = await runWorker(
          workspace,
          workspace.nonce,
          "restart-recovery",
        );
        rows.push(row(PHASE3_WORKFLOW_POC_ROWS[6], "PASSED", recovered));
      } catch (error) {
        dependency = errorCode(error);
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[6], "FAILED", { code: dependency }),
        );
      }
    } else rows.push(skipped(PHASE3_WORKFLOW_POC_ROWS[6], dependency));
  } finally {
    while (rows.length < PHASE3_WORKFLOW_POC_ROWS.length - 1)
      rows.push(
        skipped(
          PHASE3_WORKFLOW_POC_ROWS[rows.length],
          dependency ?? "earlier_failure",
        ),
      );
    if (!workspace || !ancestor) {
      rows.push(
        row(PHASE3_WORKFLOW_POC_ROWS[7], "SKIPPED", {
          dependency: dependency ?? "workspace_not_created",
        }),
      );
    } else if (dependency === "cleanup_unproved") {
      rows.push(
        row(PHASE3_WORKFLOW_POC_ROWS[7], "FAILED", {
          code: "cleanup_unproved",
          classification: "process_or_identity_proof",
          preserved: true,
        }),
      );
    } else {
      try {
        const finalHelperProofs = validatedHelperProofs(native?.outputs);
        await proveHelpersAbsent(finalHelperProofs);
        rows.push(
          row(
            PHASE3_WORKFLOW_POC_ROWS[7],
            "PASSED",
            cleanupTopology(workspace.registry),
          ),
        );
      } catch {
        rows.push(
          row(PHASE3_WORKFLOW_POC_ROWS[7], "FAILED", {
            code: "cleanup_unproved",
            classification: cleanupFailureClassification,
            preserved: true,
          }),
        );
      }
    }
    for (const item of rows) emit(item);
    const final = summary(rows);
    emit(final);
    process.exitCode = final.status === "PASSED" ? 0 : 1;
  }
}

function delay(milliseconds) {
  return new Promise((resolvePromise) =>
    setTimeout(resolvePromise, milliseconds),
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
)
  await main();
