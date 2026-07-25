#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PROTOCOL = 1;
const MAX_IPC_BYTES = 16_384;
const MAX_WORKER_MS = 35_000;
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
const SCENARIOS = new Set([
  "success",
  "rollback",
  "restart-prepare",
  "restart-apply",
  "restart-recovery",
]);
const NONCE_PATTERN = /^[a-f0-9]{64}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SOURCE_EVIDENCE =
  "Protected /data proposal store and /homeassistant repository snapshot";
const SOURCE = Buffer.from(
  "- alias: Phase 3 disposable POC baseline\n  triggers: []\n  actions: []\n",
  "utf8",
);
const CANDIDATE = Buffer.from(
  "- alias: Phase 3 disposable POC candidate\n  triggers: []\n  actions: []\n",
  "utf8",
);
const DIFF = Buffer.from(
  "--- a/automations/poc.yaml\n" +
    "+++ b/automations/poc.yaml\n" +
    "@@ -1,3 +1,3 @@\n" +
    "-- alias: Phase 3 disposable POC baseline\n" +
    "+- alias: Phase 3 disposable POC candidate\n" +
    "   triggers: []\n" +
    "   actions: []\n",
  "utf8",
);
let handled = false;
let timer;

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === "string") &&
    expected.every((key) => keys.includes(key))
  );
}
function fail(code) {
  const error = new Error("Phase 3 workflow worker failed safely");
  Object.defineProperty(error, "pocCode", { value: code });
  return error;
}

function publicCode(error) {
  try {
    const pocDescriptor =
      typeof error === "object" && error !== null
        ? Object.getOwnPropertyDescriptor(error, "pocCode")
        : undefined;
    if (
      pocDescriptor &&
      "value" in pocDescriptor &&
      typeof pocDescriptor.value === "string"
    )
      return pocDescriptor.value;
    const codeDescriptor =
      typeof error === "object" && error !== null
        ? Object.getOwnPropertyDescriptor(error, "code")
        : undefined;
    if (
      codeDescriptor &&
      "value" in codeDescriptor &&
      typeof codeDescriptor.value === "string" &&
      /^[a-z0-9_]{1,48}$/u.test(codeDescriptor.value)
    )
      return `component_${codeDescriptor.value}`;
    return "worker_failed";
  } catch {
    return "worker_failed";
  }
}

function pathsIntersect(left, right) {
  const a = resolve(left);
  const b = resolve(right);
  return (
    a === "/" ||
    b === "/" ||
    a === b ||
    a.startsWith(`${b}/`) ||
    b.startsWith(`${a}/`)
  );
}

function decodeMountField(value) {
  return value.replace(/\\(040|011|012|134)/gu, (match, code) => {
    const decoded = { "040": " ", "011": "\t", "012": "\n", 134: "\\" };
    return decoded[code] ?? match;
  });
}

function mountpoints() {
  const value = readFileSync("/proc/self/mountinfo", "utf8");
  if (value.length === 0 || value.length > 4_194_304)
    throw fail("mountinfo_invalid");
  return value
    .trimEnd()
    .split("\n")
    .map((line) => {
      const fields = line.split(" ");
      const separator = fields.indexOf("-");
      if (separator < 6 || !fields[4]) throw fail("mountinfo_invalid");
      const mountpoint = decodeMountField(fields[4]);
      if (!mountpoint.startsWith("/") || resolve(mountpoint) !== mountpoint)
        throw fail("mountinfo_invalid");
      return mountpoint;
    });
}

function metadata(path) {
  const value = lstatSync(path, { bigint: true });
  return Object.freeze({
    dev: value.dev,
    ino: value.ino,
    uid: value.uid,
    mode: value.mode,
    nlink: value.nlink,
    size: value.size,
    type: value.isDirectory() ? "directory" : value.isFile() ? "file" : "other",
  });
}

function sameMetadata(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.type === right.type
  );
}

function validateSerializedIdentity(value, requirePath = false) {
  const keys = requirePath
    ? ["path", "dev", "ino", "uid", "mode", "nlink", "size", "type"]
    : ["dev", "ino", "uid", "mode", "nlink", "size", "type"];
  if (
    !exactKeys(value, keys) ||
    (requirePath &&
      (typeof value.path !== "string" ||
        !isAbsolute(value.path) ||
        resolve(value.path) !== value.path)) ||
    !["directory", "file"].includes(value.type)
  )
    throw fail("invalid_request");
  const output = {};
  for (const key of ["dev", "ino", "uid", "mode", "nlink", "size"]) {
    if (
      typeof value[key] !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/u.test(value[key])
    )
      throw fail("invalid_request");
    output[key] = BigInt(value[key]);
  }
  return Object.freeze({
    ...(requirePath ? { path: value.path } : {}),
    ...output,
    type: value.type,
  });
}

function validatePins(value) {
  if (
    !exactKeys(value, ["ancestor", "root", "nonce", "helpers"]) ||
    !exactKeys(value.helpers, ["list", "read", "replace"]) ||
    !exactKeys(value.nonce, [
      "dev",
      "ino",
      "uid",
      "mode",
      "nlink",
      "size",
      "type",
      "sha256",
    ])
  )
    throw fail("invalid_request");
  const ancestor = validateSerializedIdentity(value.ancestor, true);
  const root = validateSerializedIdentity(value.root);
  const nonceIdentity = validateSerializedIdentity(
    Object.fromEntries(
      Object.entries(value.nonce).filter(([key]) => key !== "sha256"),
    ),
  );
  if (!SHA256_PATTERN.test(value.nonce.sha256)) throw fail("invalid_request");
  const helpers = Object.fromEntries(
    Object.entries(value.helpers).map(([name, proof]) => {
      if (
        !exactKeys(proof, [
          "dev",
          "ino",
          "uid",
          "mode",
          "nlink",
          "size",
          "type",
          "sha256",
        ]) ||
        !SHA256_PATTERN.test(proof.sha256)
      )
        throw fail("invalid_request");
      const serialized = Object.fromEntries(
        Object.entries(proof).filter(([key]) => key !== "sha256"),
      );
      return [
        name,
        Object.freeze({
          metadata: validateSerializedIdentity(serialized),
          sha256: proof.sha256,
        }),
      ];
    }),
  );
  return Object.freeze({
    ancestor,
    root,
    nonce: Object.freeze({
      metadata: nonceIdentity,
      sha256: value.nonce.sha256,
    }),
    helpers: Object.freeze(helpers),
  });
}

function validateRequest(message) {
  if (
    !exactKeys(message, [
      "type",
      "protocol",
      "nonce",
      "workspace",
      "scenario",
      "deadlineAt",
      "artifacts",
      "pins",
    ]) ||
    message.type !== "run" ||
    message.protocol !== PROTOCOL ||
    !NONCE_PATTERN.test(message.nonce) ||
    !SCENARIOS.has(message.scenario) ||
    !Number.isSafeInteger(message.deadlineAt) ||
    message.deadlineAt <= Date.now() ||
    message.deadlineAt > Date.now() + MAX_WORKER_MS ||
    !exactKeys(message.artifacts, ["list", "read", "replace", "nonce"]) ||
    JSON.stringify(message.artifacts) !== JSON.stringify(ARTIFACTS)
  )
    throw fail("invalid_request");
  if (
    typeof message.workspace !== "string" ||
    message.workspace.length > 256 ||
    !isAbsolute(message.workspace) ||
    resolve(message.workspace) !== message.workspace
  )
    throw fail("invalid_request");
  return Object.freeze({
    nonce: message.nonce,
    workspace: message.workspace,
    scenario: message.scenario,
    deadlineAt: message.deadlineAt,
    pins: validatePins(message.pins),
  });
}

function validateWorkspace(request) {
  if (
    process.platform !== "linux" ||
    !process.getuid ||
    !process.geteuid ||
    process.getuid() !== process.geteuid() ||
    process.getuid() === 0
  )
    throw fail("worker_environment");
  for (const name of DENIED_ENV)
    if (Object.hasOwn(process.env, name)) throw fail("worker_environment");
  const root = request.workspace;
  if (
    DENIED_ROOTS.some((denied) => pathsIntersect(root, denied)) ||
    !["/tmp", "/var/tmp"].includes(dirname(root)) ||
    dirname(root) !== request.pins.ancestor.path ||
    realpathSync(root) !== root
  )
    throw fail("workspace_denied");
  const ancestor = metadata(dirname(root));
  const rootMetadata = metadata(root);
  if (
    ancestor.type !== "directory" ||
    ancestor.uid !== 0n ||
    (ancestor.mode & 0o7777n) !== 0o1777n ||
    ancestor.nlink < 1n ||
    ancestor.nlink > 1_048_576n ||
    !sameMetadata(ancestor, request.pins.ancestor) ||
    rootMetadata.type !== "directory" ||
    !sameMetadata(rootMetadata, request.pins.root) ||
    rootMetadata.uid !== BigInt(process.getuid()) ||
    rootMetadata.nlink < 2n ||
    (rootMetadata.mode & 0o7777n) !== 0o700n
  )
    throw fail("workspace_metadata");
  if (
    mountpoints().some(
      (mountpoint) => mountpoint === root || mountpoint.startsWith(`${root}/`),
    )
  )
    throw fail("workspace_mount_detected");
  const noncePath = join(root, ARTIFACTS.nonce);
  const before = metadata(noncePath);
  if (
    !sameMetadata(before, request.pins.nonce.metadata) ||
    before.type !== "file" ||
    before.nlink !== 1n ||
    before.uid !== BigInt(process.getuid()) ||
    (before.mode & 0o7777n) !== 0o600n
  )
    throw fail("nonce_metadata");
  const descriptor = openSync(
    noncePath,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.uid !== before.uid ||
      opened.mode !== before.mode ||
      opened.nlink !== before.nlink
    )
      throw fail("nonce_substituted");
    const nonceBytes = readFileSync(descriptor);
    if (
      nonceBytes.toString("ascii") !== `${request.nonce}\n` ||
      createHash("sha256").update(nonceBytes).digest("hex") !==
        request.pins.nonce.sha256
    )
      throw fail("nonce_mismatch");
  } finally {
    closeSync(descriptor);
  }
  for (const name of ["list", "read", "replace"]) {
    const path = join(root, ARTIFACTS[name]);
    const artifact = metadata(path);
    const expected = request.pins.helpers[name];
    if (
      !sameMetadata(artifact, expected.metadata) ||
      artifact.type !== "file" ||
      artifact.nlink !== 1n ||
      artifact.uid !== BigInt(process.getuid()) ||
      (artifact.mode & 0o7777n) !== 0o555n
    )
      throw fail("helper_metadata");
    const descriptor = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      const opened = fstatSync(descriptor, { bigint: true });
      const openedMetadata = Object.freeze({
        dev: opened.dev,
        ino: opened.ino,
        uid: opened.uid,
        mode: opened.mode,
        nlink: opened.nlink,
        size: opened.size,
        type: opened.isFile() ? "file" : "other",
      });
      const bytes = readFileSync(descriptor);
      if (
        !sameMetadata(openedMetadata, expected.metadata) ||
        createHash("sha256").update(bytes).digest("hex") !== expected.sha256
      )
        throw fail("helper_substituted");
    } finally {
      closeSync(descriptor);
    }
  }
  return Object.freeze({ ancestor, root: rootMetadata });
}

async function modules() {
  const [
    repository,
    boundary,
    activation,
    phase2Contracts,
    storage,
    proposalAdapter,
    approvalKey,
    approvals,
    journal,
    checkpoints,
    sourceAdapter,
    atomicApply,
    validation,
    reload,
    verification,
    coordinator,
    locks,
  ] = await Promise.all([
    import("../../dist/repository/repositoryReads.js"),
    import("../../dist/security/repositoryBoundary.js"),
    import("../../dist/phase2Activation.js"),
    import("../../dist/phase2Contracts.js"),
    import("../../dist/proposals/storage.js"),
    import("../../dist/phase3/proposalAdapter.js"),
    import("../../dist/phase3/approvalKey.js"),
    import("../../dist/phase3/durableApproval.js"),
    import("../../dist/phase3/journal.js"),
    import("../../dist/phase3/checkpoints.js"),
    import("../../dist/phase3/sourceAdapter.js"),
    import("../../dist/phase3/atomicApply.js"),
    import("../../dist/phase3/validationAdapter.js"),
    import("../../dist/phase3/reloadAdapter.js"),
    import("../../dist/phase3/verificationAdapter.js"),
    import("../../dist/phase3/applyCoordinator.js"),
    import("../../dist/phase3/resourceLocks.js"),
  ]);
  if (typeof activation.ProductionSecretValueProvider !== "function")
    throw fail("activation_import_boundary");
  return Object.freeze({
    repository,
    boundary,
    ProductionSecretValueProvider: activation.ProductionSecretValueProvider,
    phase2Contracts,
    storage,
    proposalAdapter,
    approvalKey,
    approvals,
    journal,
    checkpoints,
    sourceAdapter,
    atomicApply,
    validation,
    reload,
    verification,
    coordinator,
    locks,
  });
}

function mkdirPrivate(path) {
  mkdirSync(path, { mode: 0o700, recursive: false });
  const value = metadata(path);
  if (
    value.type !== "directory" ||
    value.uid !== BigInt(process.getuid()) ||
    (value.mode & 0o7777n) !== 0o700n
  )
    throw fail("directory_metadata");
}

function writePrivate(path, bytes) {
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  const value = metadata(path);
  if (
    value.type !== "file" ||
    value.nlink !== 1n ||
    value.uid !== BigInt(process.getuid()) ||
    (value.mode & 0o7777n) !== 0o600n
  )
    throw fail("file_metadata");
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function applyFixtureUnifiedDiff(source, diff) {
  if (!Buffer.isBuffer(source) || !Buffer.isBuffer(diff))
    throw fail("fixture_diff_invalid");
  const sourceLines = source.toString("utf8").split("\n");
  const diffLines = diff.toString("utf8").split("\n");
  if (
    sourceLines.pop() !== "" ||
    diffLines.pop() !== "" ||
    diffLines[0] !== "--- a/automations/poc.yaml" ||
    diffLines[1] !== "+++ b/automations/poc.yaml" ||
    diffLines[2] !== "@@ -1,3 +1,3 @@"
  )
    throw fail("fixture_diff_invalid");
  const output = [];
  let sourceIndex = 0;
  for (const line of diffLines.slice(3)) {
    const marker = line[0];
    const content = line.slice(1);
    if (marker === " ") {
      if (sourceLines[sourceIndex] !== content)
        throw fail("fixture_diff_invalid");
      output.push(content);
      sourceIndex += 1;
    } else if (marker === "-") {
      if (sourceLines[sourceIndex] !== content)
        throw fail("fixture_diff_invalid");
      sourceIndex += 1;
    } else if (marker === "+") output.push(content);
    else throw fail("fixture_diff_invalid");
  }
  if (sourceIndex !== sourceLines.length) throw fail("fixture_diff_invalid");
  return Buffer.from(`${output.join("\n")}\n`, "utf8");
}

export function fixtureDigests() {
  const applied = applyFixtureUnifiedDiff(SOURCE, DIFF);
  return Object.freeze({
    sourceSha256: digest(SOURCE),
    candidateSha256: digest(CANDIDATE),
    appliedSha256: digest(applied),
    diffSha256: digest(DIFF),
    candidateMatches: applied.equals(CANDIDATE),
  });
}

function phase2Context(deadlineAt) {
  return Object.freeze({
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt,
    signal: new AbortController().signal,
  });
}

function phase3Context(deadlineAt) {
  return Object.freeze({
    deadlineAt,
    signal: new AbortController().signal,
  });
}

function scenarioPaths(workspace, scenario) {
  const name = scenario.startsWith("restart") ? "restart" : scenario;
  const root = join(workspace, name);
  return Object.freeze({
    name,
    root,
    repository: join(root, "repo"),
    automations: join(root, "repo", "automations"),
    proposalStore: join(root, "proposal-store"),
    journal: join(root, "journal"),
    checkpoints: join(root, "checkpoints"),
    approval: join(root, "approval"),
    keyState: join(root, "key-state"),
    keyPath: join(root, "key-state", "approval.key"),
    control: join(root, "control.json"),
  });
}

function createFixtureDirectories(paths) {
  mkdirPrivate(paths.root);
  mkdirPrivate(paths.repository);
  mkdirPrivate(paths.automations);
  mkdirPrivate(paths.approval);
  mkdirPrivate(paths.keyState);
  writePrivate(
    join(paths.repository, "secrets.yaml"),
    Buffer.from("{}\n", "utf8"),
  );
  writePrivate(join(paths.automations, "poc.yaml"), SOURCE);
}

async function proposalFixture(mod, paths, impact, deadlineAt) {
  const applied = applyFixtureUnifiedDiff(SOURCE, DIFF);
  if (!applied.equals(CANDIDATE)) throw fail("fixture_diff_mismatch");
  const store = new mod.storage.ProtectedProposalStore(paths.proposalStore);
  await store.initialize();
  const proposalId = randomUUID();
  const idempotencyKey = randomUUID();
  const candidateSha256 = digest(CANDIDATE);
  const diffSha256 = digest(DIFF);
  const publicValue = mod.phase2Contracts.proposalPublicSchema.parse({
    proposalId,
    idempotencyKey,
    state: "pending",
    path: "automations/poc.yaml",
    expectedSha256: digest(SOURCE),
    candidateSha256,
    diffSha256,
    redactedDiff: "disposable alias-only fixture",
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    risk: "high",
    validationPlan: ["strict_yaml", "post_apply", "trusted_probe"],
    reloadImpact: impact,
    sourceEvidence: SOURCE_EVIDENCE,
  });
  const protectedValue =
    mod.phase2Contracts.protectedProposalPayloadSchema.parse({
      schemaVersion: 1,
      proposalId,
      idempotencyKey,
      candidateSha256,
      diffSha256,
      encoding: "utf-8",
      exactCandidateBytesBase64: CANDIDATE.toString("base64"),
      exactDiffBytesBase64: DIFF.toString("base64"),
    });
  const envelope = mod.storage.storageEnvelope(publicValue, protectedValue);
  await store.create(envelope, phase2Context(deadlineAt));
  return Object.freeze({
    store,
    adapter: new mod.proposalAdapter.ProtectedPhase3ProposalAdapter(store),
    proposalId,
    candidateSha256,
    expectedSha256: digest(SOURCE),
  });
}

function domainProposalFixture(real) {
  return Object.freeze({
    async load(proposalId) {
      const proposal = await real.load(proposalId);
      return Object.freeze({
        ...proposal,
        impact: "domain_reload",
        reloadTarget: "automation.reload",
      });
    },
    async loadCandidate(proposalId) {
      return await real.loadCandidate(proposalId);
    },
  });
}

async function nativeComposition(mod, request, paths, proposalPort, probeMode) {
  const helperDeadline = Math.min(
    request.deadlineAt - 2_000,
    Date.now() + 12_000,
  );
  if (helperDeadline <= Date.now()) throw fail("helper_deadline");
  const catalog = new mod.repository.NativeOpenat2Catalog({
    helperPath: join(request.workspace, ARTIFACTS.list),
    root: paths.repository,
    maximumConcurrentHelpers: 1,
  });
  const reader = new mod.boundary.NativeOpenat2Reader({
    helperPath: join(request.workspace, ARTIFACTS.read),
    root: paths.repository,
    maximumConcurrentHelpers: 1,
  });
  const registry = new mod.boundary.ProtectedIdentityRegistry(reader);
  await registry.initialize(
    Object.freeze(["secrets.yaml"]),
    new mod.ProductionSecretValueProvider(),
    phase2Context(helperDeadline),
  );
  const source = new mod.sourceAdapter.ProtectedPhase3SourceAdapter(
    catalog,
    registry,
  );
  const journal = new mod.journal.DurablePhase3Journal(paths.journal);
  const checkpoints = new mod.checkpoints.DurablePhase3Checkpoints(
    paths.checkpoints,
  );
  await journal.initialize();
  await checkpoints.initialize();
  const reloadCalls = [];
  const reloadPort = new mod.reload.NarrowPhase3ReloadAdapter(
    Object.freeze({
      async resolve(path, context) {
        if (
          path !== "automations/poc.yaml" ||
          context.signal.aborted ||
          Date.now() >= context.deadlineAt
        )
          throw fail("reload_fixture");
        return Object.freeze({
          status: "resolved",
          target: "automation.reload",
        });
      },
    }),
    Object.freeze({
      async reload(target, context) {
        if (
          target !== "automation.reload" ||
          context.signal.aborted ||
          Date.now() >= context.deadlineAt
        )
          throw fail("reload_fixture");
        reloadCalls.push(target);
        return Object.freeze({ status: "completed" });
      },
    }),
  );
  const probeCalls = [];
  const verificationPort = new mod.verification.NarrowPhase3VerificationAdapter(
    source,
    Object.freeze({
      async probe(probe, context) {
        if (context.signal.aborted || Date.now() >= context.deadlineAt)
          throw fail("verification_fixture");
        probeCalls.push(probe.outcome);
        const status =
          probeMode === "reject_candidate" && probe.outcome === "candidate"
            ? "rejected"
            : "verified";
        return Object.freeze({
          status,
          transactionId: probe.transactionId,
          outcome: probe.outcome,
          expectedSha256: probe.expectedSha256,
        });
      },
    }),
  );
  const atomic = new mod.atomicApply.NativePhase3AtomicApply({
    root: paths.repository,
    helperPath: join(request.workspace, ARTIFACTS.replace),
    maxConcurrent: 1,
    maxWaiters: 1,
    terminationGraceMs: 250,
  });
  return Object.freeze({
    proposalPort,
    source,
    journal,
    checkpoints,
    reloadPort,
    verificationPort,
    reloadCalls,
    probeCalls,
    atomic,
  });
}

async function keyAndApproval(mod, paths, create, deadlineAt) {
  if (create)
    await mod.approvalKey.provisionPhase3ApprovalKey({
      stateDirectory: paths.keyState,
      keyPath: paths.keyPath,
    });
  const lease = create
    ? await mod.approvalKey.loadPhase3ApprovalKey({
        stateDirectory: paths.keyState,
        keyPath: paths.keyPath,
      })
    : await mod.approvalKey.synchronizeExistingPhase3ApprovalKey({
        stateDirectory: paths.keyState,
        keyPath: paths.keyPath,
      });
  const approval = new mod.approvals.DurablePhase3ApprovalGrants(
    paths.approval,
    lease.key,
  );
  await approval.initialize();
  if (Date.now() >= deadlineAt) throw fail("approval_deadline");
  return Object.freeze({ approval, lease });
}

function coordinator(
  mod,
  composition,
  approvals,
  atomicApply = composition.atomic,
) {
  return new mod.coordinator.Phase3ApplyCoordinator({
    proposals: composition.proposalPort,
    policy: new mod.coordinator.GuardedPhase3PolicyPort({
      writesEnabled: true,
      applyCapability: true,
      domainReloadCapability: true,
    }),
    approvals,
    locks: new mod.locks.Phase3ResourceLocks(),
    source: composition.source,
    validation: new mod.validation.StrictYamlPhase3Validation(),
    checkpoints: composition.checkpoints,
    atomicApply,
    reload: composition.reloadPort,
    verification: composition.verificationPort,
    journal: composition.journal,
  });
}

async function issueGrant(approval, proposalPort, proposalId, deadlineAt) {
  const proposal = await proposalPort.load(proposalId);
  const grant = await approval.issueApplyGrant(proposal, {
    now: Date.now(),
    signal: new AbortController().signal,
  });
  if (Date.now() >= deadlineAt) throw fail("approval_deadline");
  return Object.freeze({ proposal, grant });
}

async function expectReplay(approval, grantId, proposal) {
  try {
    await approval.consumeApplyGrant(grantId, proposal, {
      now: Date.now(),
      signal: new AbortController().signal,
    });
  } catch (error) {
    if (error?.code === "approval_replayed") return true;
  }
  throw fail("approval_replay_unproved");
}

async function runFresh(request, rollback) {
  let mod;
  try {
    mod = await modules();
  } catch {
    throw fail("module_import_failed");
  }
  const paths = scenarioPaths(request.workspace, request.scenario);
  try {
    createFixtureDirectories(paths);
  } catch {
    throw fail("fixture_create_failed");
  }
  let fixture;
  try {
    fixture = await proposalFixture(mod, paths, "none", request.deadlineAt);
  } catch {
    throw fail("proposal_fixture_failed");
  }
  const proposalPort = rollback
    ? domainProposalFixture(fixture.adapter)
    : fixture.adapter;
  let composition;
  try {
    composition = await nativeComposition(
      mod,
      request,
      paths,
      proposalPort,
      rollback ? "reject_candidate" : "verify",
    );
  } catch {
    throw fail("composition_failed");
  }
  let authority;
  try {
    authority = await keyAndApproval(mod, paths, true, request.deadlineAt);
  } catch {
    throw fail("authority_failed");
  }
  try {
    const issued = await issueGrant(
      authority.approval,
      proposalPort,
      fixture.proposalId,
      request.deadlineAt,
    );
    const record = await coordinator(
      mod,
      composition,
      authority.approval,
    ).apply(
      { proposalId: fixture.proposalId, grantId: issued.grant.grantId },
      phase3Context(request.deadlineAt),
    );
    const replay = await expectReplay(
      authority.approval,
      issued.grant.grantId,
      issued.proposal,
    );
    if (
      (!rollback && record.state !== "verification_succeeded") ||
      (rollback && record.state !== "rollback_verification_succeeded")
    )
      throw fail("terminal_state");
    if (
      (!rollback &&
        (composition.reloadCalls.length !== 0 ||
          JSON.stringify(composition.probeCalls) !==
            JSON.stringify(["candidate"]))) ||
      (rollback &&
        (composition.reloadCalls.length !== 2 ||
          JSON.stringify(composition.probeCalls) !==
            JSON.stringify(["candidate", "checkpoint"])))
    )
      throw fail("adapter_evidence");
    return rollback
      ? Object.freeze({
          terminalState: "rollback_verification_succeeded",
          realDurableApply: true,
          candidateProbeRejected: true,
          checkpointRestored: true,
          rollbackReloads: 1,
          homeAssistantCalls: 0,
          replayRejected: replay,
        })
      : Object.freeze({
          terminalState: "verification_succeeded",
          protectedStoreApi: true,
          realSourceRead: true,
          realApprovalConsume: true,
          replayRejected: replay,
          nativeCommitted: true,
          trustedProbeVerified: true,
          homeAssistantCalls: 0,
        });
  } finally {
    await authority.approval.close();
    authority.lease.release();
  }
}

async function restartPrepare(request) {
  const mod = await modules();
  const paths = scenarioPaths(request.workspace, request.scenario);
  createFixtureDirectories(paths);
  const fixture = await proposalFixture(mod, paths, "none", request.deadlineAt);
  const composition = await nativeComposition(
    mod,
    request,
    paths,
    fixture.adapter,
    "verify",
  );
  if (!composition.journal || !composition.checkpoints)
    throw fail("durable_components_unavailable");
  const authority = await keyAndApproval(mod, paths, true, request.deadlineAt);
  try {
    const issued = await issueGrant(
      authority.approval,
      fixture.adapter,
      fixture.proposalId,
      request.deadlineAt,
    );
    writePrivate(
      paths.control,
      Buffer.from(
        JSON.stringify({
          proposalId: fixture.proposalId,
          grantId: issued.grant.grantId,
          candidateSha256: fixture.candidateSha256,
          expectedSha256: fixture.expectedSha256,
        }),
        "utf8",
      ),
    );
    return Object.freeze({
      headerAuthenticated: true,
      grantIssued: true,
      initialAuthorityClosed: true,
      durableComponentsInitialized: true,
    });
  } finally {
    await authority.approval.close();
    authority.lease.release();
  }
}

function readControl(paths) {
  const before = metadata(paths.control);
  if (
    before.type !== "file" ||
    before.nlink !== 1n ||
    before.uid !== BigInt(process.getuid()) ||
    (before.mode & 0o7777n) !== 0o600n ||
    before.size > 1024n
  )
    throw fail("control_metadata");
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(paths.control, "utf8"));
  } catch {
    throw fail("control_invalid");
  }
  if (
    !exactKeys(parsed, [
      "proposalId",
      "grantId",
      "candidateSha256",
      "expectedSha256",
    ]) ||
    !UUID_PATTERN.test(parsed.proposalId) ||
    !UUID_PATTERN.test(parsed.grantId) ||
    !SHA256_PATTERN.test(parsed.candidateSha256) ||
    !SHA256_PATTERN.test(parsed.expectedSha256)
  )
    throw fail("control_invalid");
  return Object.freeze(parsed);
}

async function reopenRestart(mod, request, paths) {
  const control = readControl(paths);
  const store = new mod.storage.ProtectedProposalStore(paths.proposalStore);
  await store.initialize();
  const realProposal = new mod.proposalAdapter.ProtectedPhase3ProposalAdapter(
    store,
  );
  const composition = await nativeComposition(
    mod,
    request,
    paths,
    realProposal,
    "verify",
  );
  const authority = await keyAndApproval(mod, paths, false, request.deadlineAt);
  return Object.freeze({
    control,
    store,
    realProposal,
    composition,
    authority,
  });
}

async function restartApply(request) {
  const mod = await modules();
  const paths = scenarioPaths(request.workspace, request.scenario);
  const state = await reopenRestart(mod, request, paths);
  const killAfterCommitted = Object.freeze({
    async replace(input, context) {
      const result = await state.composition.atomic.replace(input, context);
      if (result.status !== "committed") throw fail("native_not_committed");
      await send({
        type: "committed",
        protocol: PROTOCOL,
        nonce: request.nonce,
        scenario: request.scenario,
        evidence: Object.freeze({ status: "committed", helperClosed: true }),
      });
      process.kill(process.pid, "SIGKILL");
      await new Promise(() => {});
    },
  });
  try {
    await coordinator(
      mod,
      state.composition,
      state.authority.approval,
      killAfterCommitted,
    ).apply(
      {
        proposalId: state.control.proposalId,
        grantId: state.control.grantId,
      },
      phase3Context(request.deadlineAt),
    );
    throw fail("sigkill_not_observed");
  } finally {
    await state.authority.approval.close();
    state.authority.lease.release();
  }
}

async function restartRecovery(request) {
  const mod = await modules();
  const paths = scenarioPaths(request.workspace, request.scenario);
  const state = await reopenRestart(mod, request, paths);
  let proposalLoads = 0;
  let candidateReapplies = 0;
  let checkpointRestores = 0;
  const countedProposal = Object.freeze({
    async load(id) {
      proposalLoads += 1;
      return await state.realProposal.load(id);
    },
    async loadCandidate(id) {
      proposalLoads += 1;
      return await state.realProposal.loadCandidate(id);
    },
  });
  const countedAtomic = Object.freeze({
    async replace(input, context) {
      if (input.contentSha256 === state.control.candidateSha256)
        candidateReapplies += 1;
      if (input.contentSha256 === state.control.expectedSha256)
        checkpointRestores += 1;
      return await state.composition.atomic.replace(input, context);
    },
  });
  const proposal = await state.realProposal.load(state.control.proposalId);
  const replay = await expectReplay(
    state.authority.approval,
    state.control.grantId,
    proposal,
  );
  const recoveryComposition = Object.freeze({
    ...state.composition,
    proposalPort: countedProposal,
  });
  try {
    const results = await coordinator(
      mod,
      recoveryComposition,
      state.authority.approval,
      countedAtomic,
    ).recover();
    if (
      results.length !== 1 ||
      results[0].terminalState !== "rollback_verification_succeeded" ||
      results[0].disposition !== "rolled_back" ||
      proposalLoads !== 0 ||
      candidateReapplies !== 0 ||
      checkpointRestores !== 1
    )
      throw fail("recovery_evidence");
    return Object.freeze({
      synchronizedKey: true,
      authenticatedHeader: true,
      approvalReplayed: replay,
      proposalLoadsDuringRecovery: proposalLoads,
      candidateReapplies,
      checkpointRestores,
      terminalState: "rollback_verification_succeeded",
      homeAssistantCalls: 0,
    });
  } finally {
    await state.authority.approval.close();
    state.authority.lease.release();
  }
}

async function execute(request) {
  try {
    validateWorkspace(request);
  } catch (error) {
    if (publicCode(error) !== "worker_failed") throw error;
    throw fail("workspace_validation_failed");
  }
  try {
    if (request.scenario === "success") return await runFresh(request, false);
    if (request.scenario === "rollback") return await runFresh(request, true);
    if (request.scenario === "restart-prepare")
      return await restartPrepare(request);
    if (request.scenario === "restart-apply")
      return await restartApply(request);
    return await restartRecovery(request);
  } catch (error) {
    if (publicCode(error) !== "worker_failed") throw error;
    throw fail("scenario_execution_failed");
  }
}

function send(message) {
  if (!process.send) return Promise.reject(fail("ipc_unavailable"));
  if (Buffer.byteLength(JSON.stringify(message), "utf8") > MAX_IPC_BYTES)
    return Promise.reject(fail("ipc_boundary"));
  return new Promise((resolvePromise, rejectPromise) => {
    process.send(message, (error) =>
      error ? rejectPromise(fail("ipc_send")) : resolvePromise(),
    );
  });
}

async function workerMain() {
  if (!process.send) {
    process.exitCode = 64;
    return;
  }
  await send({ type: "boot", protocol: PROTOCOL });
  timer = setTimeout(() => process.exit(64), 5_000);
  process.once("message", async (message) => {
    if (handled) {
      process.exitCode = 64;
      return;
    }
    handled = true;
    clearTimeout(timer);
    let request;
    try {
      if (Buffer.byteLength(JSON.stringify(message), "utf8") > MAX_IPC_BYTES)
        throw fail("ipc_boundary");
      request = validateRequest(message);
      const evidence = await execute(request);
      await send({
        type: "result",
        protocol: PROTOCOL,
        nonce: request.nonce,
        scenario: request.scenario,
        ok: true,
        evidence,
      });
      process.disconnect();
    } catch (error) {
      const nonce =
        request?.nonce ??
        (typeof message?.nonce === "string" && NONCE_PATTERN.test(message.nonce)
          ? message.nonce
          : "0".repeat(64));
      const scenario =
        request?.scenario ??
        (typeof message?.scenario === "string" &&
        SCENARIOS.has(message.scenario)
          ? message.scenario
          : "success");
      await send({
        type: "result",
        protocol: PROTOCOL,
        nonce,
        scenario,
        ok: false,
        code: publicCode(error),
      }).catch(() => undefined);
      process.disconnect();
      process.exitCode = 1;
    }
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
)
  await workerMain();
