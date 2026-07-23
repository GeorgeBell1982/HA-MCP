#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { DurablePhase3ApprovalGrants } from "../../dist/phase3/durableApproval.js";

const PROTOCOL_VERSION = 1;
const NOW = 1_700_000_000_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RELATIVE_ARTIFACT_PATTERN =
  /^(?!\/)(?!\.\.?$)(?!\.\.\/)(?!.*\/\.\.?(?:\/|$))[A-Za-z0-9._/-]+$/u;
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
const KEY_BYTES = Object.freeze({
  primary: 0x31,
  secondary: 0x73,
});

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function parseArguments(argv) {
  const config = { uuids: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined) return undefined;
    if (flag === "--root") config.root = value;
    else if (flag === "--key") config.key = value;
    else if (flag === "--uuid") config.uuids.push(value);
    else return undefined;
  }
  if (
    typeof config.root !== "string" ||
    !isAbsolute(config.root) ||
    resolve(config.root) !== config.root ||
    !Object.hasOwn(KEY_BYTES, config.key) ||
    config.uuids.some((value) => !UUID_PATTERN.test(value))
  )
    return undefined;
  return config;
}

const config = parseArguments(process.argv.slice(2));
if (!config || typeof process.send !== "function") process.exit(64);

const proposal = Object.freeze({
  proposalId: "10000000-0000-4000-8000-000000000001",
  proposalStorageSha256: "1".repeat(64),
  state: "pending",
  path: "configuration.yaml",
  expectedSha256: "2".repeat(64),
  candidateSha256: "3".repeat(64),
  diffSha256: "4".repeat(64),
  risk: "high",
  impact: "restart_required",
  reloadTarget: null,
  expiresAt: new Date(NOW + 86_400_000).toISOString(),
});
const uuidQueue = [...config.uuids];
let store;
let active;
let lastRequestId = 0;

function relativeArtifact(path) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path)
    throw new Error("invalid hook path");
  const value = relative(config.root, path);
  if (
    value === "" ||
    value === ".." ||
    value.startsWith(`..${sep}`) ||
    isAbsolute(value) ||
    value.includes("\\")
  )
    throw new Error("hook path escaped root");
  return value.split(sep).join("/");
}

function validateHook(context) {
  const keys =
    context?.grantId === undefined
      ? ["stage", "commitState", "root", "pendingPath", "finalPath"]
      : ["stage", "commitState", "root", "pendingPath", "finalPath", "grantId"];
  if (
    !exactKeys(context, keys) ||
    !HOOK_STAGES.has(context.stage) ||
    !COMMIT_STATES.has(context.commitState) ||
    context.root !== config.root ||
    (context.grantId !== undefined && !UUID_PATTERN.test(context.grantId))
  )
    throw new Error("invalid hook context");
  const hook = {
    stage: context.stage,
    commitState: context.commitState,
    relativePending: relativeArtifact(context.pendingPath),
    relativeFinal: relativeArtifact(context.finalPath),
    ...(context.grantId === undefined ? {} : { grantId: context.grantId }),
  };
  if (
    !RELATIVE_ARTIFACT_PATTERN.test(hook.relativePending) ||
    !RELATIVE_ARTIFACT_PATTERN.test(hook.relativeFinal) ||
    !exactKeys(
      hook,
      context.grantId === undefined
        ? ["stage", "commitState", "relativePending", "relativeFinal"]
        : [
            "stage",
            "commitState",
            "relativePending",
            "relativeFinal",
            "grantId",
          ],
    )
  )
    throw new Error("invalid sanitized hook");
  return Object.freeze(hook);
}

function send(message) {
  return new Promise((resolvePromise, reject) => {
    process.send(message, (error) =>
      error ? reject(error) : resolvePromise(),
    );
  });
}

async function afterStage(context) {
  if (!active) throw new Error("hook without request");
  const hook = validateHook(context);
  await send({ type: "hook", requestId: active.requestId, hook });
  if (active.pauseStage !== hook.stage || active.paused) return;
  active.paused = true;
  await new Promise((resolvePromise, reject) => {
    active.resume = resolvePromise;
    active.rejectResume = reject;
  });
}

function context() {
  return { now: NOW, signal: new AbortController().signal };
}

function publicCode(error) {
  try {
    return PUBLIC_CODES.has(error?.code)
      ? error.code
      : "approval_store_unhealthy";
  } catch {
    return "approval_store_unhealthy";
  }
}

function parseRequest(message) {
  if (
    message === null ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    message.type !== "request" ||
    !Number.isSafeInteger(message.requestId) ||
    message.requestId <= lastRequestId
  )
    return undefined;
  if (message.command === "initialize" || message.command === "issue") {
    const allowed =
      message.pauseStage === undefined
        ? ["type", "requestId", "command"]
        : ["type", "requestId", "command", "pauseStage"];
    if (
      !exactKeys(message, allowed) ||
      (message.pauseStage !== undefined &&
        (!HOOK_STAGES.has(message.pauseStage) ||
          !message.pauseStage.startsWith(
            message.command === "initialize" ? "header_" : "grant_",
          )))
    )
      return undefined;
    return message;
  }
  if (message.command === "consume") {
    const allowed =
      message.pauseStage === undefined
        ? ["type", "requestId", "command", "grantId"]
        : ["type", "requestId", "command", "grantId", "pauseStage"];
    if (
      !exactKeys(message, allowed) ||
      !UUID_PATTERN.test(message.grantId) ||
      (message.pauseStage !== undefined &&
        (!HOOK_STAGES.has(message.pauseStage) ||
          !message.pauseStage.startsWith("receipt_")))
    )
      return undefined;
    return message;
  }
  if (
    message.command === "close" &&
    exactKeys(message, ["type", "requestId", "command"])
  )
    return message;
  return undefined;
}

function parseResume(message) {
  return (
    exactKeys(message, ["type", "requestId", "stage"]) &&
    message.type === "resume" &&
    active?.requestId === message.requestId &&
    active.pauseStage === message.stage &&
    active.paused &&
    typeof active.resume === "function"
  );
}

async function execute(request) {
  if (request.command === "initialize") {
    if (store === undefined) {
      store = new DurablePhase3ApprovalGrants(
        config.root,
        Buffer.alloc(32, KEY_BYTES[config.key]),
        {
          hooks: { afterStage },
          now: () => NOW,
          randomUUID: () => uuidQueue.shift() ?? randomUUID(),
        },
      );
    }
    await store.initialize();
    return {
      adapters: Object.freeze({ filesystem: "default", durability: "default" }),
    };
  }
  if (store === undefined) throw new Error("store is not initialized");
  if (request.command === "issue")
    return { grant: await store.issueApplyGrant(proposal, context()) };
  if (request.command === "consume")
    return {
      grant: await store.consumeApplyGrant(
        request.grantId,
        proposal,
        context(),
      ),
    };
  await store.close();
  return { closed: true };
}

process.on("message", async (message) => {
  if (parseResume(message)) {
    const resume = active.resume;
    active.resume = undefined;
    active.rejectResume = undefined;
    resume();
    return;
  }
  if (active) {
    await send({ type: "protocol-failure", code: "request_overlap" }).catch(
      () => undefined,
    );
    process.exitCode = 65;
    process.disconnect();
    return;
  }
  const request = parseRequest(message);
  if (!request) {
    await send({ type: "protocol-failure", code: "invalid_request" }).catch(
      () => undefined,
    );
    process.exitCode = 65;
    process.disconnect();
    return;
  }
  lastRequestId = request.requestId;
  active = {
    requestId: request.requestId,
    pauseStage: request.pauseStage,
    paused: false,
  };
  try {
    const evidence = await execute(request);
    await send({
      type: "result",
      requestId: request.requestId,
      command: request.command,
      ok: true,
      evidence,
    });
  } catch (error) {
    await send({
      type: "result",
      requestId: request.requestId,
      command: request.command,
      ok: false,
      code: publicCode(error),
    }).catch(() => undefined);
  } finally {
    active = undefined;
  }
  if (request.command === "close") process.disconnect();
});

process.on("disconnect", () => {
  active?.rejectResume?.(new Error("IPC disconnected"));
});

await send({ type: "ready", protocol: PROTOCOL_VERSION });
