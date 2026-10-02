#!/usr/bin/env node
// Disposable Linux amd64 acceptance only. Approval issuance is a fixture;
// interactive operator approval has separate acceptance coverage.
import { spawn, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { once } from "node:events";
import { createServer, request as httpRequest } from "node:http";
import { connect } from "node:net";
import { join } from "node:path";
import { loadConfig } from "../../dist/config.js";
import {
  NativeOpenat2Catalog,
  RepositoryCursorCodec,
} from "../../dist/repository/repositoryReads.js";
import {
  NativeOpenat2Reader,
  ProtectedIdentityRegistry,
} from "../../dist/security/repositoryBoundary.js";
import { ProductionSecretValueProvider } from "../../dist/phase2Activation.js";
import { RepositoryResourceService } from "../../dist/repository/resourceProjection.js";
import { ProtectedProposalStore } from "../../dist/proposals/storage.js";
import { ProposalService } from "../../dist/proposals/proposalService.js";
import { Phase2AuditAdapter } from "../../dist/proposals/phase2Audit.js";
import { ProposalCursorCodec } from "../../dist/proposals/cursor.js";
import { ProtectedPhase3ProposalAdapter } from "../../dist/phase3/proposalAdapter.js";
import { ProtectedPhase3SourceAdapter } from "../../dist/phase3/sourceAdapter.js";
import { NativePhase3AtomicApply } from "../../dist/phase3/atomicApply.js";
import {
  Phase3ApplyCoordinator,
  GuardedPhase3PolicyPort,
} from "../../dist/phase3/applyCoordinator.js";
import { Phase3ResourceLocks } from "../../dist/phase3/resourceLocks.js";
import {
  AutomationPhase3AdmissionPolicy,
  AutomationPhase3ReloadCatalog,
  NarrowPhase3ReloadAdapter,
} from "../../dist/phase3/reloadAdapter.js";
import { NarrowPhase3VerificationAdapter } from "../../dist/phase3/verificationAdapter.js";
import { HomeAssistantAutomationBoundary } from "../../dist/phase3/automationHaBoundary.js";
import { HomeAssistantPhase3Client } from "../../dist/phase3/homeAssistantAdapter.js";
import { Phase3OfflineRetention } from "../../dist/phase3/retention.js";
import { acquirePhase3OperatorLease } from "../../dist/phase3/operatorLease.js";
import { sha256 } from "../../dist/phase3/contracts.js";

const root = "/fixture/config";
const state = "/fixture/state";
const ctx = () => ({
  signal: new AbortController().signal,
  deadlineAt: Date.now() + 60_000,
});
const pctx = () => ({
  ...ctx(),
  requestId: randomUUID(),
  operationId: randomUUID(),
});
function assert(value, code) {
  if (!value) throw new Error(code);
}
function row(value) {
  process.stdout.write(`PASSED ${value}\n`);
}
async function leaseEvidence(request) {
  const parent = join(state, "lease-proof");
  mkdirSync(parent, { mode: 0o700 });
  async function holder() {
    const child = spawn(process.execPath, [process.argv[1], "--lease-child"], {
      stdio: ["pipe", "ignore", "ignore", "ipc"],
    });
    const ready = once(child, "message", { signal: AbortSignal.timeout(5000) });
    child.stdin.end(JSON.stringify({ nonce: request.nonce, token: "fixture" }));
    assert((await ready)[0] === "held", "lease_holder_unavailable");
    return child;
  }
  let child = await holder();
  let busy = false;
  try {
    const other = await acquirePhase3OperatorLease(parent);
    await other.release();
  } catch (error) {
    busy = error.code === "operator_busy";
  }
  assert(busy, "lease_not_exclusive_after_helper_exit");
  const released = once(child, "message", {
    signal: AbortSignal.timeout(5000),
  });
  const exited = once(child, "exit", { signal: AbortSignal.timeout(5000) });
  child.send("release");
  assert((await released)[0] === "released", "lease_release_failed");
  await exited;
  let lease = await acquirePhase3OperatorLease(parent);
  await lease.release();
  child = await holder();
  const killed = once(child, "exit", { signal: AbortSignal.timeout(5000) });
  child.kill("SIGKILL");
  assert((await killed)[1] === "SIGKILL", "lease_holder_not_killed");
  lease = await acquirePhase3OperatorLease(parent);
  await lease.release();
  row("native-kernel-lease-helper-exit-contention-release-and-sigkill");
  lease = await acquirePhase3OperatorLease(parent);
  renameSync(join(parent, "operator.lock"), join(parent, "original.lock"));
  writeFileSync(join(parent, "operator.lock"), "", { mode: 0o600 });
  let unsafe = false;
  try {
    await lease.assertHeld();
  } catch (error) {
    unsafe = error.code === "operator_lease_unsafe";
  }
  assert(unsafe, "lease_lock_replacement_unnoticed");
  await lease.release();
  unlinkSync(join(parent, "operator.lock"));
  renameSync(join(parent, "original.lock"), join(parent, "operator.lock"));
  lease = await acquirePhase3OperatorLease(parent);
  renameSync(parent, `${parent}-original`);
  mkdirSync(parent, { mode: 0o700 });
  unsafe = false;
  try {
    await lease.assertHeld();
  } catch (error) {
    unsafe = error.code === "operator_lease_unsafe" || error.code === "ENOENT";
  }
  assert(unsafe, "lease_root_replacement_unnoticed");
  await lease.release();
  rmdirSync(parent);
  renameSync(`${parent}-original`, parent);
  chmodSync(parent, 0o755);
  unsafe = false;
  try {
    const other = await acquirePhase3OperatorLease(parent);
    await other.release();
  } catch (error) {
    unsafe = error.code === "operator_root_unsafe";
  }
  chmodSync(parent, 0o700);
  assert(unsafe, "lease_unsafe_mode_accepted");
  row("native-kernel-lease-lock-root-replacement-and-unsafe-mode-refused");
}
async function actualOperatorEvidence(request) {
  // The builder has musl headers and cc, but no script/Python. This tiny POSIX
  // bridge exercises the unchanged installed wrapper with actual kernel TTYs.
  const source = String.raw`
#define _GNU_SOURCE
#include <pty.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
int main(int argc,char **argv) {
  if(argc<2)return 64;
  int master,status=0,input=1; pid_t pid=forkpty(&master,0,0,0);
  if(pid<0)return 65;
  if(pid==0){execvp(argv[1],argv+1);_exit(66);}
  for(;;){
    fd_set set; FD_ZERO(&set);FD_SET(master,&set);if(input)FD_SET(0,&set);
    struct timeval timeout={1,0};int selected=select(master+1,&set,0,0,&timeout);
    if(selected<0&&errno!=EINTR){kill(pid,SIGKILL);waitpid(pid,&status,0);return 67;}
    char buf[4096];ssize_t n;
    if(selected>0&&input&&FD_ISSET(0,&set)){n=read(0,buf,sizeof(buf));if(n>0){ssize_t off=0;while(off<n){ssize_t w=write(master,buf+off,n-off);if(w<=0)return 68;off+=w;}}else input=0;}
    if(selected>0&&FD_ISSET(master,&set)){n=read(master,buf,sizeof(buf));if(n>0){ssize_t off=0;while(off<n){ssize_t w=write(1,buf+off,n-off);if(w<=0)return 69;off+=w;}}else {waitpid(pid,&status,0);break;}}
    if(waitpid(pid,&status,WNOHANG)==pid){while((n=read(master,buf,sizeof(buf)))>0){if(write(1,buf,n)!=n)return 70;}break;}
  }
  close(master);return WIFEXITED(status)?WEXITSTATUS(status):71;
}`;
  writeFileSync("/build/native/fixture-pty.c", source, { mode: 0o600 });
  const compiled = spawnSync(
    "cc",
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "/build/native/fixture-pty.c",
      "-o",
      "/build/native/fixture-pty",
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert(compiled.status === 0, "fixture_pty_compile_failed");
  const connections = new Set();
  const proxy = createServer((incoming, outgoing) => {
    if (!incoming.url?.startsWith("/core/api")) {
      outgoing.writeHead(404);
      outgoing.end();
      return;
    }
    const upstream = httpRequest(
      {
        host: "127.0.0.1",
        port: 8123,
        path: incoming.url.replace(/^\/core\/api/, "/api"),
        method: incoming.method,
        headers: incoming.headers,
        agent: false,
      },
      (response) => {
        outgoing.writeHead(response.statusCode ?? 502, response.headers);
        response.pipe(outgoing);
      },
    );
    upstream.on("error", () => {
      outgoing.writeHead(502);
      outgoing.end();
    });
    incoming.pipe(upstream);
  });
  proxy.on("connection", (socket) => {
    connections.add(socket);
    socket.on("close", () => connections.delete(socket));
  });
  proxy.on("upgrade", (incoming, downstream, head) => {
    if (incoming.url !== "/core/websocket") {
      downstream.destroy();
      return;
    }
    const upstream = connect(8123, "127.0.0.1", () => {
      upstream.write(
        `GET /api/websocket HTTP/1.1\r\n${incoming.rawHeaders.reduce((text, value, index, array) => (index % 2 === 0 ? `${text}${value}: ${array[index + 1]}\r\n` : text), "")}\r\n`,
      );
      if (head.length) upstream.write(head);
      downstream.pipe(upstream);
      upstream.pipe(downstream);
    });
    upstream.on("error", () => downstream.destroy());
    downstream.on("error", () => upstream.destroy());
    downstream.on("close", () => upstream.destroy());
  });
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(80, "127.0.0.1", resolve);
  });
  const env = { ...process.env, SUPERVISOR_TOKEN: request.token };
  async function command(args, confirmation = true) {
    const child = spawn(
      "/build/native/fixture-pty",
      ["/app/phase3-operator", ...args],
      { env, stdio: ["pipe", "pipe", "pipe"] },
    );
    let output = "",
      answered = false;
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    const consume = (part) => {
      output += part.toString("utf8");
      if (output.length > 65_536) {
        child.kill("SIGKILL");
        return;
      }
      const prompt = /Type exactly ([^\r\n]+)[\r\n]+> /u.exec(output);
      if (confirmation && !answered && prompt) {
        answered = true;
        child.stdin.write(`${prompt[1]}\n`);
      }
    };
    child.stdout.on("data", consume);
    child.stderr.on("data", consume);
    const [status] = await once(child, "exit");
    clearTimeout(timer);
    child.stdin.destroy();
    const lines = output.replace(/\r/g, "").split("\n");
    let result;
    for (const line of lines) {
      try {
        const item = JSON.parse(line);
        if (item && typeof item.ok === "boolean") result = item;
      } catch {
        /* terminal display */
      }
    }
    assert(result !== undefined, "actual_operator_result_missing");
    return { status, result, answered };
  }
  try {
    chmodSync("/data", 0o755);
    const init = await command(["init"]);
    assert(
      init.status === 0 &&
        init.result.ok &&
        init.result.writesEnabled === false,
      "actual_operator_init_failed",
    );
    assert(
      readFileSync("/data/phase3/approval.key").length === 32,
      "actual_operator_key_missing",
    );
    row("actual-wrapper-init-public-data-root-private-state");
    const piped = spawnSync("/app/phase3-operator", ["init"], {
      env,
      encoding: "utf8",
      timeout: 10_000,
    });
    assert(
      piped.status !== 0 &&
        JSON.parse(piped.stderr).code === "interactive_terminal_required",
      "actual_non_tty_accepted",
    );
    const bypass = await command(["init", "--yes"]);
    assert(
      bypass.status !== 0 &&
        bypass.result.code === "invalid_command_or_writes_disabled",
      "actual_yes_accepted",
    );
    row("actual-wrapper-non-tty-and-yes-refused");
    mkdirSync("/data/phase2", { mode: 0o700 });
    const catalog = new NativeOpenat2Catalog({
      helperPath: "/app/native/openat2-list",
      root: "/homeassistant",
      maximumConcurrentHelpers: 1,
    });
    const reader = new NativeOpenat2Reader({
      helperPath: "/app/native/openat2-read",
      root: "/homeassistant",
      maximumConcurrentHelpers: 1,
    });
    const registry = new ProtectedIdentityRegistry(reader);
    await registry.initialize(
      ["secrets.yaml"],
      new ProductionSecretValueProvider(),
      pctx(),
    );
    const store = new ProtectedProposalStore("/data/phase2/proposals");
    const producer = new ProposalService(
      store,
      new Phase2AuditAdapter("/data/phase2/audit/phase2.jsonl"),
      registry,
      catalog,
      new ProposalCursorCodec(Buffer.alloc(32, 10), Buffer.alloc(32, 11)),
    );
    await producer.initialize();
    async function propose(alias) {
      const before = readFileSync("/homeassistant/automations.yaml");
      return producer.propose(
        {
          path: "automations.yaml",
          expectedSha256: sha256(before),
          proposedContent: before
            .toString()
            .replace(/alias:.*\n/, `alias: ${alias}\n`),
          idempotencyKey: randomUUID(),
        },
        pctx(),
      );
    }
    const first = await propose("Disposable actual wrapper first");
    const applied = await command([
      "apply-proposal",
      first.proposalId,
      "--enable-writes",
    ]);
    assert(
      applied.status === 0 &&
        applied.answered &&
        applied.result.state === "verification_succeeded",
      "actual_operator_apply_failed",
    );
    row("actual-wrapper-pty-confirmed-producer-apply-real-ha-proof");
    const second = await propose("Disposable actual wrapper second");
    const blocked = await command([
      "apply-proposal",
      second.proposalId,
      "--enable-writes",
    ]);
    assert(
      blocked.status !== 0 &&
        !blocked.answered &&
        blocked.result.code === "epoch_rotation_required",
      "actual_epoch_reuse_accepted",
    );
    const rotated = await command(["rotate"]);
    assert(
      rotated.status === 0 && rotated.result.ok,
      "actual_operator_rotation_failed",
    );
    const reapplied = await command([
      "apply-proposal",
      second.proposalId,
      "--enable-writes",
    ]);
    assert(
      reapplied.status === 0 &&
        reapplied.answered &&
        reapplied.result.state === "verification_succeeded",
      "actual_next_epoch_apply_failed",
    );
    row("actual-wrapper-blocks-epoch-reuse-rotates-and-applies-next-proposal");
    const recovery = await command(["recover", "--enable-writes"]);
    assert(
      recovery.status === 0 && recovery.answered && recovery.result.ok,
      "actual_operator_recovery_failed",
    );
    const audited = readFileSync(
      "/data/phase3-runtime/active/operator.jsonl",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const appliedAudit = audited.find((record) => record.event === "settled");
    const recoveryAudit = audited.filter((record) =>
      record.event.startsWith("recovery_"),
    );
    assert(
      recoveryAudit.map((record) => record.event).join(",") ===
        "recovery_attempt,recovery_displayed,recovery_confirmed,recovery_settled" &&
        new Set(recoveryAudit.map((record) => record.attemptId)).size === 1 &&
        recoveryAudit
          .slice(1)
          .every(
            (record) =>
              record.displayedSha256 === recoveryAudit[1].displayedSha256,
          ) &&
        appliedAudit?.proposalId === second.proposalId &&
        appliedAudit.state === "verification_succeeded",
      "actual_operator_audit_evidence_missing",
    );
    const fixedLease = await acquirePhase3OperatorLease("/data/phase3-runtime");
    const fixedKey = readFileSync("/data/phase3/approval.key");
    try {
      const fixedEpoch = await new Phase3OfflineRetention(
        "/data/phase3-runtime",
        fixedKey,
      ).open(fixedLease);
      try {
        const records = await fixedEpoch.journal.listRecoverable();
        const snapshot = await new ProtectedPhase3ProposalAdapter(store).load(
          second.proposalId,
        );
        assert(
          records.length === 1 &&
            records[0].approvalGrantId === appliedAudit.grantId &&
            appliedAudit.proposalStorageSha256 ===
              snapshot.proposalStorageSha256,
          "actual_operator_audit_journal_binding_missing",
        );
      } finally {
        await fixedEpoch.approvals.close();
      }
    } finally {
      fixedKey.fill(0);
      await fixedLease.release();
    }
    row("actual-wrapper-pty-confirmed-recovery-and-audit");
    renameSync(
      "/data/phase3/approval.key",
      "/data/phase3/fixture-original-key",
    );
    try {
      const repeated = await command(["init"]);
      assert(
        repeated.status !== 0 &&
          repeated.result.code === "bootstrap_state_not_fresh",
        "actual_reinit_accepted",
      );
      let missing = false;
      try {
        readFileSync("/data/phase3/approval.key");
      } catch (error) {
        missing = error.code === "ENOENT";
      }
      assert(missing, "actual_reinit_replaced_key");
    } finally {
      renameSync(
        "/data/phase3/fixture-original-key",
        "/data/phase3/approval.key",
      );
    }
    row(
      "actual-wrapper-existing-epoch-missing-key-refuses-without-replacement",
    );
    producer.close();
  } finally {
    for (const socket of connections) socket.destroy();
    await new Promise((resolve) => proxy.close(resolve));
  }
}
async function readonlyOperatorEvidence(request) {
  function stateDigest(path) {
    const entries = readdirSync(path, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    return sha256(
      Buffer.from(
        JSON.stringify(
          entries.map((entry) => [
            entry.name,
            entry.isDirectory()
              ? stateDigest(join(path, entry.name))
              : sha256(readFileSync(join(path, entry.name))),
          ]),
        ),
      ),
    );
  }
  const before = stateDigest("/data/phase3-runtime");
  const sourceBefore = sha256(readFileSync("/homeassistant/automations.yaml"));
  for (const args of [
    ["apply-proposal", randomUUID(), "--enable-writes"],
    ["recover", "--enable-writes"],
  ]) {
    const child = spawn(
      "/build/native/fixture-pty",
      ["/app/phase3-operator", ...args],
      {
        env: { ...process.env, SUPERVISOR_TOKEN: request.token },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let output = "";
    child.stdout.on("data", (part) => {
      output += part.toString();
      if (output.length > 16_384) child.kill("SIGKILL");
    });
    child.stderr.on("data", (part) => {
      output += part.toString();
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
    const [status] = await once(child, "exit");
    clearTimeout(timer);
    child.stdin.destroy();
    const result = JSON.parse(output.trim());
    assert(
      status !== 0 && result.code === "operator_repository_read_only",
      "actual_readonly_mount_not_refused",
    );
  }
  assert(
    stateDigest("/data/phase3-runtime") === before &&
      sha256(readFileSync("/homeassistant/automations.yaml")) === sourceBefore,
    "actual_readonly_refusal_had_effect",
  );
  row(
    "actual-wrapper-readonly-mount-refuses-apply-and-recovery-before-grant-or-audit",
  );
}
let request;
try {
  const input = readFileSync(0, "utf8");
  assert(input.length < 16_384, "fixture_input_invalid");
  request = JSON.parse(input);
  assert(
    /^[a-f0-9]{64}$/.test(request.nonce) && typeof request.token === "string",
    "fixture_input_invalid",
  );
  assert(
    readFileSync(join(root, ".codex-fixture"), "utf8") === request.nonce &&
      readFileSync(join(state, ".codex-fixture"), "utf8") === request.nonce,
    "fixture_ownership_invalid",
  );
  if (process.argv[2] === "--readonly-child") {
    await readonlyOperatorEvidence(request);
    process.exit(0);
  }
  if (process.argv[2] === "--lease-child") {
    const lease = await acquirePhase3OperatorLease(join(state, "lease-proof"));
    process.send("held");
    process.once("message", async (message) => {
      assert(message === "release", "lease_child_message_invalid");
      await lease.release();
      process.send("released", () => process.disconnect());
    });
    await once(process, "disconnect");
    process.exit(0);
  }
  if (process.argv[2] !== "--crash-child") await leaseEvidence(request);
  const baseline = readFileSync(join(root, "automations.yaml"));
  const config = loadConfig({
    HA_BASE_URL: "http://127.0.0.1:8123",
    HA_ACCESS_TOKEN: request.token,
  });
  const catalog = new NativeOpenat2Catalog({
    helperPath: "/build/native/openat2-list",
    root,
    maximumConcurrentHelpers: 1,
  });
  const reader = new NativeOpenat2Reader({
    helperPath: "/build/native/openat2-read",
    root,
    maximumConcurrentHelpers: 1,
  });
  const registry = new ProtectedIdentityRegistry(reader);
  await registry.initialize(
    ["secrets.yaml"],
    new ProductionSecretValueProvider(),
    pctx(),
  );
  const source = new ProtectedPhase3SourceAdapter(catalog, registry);
  const resources = new RepositoryResourceService(
    catalog,
    reader,
    registry,
    new RepositoryCursorCodec(Buffer.alloc(32, 7)),
  );
  const store = new ProtectedProposalStore(join(state, "proposals"));
  const producer = new ProposalService(
    store,
    new Phase2AuditAdapter(join(state, "audit", "phase2.jsonl")),
    registry,
    catalog,
    new ProposalCursorCodec(Buffer.alloc(32, 8), Buffer.alloc(32, 9)),
  );
  await producer.initialize();
  const proposals = new ProtectedPhase3ProposalAdapter(store);
  const boundary = new HomeAssistantAutomationBoundary(config, source);
  const http = new HomeAssistantPhase3Client(config);
  const atomic = new NativePhase3AtomicApply({
    root,
    helperPath: "/build/native/openat2-replace",
    maxConcurrent: 1,
    maxWaiters: 1,
    terminationGraceMs: 250,
  });
  const parent = join(state, "epochs");
  const crashChild = process.argv[2] === "--crash-child";
  if (!crashChild) mkdirSync(parent, { mode: 0o700 });
  const key = crashChild
    ? readFileSync(join(state, "fixture.key"))
    : randomBytes(32);
  if (!crashChild)
    writeFileSync(join(state, "fixture.key"), key, { mode: 0o600 });
  const lease = await acquirePhase3OperatorLease(parent);
  const retention = new Phase3OfflineRetention(parent, key);
  let epoch = crashChild
    ? await retention.open(lease)
    : await retention.initialize(lease);
  function coordinator(stores, mode = "success") {
    let injected = false;
    const reload = new NarrowPhase3ReloadAdapter(
      new AutomationPhase3ReloadCatalog(resources),
      {
        async reload(target, context) {
          const actual = await http.reload(target, context);
          if (
            mode === "reload_unknown" &&
            !injected &&
            actual.status === "completed"
          ) {
            injected = true;
            return Object.freeze({ status: "outcome_unknown" });
          }
          return actual;
        },
      },
    );
    const verification = new NarrowPhase3VerificationAdapter(source, {
      async probe(probe, context) {
        if (
          mode === "probe_failure" &&
          !injected &&
          probe.outcome === "candidate"
        ) {
          injected = true;
          throw new Error("fixture_probe_failure");
        }
        return boundary.probe(probe, context);
      },
    });
    const atomicApply =
      mode === "crash"
        ? {
            async replace(input, context) {
              const result = await atomic.replace(input, context);
              assert(result.status === "committed", "native_commit_failed");
              process.kill(process.pid, "SIGKILL");
              await new Promise(() => {});
            },
          }
        : atomic;
    return new Phase3ApplyCoordinator({
      proposals,
      policy: new AutomationPhase3AdmissionPolicy(
        new GuardedPhase3PolicyPort({
          writesEnabled: true,
          applyCapability: true,
          domainReloadCapability: true,
        }),
        resources,
      ),
      approvals: stores.approvals,
      locks: new Phase3ResourceLocks(),
      source,
      validation: boundary,
      checkpoints: stores.checkpoints,
      atomicApply,
      reload,
      verification,
      journal: stores.journal,
    });
  }
  if (crashChild) {
    await coordinator(epoch, "crash").apply(request.interrupted, ctx());
    throw new Error("crash_not_reached");
  }
  async function proposal(text) {
    const created = await producer.propose(
      {
        path: "automations.yaml",
        expectedSha256: sha256(readFileSync(join(root, "automations.yaml"))),
        proposedContent: text,
        idempotencyKey: randomUUID(),
      },
      pctx(),
    );
    assert(
      created.reloadImpact === "domain_reload" &&
        created.reloadTarget === "automation.reload",
      "real_producer_classification_failed",
    );
    const snapshot = await proposals.load(created.proposalId);
    const grant = await epoch.approvals.issueApplyGrant(snapshot, {
      now: Date.now(),
      signal: new AbortController().signal,
    });
    return { proposalId: created.proposalId, grantId: grant.grantId };
  }
  for (const mode of ["success", "reload_unknown", "probe_failure"]) {
    const before = readFileSync(join(root, "automations.yaml"));
    const input = await proposal(
      before
        .toString()
        .replace(/alias:.*\n/, `alias: Disposable native ${mode}\n`),
    );
    const result = await coordinator(epoch, mode).apply(input, ctx());
    assert(result.approvalGrantId === input.grantId, "approval_link_missing");
    assert(
      result.state ===
        (mode === "success"
          ? "verification_succeeded"
          : "rollback_verification_succeeded"),
      "terminal_state_incorrect",
    );
    if (mode !== "success")
      assert(
        sha256(readFileSync(join(root, "automations.yaml"))) === sha256(before),
        "rollback_bytes_incorrect",
      );
    row(`native-real-ha-${mode}`);
    await epoch.approvals.close();
    const archive = await retention.rotate(lease, async (stores) =>
      coordinator(stores).recover(),
    );
    assert(archive.includes("archive-"), "archive_missing");
    epoch = await retention.open(lease);
    assert(
      (await epoch.journal.listRecoverable()).length === 0,
      "epoch_not_empty",
    );
    row(`native-retention-${mode}-archive-and-fresh-epoch`);
  }
  const beforeInvalid = readFileSync(join(root, "automations.yaml"));
  const invalidInput = await proposal(
    beforeInvalid
      .toString()
      .replace("trigger: event", "trigger: codex_nonexistent_trigger"),
  );
  let rejected = false;
  try {
    await coordinator(epoch).apply(invalidInput, ctx());
  } catch (error) {
    rejected = error.code === "ha_automation_invalid";
  }
  assert(
    rejected &&
      sha256(readFileSync(join(root, "automations.yaml"))) ===
        sha256(beforeInvalid) &&
      (await epoch.journal.listRecoverable()).length === 0,
    "invalid_candidate_effect",
  );
  row("native-real-ha-invalid-component-before-effect");
  // The crash child opens the exact persisted epoch and proposal. Its atomic
  // adapter sends SIGKILL to itself after the native helper's durable rename.
  const interrupted = await proposal(
    beforeInvalid
      .toString()
      .replace(/alias:.*\n/, "alias: Disposable interrupted native\n"),
  );
  await epoch.approvals.close();
  await lease.release();
  const child = spawnSync(
    process.execPath,
    [process.argv[1], "--crash-child"],
    {
      input: JSON.stringify({ ...request, interrupted }),
      encoding: "utf8",
      timeout: 90_000,
      maxBuffer: 16_384,
    },
  );
  assert(child.signal === "SIGKILL", "real_process_interrupt_missing");
  const recoveredLease = await acquirePhase3OperatorLease(parent);
  epoch = await retention.open(recoveredLease);
  const pending = await epoch.journal.listRecoverable();
  assert(
    pending.length === 1 && pending[0].state === "intent_prepared",
    "crash_window_unproved",
  );
  assert(
    pending[0].approvalGrantId === interrupted.grantId &&
      sha256(readFileSync(join(root, "automations.yaml"))) ===
        pending[0].candidateSha256 &&
      pending[0].checkpointSha256 === sha256(beforeInvalid),
    "crash_effect_binding_unproved",
  );
  const recovered = await coordinator(epoch).recover();
  assert(
    recovered.length === 1 &&
      ["verified", "rolled_back"].includes(recovered[0].disposition),
    "restart_recovery_failed",
  );
  row("native-real-ha-sigkill-after-rename-and-fresh-process-recovery");
  await epoch.approvals.close();
  await recoveredLease.release();
  await actualOperatorEvidence(request);
  baseline.fill(0);
  key.fill(0);
} catch (error) {
  process.stderr.write(
    `FAILED ${typeof error?.code === "string" && /^[a-z_]+$/.test(error.code) ? error.code : /^[a-z_]+$/.test(error?.message ?? "") ? error.message : "native_workflow_failed"}\n`,
  );
  process.exitCode = 1;
}
