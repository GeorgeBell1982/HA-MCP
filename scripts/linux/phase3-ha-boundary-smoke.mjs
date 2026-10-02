#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { setTimeout as pause } from "node:timers/promises";
import { loadConfig } from "../../dist/config.js";
import { HomeAssistantPhase3Client } from "../../dist/phase3/homeAssistantAdapter.js";
import { HomeAssistantAutomationBoundary } from "../../dist/phase3/automationHaBoundary.js";
import { sha256 } from "../../dist/phase3/contracts.js";
import {
  assertExactRows,
  boundaryRows,
  mainWorkerRows,
  readonlyWorkerRows,
  parseWorkerRows,
} from "./phase3-ha-evidence.mjs";

// Docker-only fixture. Never accepts an endpoint, credential, host directory or
// production container. Temporary credentials remain in memory and are destroyed
// with the owned volume. Native evidence requires the explicit full option.
const fullWorkflow =
  process.argv.slice(2).join(" ") ===
  "--ack-disposable-ha-boundary-smoke --full-workflow";
if (
  !fullWorkflow &&
  process.argv.slice(2).join(" ") !== "--ack-disposable-ha-boundary-smoke"
) {
  process.stderr.write("Required: --ack-disposable-ha-boundary-smoke\n");
  process.exit(64);
}
const image =
  "ghcr.io/home-assistant/home-assistant@sha256:e47c978e1b801466e7f62f612fd552bc3a228e077b31a3f1c22c05cf63d754da";
const name = `codex-ha-boundary-${randomUUID()}`;
const volume = `${name}-config`;
const workerName = `${name}-worker`;
const readonlyName = `${name}-readonly`;
const stateVolume = `${name}-state`;
const nonce = randomBytes(32).toString("hex");
const builder =
  "sha256:1c489404380cadf3a66d3440da070ce35ca3669cb8c8c9b56ee960834e236c04";
const original = Buffer.from(
  "- id: codex_disposable_proof\n  alias: Disposable proof\n  triggers:\n    - trigger: event\n      event_type: codex_disposable_never_fired\n  conditions: []\n  actions:\n    - delay: 0\n",
);
const candidate = Buffer.from(
  original.toString().replace("Disposable proof", "Updated disposable proof"),
);
let bytes = original;
let failed = false;
const evidenceRows = [];
function docker(...args) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 2_000_000,
    windowsHide: true,
  });
  if (result.status !== 0 || result.error)
    throw new Error("docker_operation_failed");
  return result.stdout.trim();
}
function context() {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 30_000,
  };
}
function row(name) {
  evidenceRows.push(name);
  process.stdout.write(`PASSED ${name}\n`);
}
async function json(base, path, body) {
  const response = await fetch(new URL(path, base), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
  });
  if (!response.ok) throw new Error("fixture_auth_failed");
  return response.json();
}
function install(next) {
  docker(
    "exec",
    name,
    "python",
    "-c",
    "from pathlib import Path; import sys; Path('/config/automations.yaml').write_text(sys.argv[1])",
    next.toString(),
  );
  bytes = next;
}
try {
  // Inspect requires locally available exact images; no implicit pull or tag
  // upgrade can enter this evidence run.
  docker("image", "inspect", image);
  if (fullWorkflow) docker("image", "inspect", builder);
  docker("volume", "create", volume);
  const setup =
    "from pathlib import Path; import sys; Path('/config/configuration.yaml').write_text(sys.argv[1]); Path('/config/automations.yaml').write_text(sys.argv[2]); Path('/config/secrets.yaml').write_text('{}\\n'); Path('/config/.codex-fixture').write_text(sys.argv[3])";
  docker(
    "run",
    "--rm",
    "--volume",
    `${volume}:/config`,
    "--entrypoint",
    "python",
    image,
    "-c",
    setup,
    "homeassistant:\n  name: Disposable Phase 3\nhttp:\napi:\nconfig:\nfrontend:\nonboarding:\nautomation: !include automations.yaml\n",
    original.toString(),
    nonce,
  );
  docker(
    "create",
    "--name",
    name,
    "--publish",
    "127.0.0.1::8123",
    "--volume",
    `${volume}:/config`,
    image,
  );
  docker("start", name);
  const port = docker("port", name, "8123");
  const match = /^127\.0\.0\.1:(\d+)$/u.exec(port);
  if (!match) throw new Error("fixture_port_invalid");
  const base = `http://127.0.0.1:${match[1]}`;
  const readyUntil = Date.now() + 120_000;
  let ready = false;
  while (Date.now() < readyUntil) {
    try {
      const result = await fetch(`${base}/api/onboarding`, {
        signal: AbortSignal.timeout(2_000),
      });
      ready = result.ok;
      await result.body?.cancel();
      if (ready) break;
    } catch {
      /* startup */
    }
    await pause(500);
  }
  if (!ready) throw new Error("fixture_startup_failed");
  const clientId = `${base}/`;
  const onboarding = await json(base, "/api/onboarding/users", {
    name: "Disposable operator",
    username: randomUUID(),
    password: randomBytes(32).toString("hex"),
    client_id: clientId,
    language: "en",
  });
  const tokenResponse = await fetch(`${base}/auth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: onboarding.auth_code,
      client_id: clientId,
    }),
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
  });
  if (!tokenResponse.ok) throw new Error("fixture_token_failed");
  const token = await tokenResponse.json();
  const config = loadConfig({
    HA_BASE_URL: base,
    HA_ACCESS_TOKEN: token.access_token,
  });
  const source = {
    async read() {
      return { bytes: Buffer.from(bytes), sha256: sha256(bytes) };
    },
  };
  const boundary = new HomeAssistantAutomationBoundary(config, source);
  const http = new HomeAssistantPhase3Client(config);
  const versionResponse = await fetch(`${base}/api/config`, {
    headers: { Authorization: `Bearer ${token.access_token}` },
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
  });
  if (
    !versionResponse.ok ||
    (await versionResponse.json()).version !== "2026.9.4"
  )
    throw new Error("fixture_core_version_mismatch");
  row("owned-ha-2026.9.4-startup");
  await boundary.validate(original, "checkpoint_pre_apply", context());
  await boundary.validate(candidate, "candidate_pre_apply", context());
  row("candidate-and-checkpoint-components-valid");
  const invalid = Buffer.from(
    candidate
      .toString()
      .replace("trigger: event", "trigger: codex_nonexistent_trigger"),
  );
  let rejected = false;
  try {
    await boundary.validate(invalid, "candidate_pre_apply", context());
  } catch (error) {
    rejected = error.code === "ha_automation_invalid";
  }
  if (!rejected) throw new Error("semantic_rejection_missing");
  row("invalid-ha-trigger-rejected-before-effect");
  install(candidate);
  await boundary.validate(candidate, "candidate_post_apply", context());
  if (
    (await http.reload("automation.reload", context())).status !== "completed"
  )
    throw new Error("reload_incomplete");
  const request = {
    transactionId: randomUUID(),
    path: "automations.yaml",
    outcome: "candidate",
    expectedSha256: sha256(candidate),
    impact: "domain_reload",
    reloadTarget: "automation.reload",
    rollbackReloadRequired: false,
  };
  await boundary.probe(request, context());
  row("reload-and-exact-loaded-config-verified");
  install(original);
  let mismatch = false;
  try {
    await boundary.probe(
      { ...request, expectedSha256: sha256(original) },
      context(),
    );
  } catch (error) {
    mismatch = error.code === "ha_loaded_config_mismatch";
  }
  if (!mismatch) throw new Error("loaded_drift_rejection_missing");
  row("installed-but-not-reloaded-config-rejected");
  await boundary.validate(original, "checkpoint_post_rollback", context());
  if (
    (await http.reload("automation.reload", context())).status !== "completed"
  )
    throw new Error("rollback_reload_incomplete");
  await boundary.probe(
    {
      ...request,
      outcome: "checkpoint",
      expectedSha256: sha256(original),
      rollbackReloadRequired: true,
    },
    context(),
  );
  row("restored-checkpoint-reloaded-and-verified");
  if (fullWorkflow) {
    docker("volume", "create", stateVolume);
    docker(
      "create",
      "--name",
      workerName,
      "--network",
      `container:${name}`,
      "--volume",
      `${volume}:/fixture/config`,
      "--volume",
      `${volume}:/homeassistant`,
      "--volume",
      `${stateVolume}:/fixture/state`,
      "--volume",
      `${stateVolume}:/data`,
      "--entrypoint",
      "/bin/sh",
      builder,
      "-c",
      "sleep 900",
    );
    docker("start", workerName);
    docker(
      "exec",
      workerName,
      "node",
      "-e",
      "const fs=require('fs');fs.chmodSync('/fixture/state',0o700);fs.writeFileSync('/fixture/state/.codex-fixture',process.argv[1],{mode:0o600});fs.mkdirSync('/build/scripts/linux',{recursive:true});",
      nonce,
    );
    docker("cp", "dist/.", `${workerName}:/build/dist`);
    docker(
      "exec",
      workerName,
      "node",
      "-e",
      "const fs=require('fs');fs.mkdirSync('/app/native',{recursive:true});fs.mkdirSync('/app/dist',{recursive:true});fs.symlinkSync('/build/node_modules','/app/node_modules');fs.appendFileSync('/etc/hosts','\\n127.0.0.1 supervisor\\n');",
    );
    docker("cp", "dist/.", `${workerName}:/app/dist`);
    docker(
      "cp",
      "addon/phase3-operator.sh",
      `${workerName}:/app/phase3-operator`,
    );
    docker("exec", workerName, "chmod", "0555", "/app/phase3-operator");
    docker(
      "cp",
      "scripts/linux/phase3-ha-workflow-worker.mjs",
      `${workerName}:/build/scripts/linux/phase3-ha-workflow-worker.mjs`,
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
    for (const [source, target] of [
      ["src/security/native/openat2-read.c", "openat2-read"],
      ["src/repository/native/openat2-list.c", "openat2-list"],
      ["src/phase3/native/openat2-replace.c", "openat2-replace"],
    ]) {
      docker("cp", source, `${workerName}:/build/native/${target}.c`);
      docker(
        "exec",
        workerName,
        "cc",
        ...flags,
        `/build/native/${target}.c`,
        ...(target === "openat2-replace" ? ["-l:libcrypto.so.3"] : []),
        "-o",
        `/build/native/${target}`,
      );
      docker(
        "exec",
        workerName,
        "cp",
        `/build/native/${target}`,
        `/app/native/${target}`,
      );
    }
    const result = spawnSync(
      "docker",
      [
        "exec",
        "-i",
        workerName,
        "node",
        "/build/scripts/linux/phase3-ha-workflow-worker.mjs",
      ],
      {
        input: JSON.stringify({ nonce, token: token.access_token }),
        encoding: "utf8",
        timeout: 180_000,
        maxBuffer: 32_768,
        windowsHide: true,
      },
    );
    // Workers only emit closed, credential-free status rows. Never print an
    // unexpected child diagnostic, Docker output, input, or HA response.
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    for (const name of parseWorkerRows(output, mainWorkerRows)) row(name);
    if (result.status !== 0 || result.error)
      throw new Error("native_workflow_failed");
    docker(
      "create",
      "--name",
      readonlyName,
      "--network",
      `container:${name}`,
      "--volume",
      `${volume}:/fixture/config:ro`,
      "--volume",
      `${volume}:/homeassistant:ro`,
      "--volume",
      `${stateVolume}:/fixture/state`,
      "--volume",
      `${stateVolume}:/data`,
      "--entrypoint",
      "/bin/sh",
      builder,
      "-c",
      "sleep 900",
    );
    docker("start", readonlyName);
    docker("exec", readonlyName, "mkdir", "-p", "/app", "/build/scripts/linux");
    // Docker tar streams move only compiled fixture artifacts between owned
    // containers. No host directories or filesystem snapshots are introduced.
    for (const [from, to] of [
      [`${workerName}:/app/.`, `${readonlyName}:/app`],
      [
        `${workerName}:/build/native/fixture-pty`,
        `${readonlyName}:/build/native`,
      ],
    ]) {
      const packed = spawnSync("docker", ["cp", from, "-"], {
        timeout: 10_000,
        maxBuffer: 16_000_000,
        windowsHide: true,
      });
      if (packed.status !== 0 || packed.error)
        throw new Error("fixture_copy_failed");
      const unpacked = spawnSync("docker", ["cp", "-", to], {
        input: packed.stdout,
        timeout: 10_000,
        maxBuffer: 16_384,
        windowsHide: true,
      });
      if (unpacked.status !== 0 || unpacked.error)
        throw new Error("fixture_copy_failed");
    }
    docker("cp", "dist/.", `${readonlyName}:/build/dist`);
    docker(
      "cp",
      "scripts/linux/phase3-ha-workflow-worker.mjs",
      `${readonlyName}:/build/scripts/linux/phase3-ha-workflow-worker.mjs`,
    );
    const readonlyResult = spawnSync(
      "docker",
      [
        "exec",
        "-i",
        readonlyName,
        "node",
        "/build/scripts/linux/phase3-ha-workflow-worker.mjs",
        "--readonly-child",
      ],
      {
        input: JSON.stringify({ nonce, token: token.access_token }),
        encoding: "utf8",
        timeout: 30_000,
        maxBuffer: 16_384,
        windowsHide: true,
      },
    );
    const readonlyOutput = `${readonlyResult.stdout ?? ""}${readonlyResult.stderr ?? ""}`;
    for (const name of parseWorkerRows(readonlyOutput, readonlyWorkerRows))
      row(name);
    if (readonlyResult.status !== 0 || readonlyResult.error)
      throw new Error("readonly_workflow_failed");
  }
} catch (error) {
  failed = true;
  const safe =
    typeof error?.code === "string" && /^[a-z_]+$/u.test(error.code)
      ? error.code
      : "smoke_failed";
  process.stderr.write(`FAILED ${safe}\n`);
} finally {
  let cleanupFailed = false;
  // A failed client call may still have created a daemon-side resource. Always
  // remove every nonce-owned name; removal errors require affirmative absence.
  for (const args of [
    ["rm", "--force", readonlyName],
    ["rm", "--force", workerName],
    ["rm", "--force", name],
    ["volume", "rm", stateVolume],
    ["volume", "rm", volume],
  ]) {
    try {
      docker(...args);
    } catch {
      // Missing resources are harmless; the successful list below is authority.
    }
  }
  try {
    for (const [args, owned] of [
      [
        ["container", "ls", "--all", "--format", "{{.Names}}"],
        [name, workerName, readonlyName],
      ],
      [
        ["volume", "ls", "--format", "{{.Name}}"],
        [volume, stateVolume],
      ],
    ]) {
      const present = docker(...args).split("\n");
      if (owned.some((entry) => present.includes(entry))) cleanupFailed = true;
    }
  } catch {
    cleanupFailed = true;
  }
  if (cleanupFailed) {
    failed = true;
    process.stderr.write("FAILED fixture_cleanup\n");
  } else row("owned-container-and-volume-removed");
  if (!failed) {
    try {
      assertExactRows(
        evidenceRows,
        fullWorkflow
          ? [...boundaryRows, ...mainWorkerRows, ...readonlyWorkerRows]
          : boundaryRows,
      );
    } catch {
      failed = true;
      process.stderr.write("FAILED workflow_evidence_incomplete\n");
    }
  }
  original.fill(0);
  candidate.fill(0);
}
process.exitCode = failed ? 1 : 0;
