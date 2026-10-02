#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { setTimeout as pause } from "node:timers/promises";
import { loadConfig } from "../../dist/config.js";
import { HomeAssistantPhase3Client } from "../../dist/phase3/homeAssistantAdapter.js";
import { HomeAssistantAutomationBoundary } from "../../dist/phase3/automationHaBoundary.js";
import { sha256 } from "../../dist/phase3/contracts.js";

// Docker-only fixture. Never accepts an endpoint, credential, host directory or
// production container. Temporary credentials remain in memory and are destroyed
// with the owned volume. This does not claim native apply/durability evidence.
if (process.argv.slice(2).join(" ") !== "--ack-disposable-ha-boundary-smoke") {
  process.stderr.write("Required: --ack-disposable-ha-boundary-smoke\n");
  process.exit(64);
}
const image =
  "ghcr.io/home-assistant/home-assistant@sha256:1476924357b46e80735c13e94232ba5c853cac052e9df4bb28d50fa56348097b";
const name = `codex-ha-boundary-${randomUUID()}`;
const volume = `${name}-config`;
const original = Buffer.from(
  "- id: codex_disposable_proof\n  alias: Disposable proof\n  triggers:\n    - trigger: event\n      event_type: codex_disposable_never_fired\n  conditions: []\n  actions:\n    - delay: 0\n",
);
const candidate = Buffer.from(
  original.toString().replace("Disposable proof", "Updated disposable proof"),
);
let bytes = original;
let hasVolume = false;
let hasContainer = false;
let failed = false;
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
  docker("volume", "create", volume);
  hasVolume = true;
  const setup =
    "from pathlib import Path; import sys; Path('/config/configuration.yaml').write_text(sys.argv[1]); Path('/config/automations.yaml').write_text(sys.argv[2])";
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
  hasContainer = true;
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
  row("owned-ha-2026.7.2-startup");
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
} catch (error) {
  failed = true;
  const safe =
    typeof error?.code === "string" && /^[a-z_]+$/u.test(error.code)
      ? error.code
      : "smoke_failed";
  process.stderr.write(`FAILED ${safe}\n`);
} finally {
  try {
    if (hasContainer) docker("rm", "--force", name);
    if (hasVolume) docker("volume", "rm", volume);
    row("owned-container-and-volume-removed");
  } catch {
    failed = true;
    process.stderr.write("FAILED fixture_cleanup\n");
  }
  original.fill(0);
  candidate.fill(0);
}
process.exitCode = failed ? 1 : 0;
