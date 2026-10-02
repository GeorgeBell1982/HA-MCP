#!/usr/bin/env node
import { JsonlAudit } from "./audit.js";
import { loadConfig, publicPolicy } from "./config.js";
import { HaRestClient } from "./ha/rest.js";
import { safeMessage } from "./redaction.js";
import { createPhase3OperatorTerminal } from "./phase3/operatorApproval.js";
const command = process.argv[2] ?? "doctor";
let operatorFailureDetails: ((error: unknown) => object) | undefined;
async function main() {
  if (command === "show-policy") return publicPolicy(process.env);
  if (command === "phase3") {
    const {
      parsePhase3OperatorCommand,
      runPhase3OperatorCommand,
      phase3OperatorFailureDetails,
    } = await import("./phase3/operatorRuntime.js");
    operatorFailureDetails = phase3OperatorFailureDetails;
    parsePhase3OperatorCommand(process.argv.slice(3));
    return runPhase3OperatorCommand(
      process.argv.slice(3),
      loadConfig(process.env),
      createPhase3OperatorTerminal(process.stdin, process.stdout),
    );
  }
  const config = loadConfig(process.env);
  const audit = new JsonlAudit(config.auditPath);
  await audit.health();
  if (command === "list-capabilities")
    return {
      restReads: true,
      websocketReads: true,
      configRepository: false,
      git: false,
      mutations: false,
      http: config.mode === "addon" && config.enableHttp,
    };
  if (command === "check-auth" || command === "doctor") {
    const c = await new HaRestClient(config.baseUrl, config.token).config();
    return command === "check-auth"
      ? { ok: true }
      : {
          ok: true,
          mode: config.mode,
          version: c.version,
          audit: "writable",
          mutations: false,
        };
  }
  if (["check-config-path", "check-git", "validate"].includes(command))
    return { ok: false, code: "capability_unavailable", phase: 2 };
  throw new Error("Unknown command");
}
try {
  const result = await main();
  process.stdout.write(JSON.stringify(result) + "\n");
  if (command === "phase3" && result && "ok" in result && result.ok === false)
    process.exitCode = 1;
} catch (e) {
  process.stderr.write(
    JSON.stringify({
      ok: false,
      error:
        command === "phase3"
          ? "Phase 3 operator command failed"
          : safeMessage(e),
      ...(operatorFailureDetails?.(e) ?? {}),
    }) + "\n",
  );
  process.exitCode = 1;
}
