#!/usr/bin/env node
import { JsonlAudit } from "./audit.js";
import { loadConfig, publicPolicy } from "./config.js";
import { HaRestClient } from "./ha/rest.js";
import { safeMessage } from "./redaction.js";
const command = process.argv[2] ?? "doctor";
async function main() {
  if (command === "show-policy") return publicPolicy(process.env);
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
  process.stdout.write(JSON.stringify(await main()) + "\n");
} catch (e) {
  process.stderr.write(
    JSON.stringify({ ok: false, error: safeMessage(e) }) + "\n",
  );
  process.exitCode = 1;
}
