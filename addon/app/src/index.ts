#!/usr/bin/env node
import { JsonlAudit } from "./audit.js";
import { ReadTools } from "./application.js";
import { loadConfig } from "./config.js";
import { HaRestClient } from "./ha/rest.js";
import { deriveWebSocketUrl, HaWebSocketClient } from "./ha/websocket.js";
import { runStdio } from "./transport/mcp.js";
import { readFile } from "node:fs/promises";
import { PairingStore } from "./security/pairing.js";
import { loadPairings, startIngress } from "./ingress.js";
import { startMcpHttps } from "./http.js";
import { ensureTlsIdentity } from "./security/tls.js";
const config = loadConfig(process.env);
const audit = new JsonlAudit(config.auditPath);
await audit.health();
const tools = new ReadTools(
  new HaRestClient(config.baseUrl, config.token),
  new HaWebSocketClient(deriveWebSocketUrl(config.baseUrl), config.token),
  audit,
);
if (config.mode === "addon") {
  const store = new PairingStore(Number(process.env.HA_MAX_CLIENTS ?? 16));
  const pairingPath = process.env.HA_PAIRING_PATH ?? "/data/pairings.json";
  const certPath = process.env.HA_TLS_CERT ?? "/data/tls/server.crt";
  const keyPath = process.env.HA_TLS_KEY ?? "/data/tls/server.key";
  const externalName = (process.env.HA_HTTP_ALLOWED_HOST ?? "").replace(
    /:\d+$/,
    "",
  );
  const san = /^\d{1,3}(\.\d{1,3}){3}$/.test(externalName)
    ? `IP:${externalName}`
    : `DNS:${externalName}`;
  await ensureTlsIdentity({ certPath, keyPath, subjectAltName: san });
  await loadPairings(store, pairingPath);
  await startIngress({
    store,
    path: pairingPath,
    host: "0.0.0.0",
    tls: { certPath, keyPath, subjectAltName: san },
  });
  if (config.enableHttp)
    await startMcpHttps({
      bind: process.env.HA_HTTP_BIND ?? "",
      port: 8443,
      allowedHost: process.env.HA_HTTP_ALLOWED_HOST ?? "",
      tools,
      pairings: store,
      certificate: await readFile(certPath, "utf8"),
      privateKey: await readFile(keyPath, "utf8"),
      maxSessionsPerClient: Number(process.env.HA_MAX_SESSIONS_PER_CLIENT ?? 2),
      addonMode: true,
    });
} else await runStdio(tools);
