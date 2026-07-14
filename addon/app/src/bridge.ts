#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  closeStreamableHttpConnection,
  RemoteSession,
  type RemoteConnectionFactory,
} from "./remoteSession.js";
import { BridgeLifecycle } from "./bridgeLifecycle.js";

async function main() {
  const lifecycle = new BridgeLifecycle({
    stdin: process.stdin,
    process,
    forceExit: (code) => process.exit(code),
  });
  lifecycle.install();
  try {
    const url = process.env.HA_MCP_URL;
    const credentialFile = process.env.HA_MCP_CREDENTIAL_FILE;
    const fingerprint = process.env.HA_MCP_CERT_SHA256?.replace(
      /:/g,
      "",
    ).toLowerCase();
    if (!url?.startsWith("https://") || !credentialFile || !fingerprint)
      throw new Error(
        "Bridge requires HTTPS URL, credential file, and certificate pin",
      );
    if (!/^[0-9a-f]{64}$/.test(fingerprint))
      throw new Error("Certificate pin must be 64 hexadecimal characters");
    const credentialStat = await stat(credentialFile);
    if (process.platform !== "win32" && (credentialStat.mode & 0o077) !== 0)
      throw new Error(
        "Credential file must not be accessible by group or other users",
      );
    const bearer = (
      await readFile(credentialFile, { encoding: "utf8", flag: "r" })
    ).trim();
    // Node fetch does not expose the peer certificate. Refuse unless the operator has
    // supplied a pinned CA certificate whose DER hash is the expected identity.
    const caFile = process.env.HA_MCP_CA_FILE;
    if (!caFile)
      throw new Error("HA_MCP_CA_FILE is required for server identity pinning");
    const ca = await readFile(caFile);
    const actual = createHash("sha256")
      .update(new X509Certificate(ca).raw)
      .digest();
    const expected = Buffer.from(fingerprint, "hex");
    if (expected.length !== actual.length || !timingSafeEqual(actual, expected))
      throw new Error("Pinned certificate fingerprint mismatch");
    if (process.env.NODE_EXTRA_CA_CERTS !== caFile)
      throw new Error(
        "NODE_EXTRA_CA_CERTS must name the pinned CA file before bridge startup",
      );
    const createTransport = (sessionId?: string) =>
      new StreamableHTTPClientTransport(new URL(url), {
        requestInit: { headers: { Authorization: `Bearer ${bearer}` } },
        reconnectionOptions: {
          initialReconnectionDelay: 500,
          maxReconnectionDelay: 5000,
          reconnectionDelayGrowFactor: 2,
          maxRetries: 3,
        },
        ...(sessionId ? { sessionId } : {}),
      });
    const remoteFactory: RemoteConnectionFactory<Client> = () => {
      const transport = createTransport();
      const client = new Client({
        name: "ha-engineering-bridge",
        version: "0.1.0",
      });
      return {
        client,
        transport,
        connect: () => client.connect(transport as unknown as Transport),
        close: () =>
          closeStreamableHttpConnection(client, transport, createTransport),
      };
    };
    const remote = await RemoteSession.connect(remoteFactory);
    lifecycle.attachRemote(remote);
    if (lifecycle.isShuttingDown) return lifecycle.done;
    const local = new Server(
      { name: "ha-engineering-bridge", version: "0.1.0" },
      { capabilities: { tools: {} } },
    );
    local.setRequestHandler(ListToolsRequestSchema, async () =>
      remote.run((client) => client.listTools()),
    );
    local.setRequestHandler(CallToolRequestSchema, async (request) =>
      remote.run((client) => client.callTool(request.params)),
    );
    const localTransport = new StdioServerTransport();
    await local.connect(localTransport);
    lifecycle.attachLocal(local, localTransport);
    if (lifecycle.isShuttingDown) return lifecycle.done;
  } finally {
    lifecycle.startupFinished();
  }
  await lifecycle.done;
}
await main();
