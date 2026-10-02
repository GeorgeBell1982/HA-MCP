#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ElicitRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  closeStreamableHttpConnection,
  RemoteSession,
  type RemoteConnectionFactory,
} from "./remoteSession.js";
import { BridgeLifecycle } from "./bridgeLifecycle.js";

/** A relay is scoped to the one active, serialized originating tool call. */
export class BridgeElicitationRelay {
  private active:
    | { requestId: string | number; signal: AbortSignal }
    | undefined;
  constructor(private readonly local: () => Server | undefined) {}

  attach(client: Client): void {
    client.setRequestHandler(ElicitRequestSchema, async (request, extra) => {
      const local = this.local();
      const active = this.active;
      if (
        !local?.getClientCapabilities()?.elicitation?.form ||
        !active ||
        request.params.mode === "url" ||
        active.signal.aborted ||
        extra.signal.aborted
      )
        throw new Error("approval_unsupported");
      if (Buffer.byteLength(request.params.message, "utf8") > 71_000)
        throw new Error("approval_request_oversized");
      // Direct relay: RemoteSession's queue is already occupied by this call.
      return local.elicitInput(
        { ...request.params, mode: "form" },
        {
          relatedRequestId: active.requestId,
          signal: AbortSignal.any([active.signal, extra.signal]),
          timeout: 120_000,
          maxTotalTimeout: 120_000,
        },
      );
    });
  }

  async within<T>(
    context: { requestId: string | number; signal: AbortSignal },
    operation: () => Promise<T>,
  ): Promise<T> {
    if (this.active) throw new Error("bridge_call_overlap");
    this.active = context;
    try {
      return await operation();
    } finally {
      this.active = undefined;
    }
  }
}

export function bridgeCallMayRetry(
  name: string,
  readOnlyHint?: boolean,
): boolean {
  if (
    name === "ha_apply_proposal" ||
    name === "ha_rotate_epoch" ||
    readOnlyHint === false
  )
    return false;
  if (readOnlyHint === true) return true;
  return historicalReadOnlyTools.has(name);
}

const historicalReadOnlyTools = new Set([
  "ha_get_system_info",
  "ha_list_entities",
  "ha_get_entity_state",
  "ha_search_entities",
  "ha_list_automations",
  "ha_get_automation",
  "ha_list_scripts",
  "ha_get_script",
  "ha_list_helpers",
  "ha_list_dashboards",
  "ha_get_dashboard",
  "ha_list_scenes",
  "ha_list_blueprints",
  "ha_get_config_status",
  "ha_get_recent_errors",
  "ha_list_config_files",
  "ha_read_config_file",
  "ha_search_config",
  "ha_list_config_resources",
  "ha_get_config_resource",
  "ha_get_git_status",
  "ha_get_git_diff",
  "ha_list_proposals",
  "ha_get_pending_diff",
]);

async function main() {
  const lifecycle = new BridgeLifecycle({
    stdin: process.stdin,
    process,
    forceExit: (code) => process.exit(code),
  });
  lifecycle.install();
  let local: Server | undefined;
  const relay = new BridgeElicitationRelay(() => local);
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
      const client = new Client(
        {
          name: "ha-engineering-bridge",
          version: "0.1.0",
        },
        local?.getClientCapabilities()?.elicitation?.form
          ? { capabilities: { elicitation: { form: {} } } }
          : {},
      );
      if (local?.getClientCapabilities()?.elicitation?.form)
        relay.attach(client);
      return {
        client,
        transport,
        connect: () =>
          client.connect(transport as unknown as Transport, {
            signal: remoteShutdown.signal,
          }),
        close: () =>
          closeStreamableHttpConnection(client, transport, createTransport),
      };
    };
    const remoteShutdown = new AbortController();
    let remotePromise: Promise<RemoteSession<Client>> | undefined;
    const getRemote = () => {
      if (lifecycle.isShuttingDown)
        throw new Error("Remote session is closing");
      // First tools request follows local initialization, so upstream capability
      // advertisement reflects this actual host rather than a relay assumption.
      remotePromise ??= RemoteSession.connect(remoteFactory);
      return remotePromise;
    };
    lifecycle.attachRemote({
      close: async () => {
        remoteShutdown.abort();
        const remote = await remotePromise?.catch(() => undefined);
        await remote?.close();
      },
    });
    local = new Server(
      { name: "ha-engineering-bridge", version: "0.1.0" },
      { capabilities: { tools: {} } },
    );
    const readOnlyHints = new Map<string, boolean | undefined>();
    local.setRequestHandler(ListToolsRequestSchema, async () => {
      const remote = await getRemote();
      const result = await remote.run((client) => client.listTools());
      for (const tool of result.tools)
        readOnlyHints.set(tool.name, tool.annotations?.readOnlyHint);
      return result;
    });
    local.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const remote = await getRemote();
      return remote.run(
        (client) =>
          relay.within(extra, () =>
            client.callTool(request.params, undefined, {
              signal: extra.signal,
              timeout: 300_000,
              maxTotalTimeout: 300_000,
            }),
          ),
        {
          retryExpiredSession: bridgeCallMayRetry(
            request.params.name,
            readOnlyHints.get(request.params.name),
          ),
        },
      );
    });
    const localTransport = new StdioServerTransport();
    await local.connect(localTransport);
    lifecycle.attachLocal(local, localTransport);
    if (lifecycle.isShuttingDown) return lifecycle.done;
  } finally {
    lifecycle.startupFinished();
  }
  await lifecycle.done;
}
if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
)
  await main();
