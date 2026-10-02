import { createServer as createNetServer } from "node:net";
import { request } from "node:https";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:https";
import type { ReadTools } from "../src/application.js";
import { startMcpHttps } from "../src/http.js";
import { PairingStore } from "../src/security/pairing.js";
import { generateOrRotateTlsIdentity } from "../src/security/tls.js";
import { certificateFingerprint } from "../src/security/tls.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { ToolRegistry } from "../src/toolRegistry.js";
const servers: Server[] = [];
const execFileAsync = promisify(execFile);
afterEach(async () =>
  Promise.all(
    servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))),
  ),
);
async function freePort() {
  const s = createNetServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const a = s.address();
  if (!a || typeof a === "string") throw new Error("address");
  await new Promise<void>((r) => s.close(() => r()));
  return a.port;
}
describe("TLS Streamable HTTP MCP", () => {
  it("relays exact form approval from the originating HTTPS tool call through the real built stdio bridge", async () => {
    const root = await mkdtemp(join(tmpdir(), "http-approval-"));
    const certPath = join(root, "cert.pem"),
      keyPath = join(root, "key.pem"),
      credentialFile = join(root, "credential");
    await generateOrRotateTlsIdentity({
      certPath,
      keyPath,
      openssl:
        process.platform === "win32"
          ? "C:/Program Files/Git/mingw64/bin/openssl.exe"
          : "openssl",
      subjectAltName: "IP:127.0.0.1",
    });
    const cert = await readFile(certPath, "utf8"),
      key = await readFile(keyPath, "utf8");
    const pairings = new PairingStore(),
      pairing = await pairings.pair();
    await writeFile(credentialFile, pairing.bearer, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const port = await freePort();
    const confirmation =
      "APPLY 11111111-1111-4111-8111-111111111111 " + "a".repeat(64);
    let effects = 0,
      approvals = 0,
      approvalContexts = 0,
      rotations = 0;
    const tools: ToolRegistry = {
      names: () => ["ha_apply_proposal", "ha_rotate_epoch"],
      descriptor: () => tools.descriptors()[0],
      descriptors: () => [
        {
          name: "ha_apply_proposal",
          description: "Disposable transport fixture",
          inputSchema: z.object({}).strict(),
          annotations: { readOnlyHint: false, idempotentHint: false },
        },
        {
          name: "ha_rotate_epoch",
          description: "Disposable state mutation fixture",
          inputSchema: z.object({}).strict(),
          annotations: { readOnlyHint: false, idempotentHint: false },
        },
      ],
      async call(name, _input, context) {
        if (name === "ha_rotate_epoch") {
          rotations++;
          return { ok: true, requestId: "rotation" };
        }
        if (!context?.requestApproval)
          return { ok: false, requestId: "fixture" };
        approvalContexts++;
        try {
          const answer = await context.requestApproval({
            message: "Exact disposable diff",
            confirmation,
            signal: context.signal,
            deadlineAt: Date.now() + 5000,
          });
          if (answer !== confirmation)
            return { ok: false, requestId: "fixture" };
          effects++;
          return { ok: true, requestId: "fixture" };
        } catch {
          return { ok: false, requestId: "fixture" };
        }
      },
    };
    const server = await startMcpHttps({
      bind: "127.0.0.1",
      port,
      allowedHost: `127.0.0.1:${port}`,
      certificate: cert,
      privateKey: key,
      pairings,
      tools,
    });
    servers.push(server);
    const inherited = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env: {
        ...inherited,
        HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
        HA_MCP_CREDENTIAL_FILE: credentialFile,
        HA_MCP_CA_FILE: certPath,
        HA_MCP_CERT_SHA256: certificateFingerprint(cert),
        NODE_EXTRA_CA_CERTS: certPath,
      },
      stderr: "pipe",
    });
    const client = new Client(
      { name: "approval-host", version: "1" },
      { capabilities: { elicitation: { form: {} } } },
    );
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      approvals++;
      expect(request.params.mode).toBe("form");
      expect(request.params.message).toContain(confirmation);
      return { action: "accept", content: { confirmation } };
    });
    try {
      await client.connect(transport);
      expect((await client.listTools()).tools[0]?.annotations).toMatchObject({
        readOnlyHint: false,
        idempotentHint: false,
      });
      expect(
        (await client.callTool({ name: "ha_apply_proposal", arguments: {} }))
          .isError,
      ).toBe(false);
      expect({ effects, approvals, approvalContexts }).toEqual({
        effects: 1,
        approvals: 1,
        approvalContexts: 1,
      });
    } finally {
      await client.close();
    }
    const unsupportedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env: {
        ...inherited,
        HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
        HA_MCP_CREDENTIAL_FILE: credentialFile,
        HA_MCP_CA_FILE: certPath,
        HA_MCP_CERT_SHA256: certificateFingerprint(cert),
        NODE_EXTRA_CA_CERTS: certPath,
      },
      stderr: "pipe",
    });
    const unsupported = new Client({ name: "unsupported-host", version: "1" });
    try {
      await unsupported.connect(unsupportedTransport);
      expect(
        (
          await unsupported.callTool({
            name: "ha_apply_proposal",
            arguments: {},
          })
        ).isError,
      ).toBe(true);
      expect({ effects, approvals, approvalContexts }).toEqual({
        effects: 1,
        approvals: 1,
        approvalContexts: 1,
      });
    } finally {
      await unsupported.close();
    }
    // Settle a real HTTPS state mutation, then hide its response behind a 404.
    // The bridge must surface uncertainty without replaying the request.
    const preload = `const original = globalThis.fetch; let hidden = false; globalThis.fetch = async (input, init) => { const response = await original(input, init); if (!hidden && typeof init?.body === "string" && JSON.parse(init.body).method === "tools/call") { hidden = true; await response.text(); return new Response("lost settled response", {status: 404}); } return response; };`;
    const lostTransport = new StdioClientTransport({
      command: process.execPath,
      args: [
        "--import",
        `data:text/javascript,${encodeURIComponent(preload)}`,
        join(process.cwd(), "dist/bridge.js"),
      ],
      env: {
        ...inherited,
        HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
        HA_MCP_CREDENTIAL_FILE: credentialFile,
        HA_MCP_CA_FILE: certPath,
        HA_MCP_CERT_SHA256: certificateFingerprint(cert),
        NODE_EXTRA_CA_CERTS: certPath,
      },
      stderr: "pipe",
    });
    const lostClient = new Client({ name: "lost-response-host", version: "1" });
    try {
      await lostClient.connect(lostTransport);
      await expect(
        lostClient.callTool({ name: "ha_rotate_epoch", arguments: {} }),
      ).rejects.toThrow();
      expect(rotations).toBe(1);
    } finally {
      await lostClient.close();
    }
  }, 20_000);
  it("initializes with auth and hides sessions from another client", async () => {
    const root = await mkdtemp(join(tmpdir(), "http-mcp-"));
    const certPath = join(root, "c.pem");
    const keyPath = join(root, "k.pem");
    await generateOrRotateTlsIdentity({
      certPath,
      keyPath,
      openssl:
        process.platform === "win32"
          ? "C:/Program Files/Git/mingw64/bin/openssl.exe"
          : "openssl",
      subjectAltName: "IP:127.0.0.1",
    });
    const cert = await readFile(certPath, "utf8");
    const key = await readFile(keyPath, "utf8");
    const pairings = new PairingStore();
    const a = await pairings.pair();
    const b = await pairings.pair();
    const port = await freePort();
    let toolCalls = 0;
    const tools = {
      names: () => ["ha_get_system_info"],
      call: async () => {
        toolCalls++;
        return {
          ok: true,
          requestId: "1",
          data: {},
          warnings: [],
          evidence: [],
        };
      },
    } as unknown as ReadTools;
    const server = await startMcpHttps({
      bind: "127.0.0.1",
      port,
      allowedHost: `127.0.0.1:${port}`,
      certificate: cert,
      privateKey: key,
      pairings,
      tools,
      sessionIdleMs: 500,
      sessionAbsoluteMs: 1000,
      maxSessionsPerClient: 2,
      maxSessionsGlobal: 3,
    });
    servers.push(server);
    expect((await post(port, cert, a.bearer, { invalid: true })).status).toBe(
      400,
    );
    const init = await post(port, cert, a.bearer, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "test", version: "1" },
      },
    });
    expect(init.status).toBe(200);
    expect(init.session).toBeTruthy();
    expect(
      (
        await post(
          port,
          cert,
          b.bearer,
          { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
          init.session,
        )
      ).status,
    ).toBe(404);
    const secondInit = await post(port, cert, a.bearer, {
      jsonrpc: "2.0",
      id: 19,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "second", version: "1" },
      },
    });
    expect(secondInit.status).toBe(200);
    expect(
      (
        await post(port, cert, a.bearer, {
          jsonrpc: "2.0",
          id: 20,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "overload", version: "1" },
          },
        })
      ).status,
    ).toBe(429);
    expect(
      (
        await send(
          port,
          cert,
          a.bearer,
          undefined,
          secondInit.session,
          "DELETE",
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await post(port, cert, a.bearer, {
          jsonrpc: "2.0",
          id: 23,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "after-close", version: "1" },
          },
        })
      ).status,
    ).toBe(200);
    await new Promise((r) => setTimeout(r, 550));
    expect(
      (
        await post(
          port,
          cert,
          a.bearer,
          { jsonrpc: "2.0", id: 21, method: "tools/list", params: {} },
          init.session,
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await post(port, cert, a.bearer, {
          jsonrpc: "2.0",
          id: 22,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "after-expiry", version: "1" },
          },
        })
      ).status,
    ).toBe(200);
    const bridgePair = await pairings.pair();
    const credentialFile = join(root, "credential");
    await writeFile(credentialFile, bridgePair.bearer, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const bridge = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env: {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            (x): x is [string, string] => typeof x[1] === "string",
          ),
        ),
        HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
        HA_MCP_CREDENTIAL_FILE: credentialFile,
        HA_MCP_CA_FILE: certPath,
        HA_MCP_CERT_SHA256: certificateFingerprint(cert),
        NODE_EXTRA_CA_CERTS: certPath,
      },
    });
    const client = new Client({ name: "bridge-test", version: "1" });
    await client.connect(bridge);
    expect((await client.listTools()).tools.map((x) => x.name)).toContain(
      "ha_get_system_info",
    );
    // Wait beyond two idle sweeps so this exercises bridge recovery, not timing luck.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(
      (await client.callTool({ name: "ha_get_system_info", arguments: {} }))
        .isError,
    ).toBeFalsy();
    expect(toolCalls).toBe(1);
    await client.close();
    const badBridge = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env: {
        ...Object.fromEntries(
          Object.entries(process.env).filter(
            (x): x is [string, string] => typeof x[1] === "string",
          ),
        ),
        HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
        HA_MCP_CREDENTIAL_FILE: credentialFile,
        HA_MCP_CA_FILE: certPath,
        HA_MCP_CERT_SHA256: "0".repeat(64),
        NODE_EXTRA_CA_CERTS: certPath,
      },
      stderr: "pipe",
    });
    const badClient = new Client({ name: "bad-pin", version: "1" });
    await expect(badClient.connect(badBridge)).rejects.toThrow();
    pairings.revoke(a.record.clientId);
    expect(
      (
        await post(
          port,
          cert,
          a.bearer,
          { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} },
          init.session,
        )
      ).status,
    ).toBe(401);
  }, 15_000);

  it("reclaims a session allocated before client initialization fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "http-mcp-reclaim-"));
    const certPath = join(root, "c.pem");
    const keyPath = join(root, "k.pem");
    await generateOrRotateTlsIdentity({
      certPath,
      keyPath,
      openssl:
        process.platform === "win32"
          ? "C:/Program Files/Git/mingw64/bin/openssl.exe"
          : "openssl",
      subjectAltName: "IP:127.0.0.1",
    });
    const cert = await readFile(certPath, "utf8");
    const key = await readFile(keyPath, "utf8");
    const pairings = new PairingStore();
    const pairing = await pairings.pair();
    const port = await freePort();
    const tools = {
      names: () => ["ha_get_system_info"],
      call: async () => ({
        ok: true,
        requestId: "1",
        data: {},
        warnings: [],
        evidence: [],
      }),
    } as unknown as ReadTools;
    const server = await startMcpHttps({
      bind: "127.0.0.1",
      port,
      allowedHost: `127.0.0.1:${port}`,
      certificate: cert,
      privateKey: key,
      pairings,
      tools,
      maxSessionsPerClient: 1,
      maxSessionsGlobal: 1,
    });
    servers.push(server);

    const script = `
      import { Client } from "@modelcontextprotocol/sdk/client/index.js";
      import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
      import { closeStreamableHttpConnection } from "./dist/remoteSession.js";
      const url = new URL(process.env.TEST_URL);
      const bearer = process.env.TEST_BEARER;
      const requestInit = { headers: { Authorization: "Bearer " + bearer } };
      const reconnectionOptions = { initialReconnectionDelay: 10, maxReconnectionDelay: 10, reconnectionDelayGrowFactor: 1, maxRetries: 0 };
      let failInitialized = true;
      const failingFetch = async (input, init) => {
        if (failInitialized && typeof init?.body === "string" && init.body.includes("notifications/initialized")) {
          failInitialized = false;
          return new Response("forced post-initialize failure", { status: 500, statusText: "forced" });
        }
        return fetch(input, init);
      };
      const createTransport = (sessionId, fetchOverride) => new StreamableHTTPClientTransport(url, {
        requestInit,
        reconnectionOptions,
        ...(sessionId ? { sessionId } : {}),
        ...(fetchOverride ? { fetch: fetchOverride } : {}),
      });
      const firstTransport = createTransport(undefined, failingFetch);
      const firstClient = new Client({ name: "failed-candidate", version: "1" });
      let failed = false;
      try {
        await firstClient.connect(firstTransport);
      } catch {
        failed = true;
        await closeStreamableHttpConnection(firstClient, firstTransport, sessionId => createTransport(sessionId));
      }
      if (!failed) throw new Error("Expected post-initialize failure");
      const replacementTransport = createTransport();
      const replacementClient = new Client({ name: "replacement", version: "1" });
      await replacementClient.connect(replacementTransport);
      await closeStreamableHttpConnection(replacementClient, replacementTransport, sessionId => createTransport(sessionId));
    `;
    await expect(
      execFileAsync(
        process.execPath,
        ["--input-type=module", "--eval", script],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            NODE_EXTRA_CA_CERTS: certPath,
            TEST_URL: `https://127.0.0.1:${port}/mcp`,
            TEST_BEARER: pairing.bearer,
          },
          timeout: 10_000,
        },
      ),
    ).resolves.toBeDefined();
  }, 15_000);

  it("releases a max-one HTTP session when a stdio client closes normally", async () => {
    const root = await mkdtemp(join(tmpdir(), "http-mcp-bridge-close-"));
    const certPath = join(root, "c.pem");
    const keyPath = join(root, "k.pem");
    await generateOrRotateTlsIdentity({
      certPath,
      keyPath,
      openssl:
        process.platform === "win32"
          ? "C:/Program Files/Git/mingw64/bin/openssl.exe"
          : "openssl",
      subjectAltName: "IP:127.0.0.1",
    });
    const cert = await readFile(certPath, "utf8");
    const key = await readFile(keyPath, "utf8");
    const pairings = new PairingStore();
    const pairing = await pairings.pair();
    const credentialFile = join(root, "credential");
    await writeFile(credentialFile, pairing.bearer, { mode: 0o600 });
    await chmod(credentialFile, 0o600);
    const port = await freePort();
    const tools = {
      names: () => ["ha_get_system_info"],
      call: async () => ({
        ok: true,
        requestId: "1",
        data: {},
        warnings: [],
        evidence: [],
      }),
    } as unknown as ReadTools;
    const server = await startMcpHttps({
      bind: "127.0.0.1",
      port,
      allowedHost: `127.0.0.1:${port}`,
      certificate: cert,
      privateKey: key,
      pairings,
      tools,
      maxSessionsPerClient: 1,
      maxSessionsGlobal: 1,
    });
    servers.push(server);
    const env = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      ),
      HA_MCP_URL: `https://127.0.0.1:${port}/mcp`,
      HA_MCP_CREDENTIAL_FILE: credentialFile,
      HA_MCP_CA_FILE: certPath,
      HA_MCP_CERT_SHA256: certificateFingerprint(cert),
      NODE_EXTRA_CA_CERTS: certPath,
    };

    const firstTransport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env,
      stderr: "pipe",
    });
    let stderr = "";
    firstTransport.stderr?.on("data", (chunk) => (stderr += String(chunk)));
    const firstClient = new Client({ name: "bridge-close-a", version: "1" });
    await firstClient.connect(firstTransport);
    expect((await firstClient.listTools()).tools).toHaveLength(1);
    const started = Date.now();
    await firstClient.close();
    expect(Date.now() - started).toBeLessThan(1900);
    expect(stderr).toBe("");

    const secondTransport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), "dist/bridge.js")],
      env,
      stderr: "pipe",
    });
    const secondClient = new Client({ name: "bridge-close-b", version: "1" });
    await secondClient.connect(secondTransport);
    expect((await secondClient.listTools()).tools).toHaveLength(1);
    await secondClient.close();
  }, 15_000);
});
function post(
  port: number,
  ca: string,
  bearer: string,
  body: unknown,
  session?: string,
) {
  return send(port, ca, bearer, body, session, "POST");
}
function send(
  port: number,
  ca: string,
  bearer: string,
  body: unknown,
  session: string | undefined,
  method: "POST" | "DELETE",
) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  return new Promise<{ status: number; session?: string }>(
    (resolve, reject) => {
      const req = request(
        {
          hostname: "127.0.0.1",
          port,
          path: "/mcp",
          method,
          ca,
          headers: {
            host: `127.0.0.1:${port}`,
            authorization: `Bearer ${bearer}`,
            accept: "application/json, text/event-stream",
            "content-type": "application/json",
            "content-length": Buffer.byteLength(payload),
            ...(session ? { "mcp-session-id": session } : {}),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              ...(typeof res.headers["mcp-session-id"] === "string"
                ? { session: res.headers["mcp-session-id"] }
                : {}),
            }),
          );
        },
      );
      req.on("error", reject);
      req.end(payload);
    },
  );
}
