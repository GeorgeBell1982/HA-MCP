import { createServer as createNetServer } from "node:net";
import { request } from "node:https";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:https";
import type { ReadTools } from "../src/application.js";
import { startMcpHttps } from "../src/http.js";
import { PairingStore } from "../src/security/pairing.js";
import { generateOrRotateTlsIdentity } from "../src/security/tls.js";
import { certificateFingerprint } from "../src/security/tls.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const servers: Server[] = [];
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
    expect(
      (await client.callTool({ name: "ha_get_system_info", arguments: {} }))
        .isError,
    ).toBeFalsy();
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
  });
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
