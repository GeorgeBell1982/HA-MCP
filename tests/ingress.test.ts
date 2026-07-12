import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import { runInNewContext } from "node:vm";
import { PairingStore } from "../src/security/pairing.js";
import { loadPairings, startIngress } from "../src/ingress.js";
import { generateOrRotateTlsIdentity } from "../src/security/tls.js";
const servers: Server[] = [];
afterEach(async () =>
  Promise.all(
    servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))),
  ),
);
describe("loopback ingress operations", () => {
  it("pairs, persists, rotates and revokes clients", async () => {
    const root = await mkdtemp(join(tmpdir(), "pairings-"));
    const path = join(root, "pairings.json");
    const certPath = join(root, "server.crt");
    const keyPath = join(root, "server.key");
    await generateOrRotateTlsIdentity({
      certPath,
      keyPath,
      openssl:
        process.platform === "win32"
          ? "C:/Program Files/Git/mingw64/bin/openssl.exe"
          : "openssl",
      subjectAltName: "IP:127.0.0.1",
    });
    const store = new PairingStore(2);
    const server = await startIngress({
      store,
      path,
      port: 0,
      tls: { certPath, keyPath, subjectAltName: "IP:127.0.0.1" },
    });
    servers.push(server);
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing test address");
    expect(address.address).toBe("127.0.0.1");
    const base = `http://127.0.0.1:${address.port}`;
    const page = await fetch(`${base}/`);
    expect(page.status).toBe(200);
    await proveOperatorScript(await page.text());
    const cert = await fetch(`${base}/certificate`);
    expect(cert.headers.get("cache-control")).toContain("no-store");
    expect(cert.headers.get("content-disposition")).toContain("attachment");
    expect(await cert.text()).toContain("BEGIN CERTIFICATE");
    expect((await fetch(`${base}/fingerprint`)).status).toBe(200);
    expect((await fetch(`${base}/pair`, { method: "POST" })).status).toBe(403);
    const mutation = {
      method: "POST",
      headers: { "x-ha-mcp-csrf": "1", "sec-fetch-site": "same-origin" },
    };
    const pair = await fetch(`${base}/pair`, mutation);
    expect(pair.status).toBe(201);
    const first = (await pair.json()) as {
      clientId: string;
      credential: string;
    };
    expect(first.credential).not.toBe("");
    expect(await readFile(path, "utf8")).not.toContain(first.credential);
    const restored = new PairingStore();
    await loadPairings(restored, path);
    expect(await restored.authenticate(first.credential)).toBe(first.clientId);
    const rotated = await fetch(`${base}/rotate/${first.clientId}`, mutation);
    expect(rotated.status).toBe(201);
    const second = (await rotated.json()) as {
      clientId: string;
      credential: string;
    };
    expect(await store.authenticate(first.credential)).toBeUndefined();
    expect(await store.authenticate(second.credential)).toBe(second.clientId);
    expect(
      (await fetch(`${base}/revoke/${second.clientId}`, mutation)).status,
    ).toBe(204);
    expect(await store.authenticate(second.credential)).toBeUndefined();
  });
  it("binds the add-on listener to the internal wildcard when explicit", async () => {
    const root = await mkdtemp(join(tmpdir(), "ingress-bind-"));
    const server = await startIngress({
      store: new PairingStore(),
      path: join(root, "pairings.json"),
      port: 0,
      host: "0.0.0.0",
    });
    servers.push(server);
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing address");
    expect(address.address).toBe("0.0.0.0");
  });
});
async function proveOperatorScript(html: string) {
  const script = html.match(/<script>([\s\S]*)<\/script>/)?.[1];
  if (!script) throw new Error("served operator script missing");
  class FakeElement {
    dataset: Record<string, string> = {};
    textContent = "";
    innerHTML = "";
  }
  const elements = new Map([
    ["status", new FakeElement()],
    ["clients", new FakeElement()],
    ["secret", new FakeElement()],
  ]);
  let click: ((event: { target: unknown }) => Promise<void>) | undefined;
  const calls: Array<{ path: string; init?: RequestInit }> = [];
  const responses: Record<string, unknown> = {
    health: { ok: true },
    fingerprint: { fingerprint: "abc123" },
    clients: { clients: [{ clientId: "client-a" }] },
    pair: { credential: "one-time-secret", clientId: "client-b" },
  };
  const fetchLike = async (path: string, init?: RequestInit) => {
    calls.push({ path, ...(init ? { init } : {}) });
    return {
      json: async () => responses[path],
      headers: {
        get: (name: string) =>
          path === "pair" && name === "content-type"
            ? "application/json"
            : null,
      },
    };
  };
  runInNewContext(script, {
    Element: FakeElement,
    fetch: fetchLike,
    alert: () => undefined,
    document: {
      getElementById: (id: string) => elements.get(id) ?? null,
      addEventListener: (name: string, handler: typeof click) => {
        if (name === "click") click = handler;
      },
    },
  });
  await waitFor(() => elements.get("status")?.textContent !== "");
  expect(elements.get("status")?.textContent).toContain("Healthy: true");
  expect(elements.get("clients")?.innerHTML).toContain("client-a");
  if (!click) throw new Error("click handler missing");
  await click({ target: {} });
  expect(calls).toHaveLength(3);
  const pair = new FakeElement();
  pair.dataset.action = "pair";
  await click({ target: pair });
  expect(calls[3]).toMatchObject({
    path: "pair",
    init: { method: "POST", headers: { "x-ha-mcp-csrf": "1" } },
  });
  expect(elements.get("secret")?.textContent).toBe("one-time-secret");
  expect(calls.slice(4).map((x) => x.path)).toEqual([
    "health",
    "fingerprint",
    "clients",
  ]);
}
async function waitFor(predicate: () => boolean) {
  for (let i = 0; i < 50; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("operator script did not settle");
}
