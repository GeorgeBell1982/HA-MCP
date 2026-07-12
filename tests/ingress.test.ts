import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:http";
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
    expect((await fetch(`${base}/`)).status).toBe(200);
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
