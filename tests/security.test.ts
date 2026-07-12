import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonlAudit } from "../src/audit.js";
import { redact } from "../src/redaction.js";
import {
  createCredential,
  PairingStore,
  verifyCredential,
} from "../src/security/pairing.js";
import { assertHttpCanStart, validateRequestHeaders } from "../src/http.js";
import {
  certificateFingerprint,
  ensureTlsIdentity,
  generateOrRotateTlsIdentity,
} from "../src/security/tls.js";
import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
describe("security", () => {
  it("redacts credential shapes recursively", () =>
    expect(
      JSON.stringify(
        redact({ authorization: "Bearer canary", nested: "password=canary" }),
      ),
    ).not.toContain("canary"));
  it("redacts URL userinfo and webhook paths", () => {
    const value = JSON.stringify(
      redact("https://user:pass@ha.test/api/webhook/canary"),
    );
    expect(value).not.toContain("pass");
    expect(value).not.toContain("canary");
  });
  it("hashes and verifies pairing secrets", async () => {
    const c = await createCredential();
    expect(c.record).not.toHaveProperty("secret");
    expect(await verifyCredential(c.bearer, c.record)).toBe(true);
    expect(await verifyCredential(c.bearer + "x", c.record)).toBe(false);
  });
  it("refuses unprovisioned HTTP", () =>
    expect(() =>
      assertHttpCanStart({ enabled: true, pairedClients: 0 }),
    ).toThrow());
  it("binds sessions to strict request authority", () => {
    expect(() =>
      validateRequestHeaders({ host: "ha:8443" }, "ha:8443"),
    ).not.toThrow();
    expect(() => validateRequestHeaders({ host: "evil" }, "ha:8443")).toThrow();
    expect(() =>
      validateRequestHeaders(
        { host: "ha:8443", origin: "https://evil" },
        "ha:8443",
      ),
    ).toThrow();
    expect(() =>
      validateRequestHeaders(
        { host: "ha:8443", forwarded: "for=evil" },
        "ha:8443",
      ),
    ).toThrow();
  });
  it("rotates and revokes independent client credentials", async () => {
    const store = new PairingStore(2);
    const a = await store.pair();
    const b = await store.pair();
    expect(await store.authenticate(a.bearer)).toBe(a.record.clientId);
    expect(await store.authenticate(b.bearer)).toBe(b.record.clientId);
    const replacement = await store.rotate(a.record.clientId);
    expect(await store.authenticate(a.bearer)).toBeUndefined();
    expect(await store.authenticate(replacement.bearer)).toBe(
      replacement.record.clientId,
    );
    store.revoke(b.record.clientId);
    expect(await store.authenticate(b.bearer)).toBeUndefined();
  });
  it.runIf(existsSync("C:/Program Files/Git/mingw64/bin/openssl.exe"))(
    "generates and rotates an ECDSA certificate identity",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "tls-"));
      const certPath = join(root, "server.crt");
      const keyPath = join(root, "server.key");
      const openssl = "C:/Program Files/Git/mingw64/bin/openssl.exe";
      const first = await generateOrRotateTlsIdentity({
        certPath,
        keyPath,
        openssl,
      });
      expect(first).toHaveLength(64);
      expect(certificateFingerprint(await readFile(certPath))).toBe(first);
      expect(await readFile(keyPath, "utf8")).toContain("PRIVATE KEY");
      const second = await generateOrRotateTlsIdentity({
        certPath,
        keyPath,
        openssl,
      });
      expect(second).not.toBe(first);
      await writeFile(keyPath, "crash-corrupted-key");
      const recovered = await ensureTlsIdentity({
        certPath,
        keyPath,
        openssl,
        subjectAltName: "IP:127.0.0.1",
      });
      expect(recovered).toHaveLength(64);
      expect(await readFile(keyPath, "utf8")).toContain("PRIVATE KEY");
    },
  );
  it("syncs redacted JSONL", async () => {
    const root = await mkdtemp(join(tmpdir(), "audit-"));
    const path = join(root, "audit.jsonl");
    const audit = new JsonlAudit(path);
    await audit.append({
      timestamp: new Date().toISOString(),
      tool: "x",
      requestId: "1",
      result: "failure",
      risk: "read-only",
      error: "Bearer canary",
    });
    expect(await readFile(path, "utf8")).not.toContain("canary");
  });
  it("bounds and redacts multiline error summaries", async () => {
    const { summarizeErrors } = await import("../src/application.js");
    const result = summarizeErrors(
      `${"old\n".repeat(60)}https://u:p@ha/api/webhook/canary\nBearer tokenvalue`,
    );
    expect(result.count).toBe(50);
    expect(result.truncated).toBe(true);
    expect(JSON.stringify(result)).not.toContain("canary");
    expect(JSON.stringify(result)).not.toContain("tokenvalue");
  });
});
