import { createServer } from "node:http";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import type { CredentialRecord, PairingStore } from "./security/pairing.js";
import { generateOrRotateTlsIdentity } from "./security/tls.js";
import { certificateFingerprint } from "./security/tls.js";
export async function loadPairings(store: PairingStore, path: string) {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!Array.isArray(parsed) || !parsed.every(isCredentialRecord))
      throw new Error("Pairing store is malformed");
    store.importRecords(parsed);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
}
function isCredentialRecord(value: unknown): value is CredentialRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.clientId === "string" &&
    /^[A-Za-z0-9_-]{22}$/.test(v.clientId) &&
    typeof v.salt === "string" &&
    /^[A-Za-z0-9_-]{22}$/.test(v.salt) &&
    typeof v.hash === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(v.hash) &&
    typeof v.createdAt === "string" &&
    (v.revokedAt === undefined || typeof v.revokedAt === "string")
  );
}
export async function savePairings(store: PairingStore, path: string) {
  const temp = `${path}.tmp`;
  await writeFile(temp, JSON.stringify(store.exportRecords()), { mode: 0o600 });
  await chmod(temp, 0o600);
  await rename(temp, path);
}
export async function startIngress(options: {
  store: PairingStore;
  path: string;
  port?: number;
  host?: string;
  tls?: {
    certPath: string;
    keyPath: string;
    subjectAltName?: string;
    onRotated?: (fingerprint: string) => void;
  };
}) {
  const server = createServer(
    (req, res) =>
      void (async () => {
        if (req.url === "/" && req.method === "GET") {
          res
            .writeHead(200, secureHeaders("text/html; charset=utf-8"))
            .end(operatorHtml());
          return;
        }
        if (req.url === "/certificate" && req.method === "GET" && options.tls) {
          const cert = await readFile(options.tls.certPath);
          res
            .writeHead(200, {
              ...secureHeaders("application/x-pem-file"),
              "content-disposition":
                'attachment; filename="ha-engineering-mcp.crt"',
            })
            .end(cert);
          return;
        }
        if (req.url === "/fingerprint" && req.method === "GET" && options.tls) {
          const fingerprint = certificateFingerprint(
            await readFile(options.tls.certPath),
          );
          res
            .writeHead(200, secureHeaders("application/json"))
            .end(JSON.stringify({ fingerprint }));
          return;
        }
        if (req.url === "/health" && req.method === "GET") {
          res.writeHead(200, { "content-type": "application/json" }).end(
            JSON.stringify({
              ok: true,
              pairedClients: options.store.list().filter((x) => !x.revokedAt)
                .length,
            }),
          );
          return;
        }
        // HA Ingress strips external auth and supplies this path only to authenticated HA users.
        if (req.url === "/pair" && req.method === "POST") {
          if (!allowMutation(req)) {
            res.writeHead(403).end();
            return;
          }
          const created = await options.store.pair();
          await savePairings(options.store, options.path);
          res
            .writeHead(201, {
              "content-type": "application/json",
              "cache-control": "no-store",
            })
            .end(
              JSON.stringify({
                credential: created.bearer,
                clientId: created.record.clientId,
              }),
            );
          return;
        }
        if (req.url === "/clients" && req.method === "GET") {
          res
            .writeHead(200, {
              "content-type": "application/json",
              "cache-control": "no-store",
            })
            .end(JSON.stringify({ clients: options.store.list() }));
          return;
        }
        if (
          req.url === "/rotate-certificate" &&
          req.method === "POST" &&
          options.tls
        ) {
          if (!allowMutation(req)) {
            res.writeHead(403).end();
            return;
          }
          const fingerprint = await generateOrRotateTlsIdentity(options.tls);
          res
            .writeHead(201, {
              "content-type": "application/json",
              "cache-control": "no-store",
            })
            .end(JSON.stringify({ fingerprint, restartRequired: true }));
          options.tls.onRotated?.(fingerprint);
          options.store.resetSessions();
          return;
        }
        const action = req.url?.match(
          /^\/(revoke|rotate)\/([A-Za-z0-9_-]{22})$/,
        );
        if (action && req.method === "POST") {
          if (!allowMutation(req)) {
            res.writeHead(403).end();
            return;
          }
          const [, operation, clientId] = action;
          if (!clientId) {
            res.writeHead(400).end();
            return;
          }
          if (operation === "revoke") {
            if (!options.store.revoke(clientId)) {
              res.writeHead(404).end();
              return;
            }
            await savePairings(options.store, options.path);
            res.writeHead(204).end();
            return;
          }
          try {
            const replacement = await options.store.rotate(clientId);
            await savePairings(options.store, options.path);
            res
              .writeHead(201, {
                "content-type": "application/json",
                "cache-control": "no-store",
              })
              .end(
                JSON.stringify({
                  credential: replacement.bearer,
                  clientId: replacement.record.clientId,
                }),
              );
          } catch {
            res.writeHead(404).end();
          }
          return;
        }
        res.writeHead(404).end();
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      }),
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 8099, options.host ?? "127.0.0.1", resolve);
  });
  return server;
}
function secureHeaders(contentType: string) {
  return {
    "content-type": contentType,
    "cache-control": "no-store, max-age=0",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'self'",
  };
}
function allowMutation(req: import("node:http").IncomingMessage) {
  const site = req.headers["sec-fetch-site"];
  return (
    req.headers["x-ha-mcp-csrf"] === "1" && (!site || site === "same-origin")
  );
}
function operatorHtml() {
  return `<!doctype html><meta charset="utf-8"><title>HA Engineering MCP</title><style>body{font:16px system-ui;max-width:55rem;margin:2rem auto}button{margin:.25rem}pre{white-space:pre-wrap}</style><h1>Home Assistant Engineering MCP</h1><p id="status">Loading…</p><p><a href="certificate">Download public certificate</a></p><button data-action="pair">Pair new client</button><button data-action="rotate-certificate">Rotate certificate</button><h2>One-time credential</h2><pre id="secret">Not generated. It is never stored by this page.</pre><h2>Clients</h2><div id="clients"></div><script>const statusEl=document.getElementById('status'),clientsEl=document.getElementById('clients'),secretEl=document.getElementById('secret');if(!statusEl||!clientsEl||!secretEl)throw new Error('Operator UI elements are unavailable');const h={'x-ha-mcp-csrf':'1'};async function refresh(){const [health,fp,clients]=await Promise.all(['health','fingerprint','clients'].map(x=>fetch(x,{cache:'no-store'}).then(r=>r.json())));statusEl.textContent='Healthy: '+health.ok+' — fingerprint: '+fp.fingerprint;clientsEl.innerHTML=clients.clients.map(c=>c.clientId+' '+(c.revokedAt?'revoked':'active')+' <button data-action="rotate/'+c.clientId+'">rotate</button><button data-action="revoke/'+c.clientId+'">revoke</button>').join('<br>')}document.addEventListener('click',async e=>{if(!(e.target instanceof Element))return;const a=e.target.dataset.action;if(!a)return;const r=await fetch(a,{method:'POST',headers:h,cache:'no-store'});if(r.headers.get('content-type')?.includes('json')){const v=await r.json();if(v.credential)secretEl.textContent=v.credential;if(v.fingerprint)alert('New fingerprint: '+v.fingerprint+'; restart the add-on and update bridge pins.')}await refresh()});refresh()</script>`;
}
