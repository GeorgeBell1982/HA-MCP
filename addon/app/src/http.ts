import { SafeError } from "./domain.js";
import { createServer as createHttpsServer } from "node:https";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { ToolRegistry } from "./toolRegistry.js";
import { createServer as createMcpServer } from "./transport/mcp.js";
import type { PairingStore } from "./security/pairing.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
export function assertHttpCanStart(options: {
  enabled: boolean;
  tlsCertificate?: string;
  pairedClients: number;
  bind?: string;
  addonMode?: boolean;
}) {
  if (!options.enabled) return { enabled: false as const };
  if (!options.tlsCertificate || options.pairedClients < 1)
    throw new SafeError(
      "capability_unavailable",
      "HTTPS requires a valid TLS identity and at least one paired client",
    );
  if (
    !options.bind ||
    (!options.addonMode &&
      (options.bind === "0.0.0.0" || options.bind === "::"))
  )
    throw new SafeError(
      "invalid_input",
      "Explicit private LAN bind is required",
    );
  return { enabled: true as const };
}

export function validateRequestHeaders(
  headers: Record<string, string | string[] | undefined>,
  allowedHost: string,
) {
  const host = headers.host;
  if (host !== allowedHost)
    throw new SafeError("auth_failed", "Host is not allowed");
  const origin = headers.origin;
  if (origin)
    throw new SafeError("auth_failed", "Browser origins are not allowed");
  if (headers["x-forwarded-proto"] || headers.forwarded)
    throw new SafeError("auth_failed", "Proxy forwarding is not supported");
}

export async function startMcpHttps(options: {
  bind: string;
  port: number;
  certificate: string;
  privateKey: string;
  allowedHost: string;
  tools: ToolRegistry;
  pairings: PairingStore;
  maxSessionsPerClient?: number;
  maxSessionsGlobal?: number;
  sessionIdleMs?: number;
  sessionAbsoluteMs?: number;
  maxBodyBytes?: number;
  maxHeaderBytes?: number;
  requestsPerMinute?: number;
  maxConcurrentRequestsPerClient?: number;
  addonMode?: boolean;
}) {
  assertHttpCanStart({
    enabled: true,
    tlsCertificate: options.certificate,
    pairedClients: options.pairings.list().filter((client) => !client.revokedAt)
      .length,
    bind: options.bind,
    ...(options.addonMode === undefined
      ? {}
      : { addonMode: options.addonMode }),
  });
  const sessions = new Map<
    string,
    { clientId: string; transport: StreamableHTTPServerTransport }
  >();
  const counts = new Map<string, number>();
  const max = options.maxSessionsPerClient ?? 2;
  const globalMax = options.maxSessionsGlobal ?? 16;
  const idleMs = options.sessionIdleMs ?? 5 * 60_000;
  const absoluteMs = options.sessionAbsoluteMs ?? 60 * 60_000;
  const maxBody = options.maxBodyBytes ?? 1_000_000;
  const maxHeader = options.maxHeaderBytes ?? 16_384;
  const rate = new Map<string, { start: number; count: number }>();
  const inFlight = new Map<string, number>();
  const expiry = new Map<string, { created: number; touched: number }>();
  const cleanupSession = async (sid: string, closeTransport: boolean) => {
    const item = sessions.get(sid);
    expiry.delete(sid);
    if (!item) return false;
    sessions.delete(sid);
    const remaining = Math.max(0, (counts.get(item.clientId) ?? 1) - 1);
    if (remaining) counts.set(item.clientId, remaining);
    else counts.delete(item.clientId);
    if (closeTransport) await item.transport.close();
    return true;
  };
  const removeRevocationListener = options.pairings.onRevoked((clientId) => {
    rate.delete(clientId);
    inFlight.delete(clientId);
    for (const [sid, item] of sessions)
      if (item.clientId === clientId) void cleanupSession(sid, true);
  });
  const removeResetListener = options.pairings.onSessionsReset(() => {
    for (const sid of sessions.keys()) void cleanupSession(sid, true);
  });
  const server = createHttpsServer(
    { cert: options.certificate, key: options.privateKey },
    (req, res) =>
      void (async () => {
        try {
          validateRequestHeaders(req.headers, options.allowedHost);
          if (req.rawHeaders.join("").length > maxHeader) {
            res.writeHead(431).end();
            return;
          }
          const declared = Number(req.headers["content-length"] ?? 0);
          if (
            !Number.isFinite(declared) ||
            declared < 0 ||
            declared > maxBody
          ) {
            res.writeHead(413).end();
            return;
          }
          if (
            req.method === "POST" &&
            (req.headers["transfer-encoding"] || !req.headers["content-length"])
          ) {
            res.writeHead(411).end();
            return;
          }
          if (req.url !== "/mcp") {
            res.writeHead(404).end();
            return;
          }
          const auth = req.headers.authorization;
          const clientId = auth?.startsWith("Bearer ")
            ? await options.pairings.authenticate(auth.slice(7))
            : undefined;
          if (!clientId) {
            res.writeHead(401, { "WWW-Authenticate": "Bearer" }).end();
            return;
          }
          if (
            (inFlight.get(clientId) ?? 0) >=
            (options.maxConcurrentRequestsPerClient ?? 4)
          ) {
            res.writeHead(429).end();
            return;
          }
          inFlight.set(clientId, (inFlight.get(clientId) ?? 0) + 1);
          let released = false;
          const release = () => {
            if (released) return;
            released = true;
            const remaining = Math.max(0, (inFlight.get(clientId) ?? 1) - 1);
            if (remaining) inFlight.set(clientId, remaining);
            else inFlight.delete(clientId);
          };
          res.once("finish", release);
          res.once("close", release);
          const now = Date.now();
          const bucket = rate.get(clientId);
          if (!bucket || now - bucket.start >= 60_000)
            rate.set(clientId, { start: now, count: 1 });
          else if (++bucket.count > (options.requestsPerMinute ?? 120)) {
            res.writeHead(429).end();
            return;
          }
          const requested = req.headers["mcp-session-id"];
          const sid = typeof requested === "string" ? requested : undefined;
          let item = sid ? sessions.get(sid) : undefined;
          if (sid && item) {
            const times = expiry.get(sid);
            if (
              !times ||
              now - times.touched > idleMs ||
              now - times.created > absoluteMs
            ) {
              await cleanupSession(sid, true);
              item = undefined;
            } else times.touched = now;
          }
          if (item && item.clientId !== clientId) {
            res.writeHead(404).end();
            return;
          }
          if (!item) {
            if (sid) {
              res.writeHead(404).end();
              return;
            }
            if (
              (counts.get(clientId) ?? 0) >= max ||
              sessions.size >= globalMax
            ) {
              res.writeHead(429).end();
              return;
            }
            const transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: randomUUID,
            }) as StreamableHTTPServerTransport & {
              __registeredSessionId?: string;
            };
            const mcp = createMcpServer(options.tools);
            await mcp.connect(transport as unknown as Transport);
            const protocolClose = transport.onclose;
            transport.onclose = () => {
              protocolClose?.();
              const id = transport.__registeredSessionId ?? transport.sessionId;
              if (id) void cleanupSession(id, false);
            };
            item = { clientId, transport };
          }
          await item.transport.handleRequest(req, res);
          if (req.method === "DELETE" && sid) {
            await cleanupSession(sid, false);
            return;
          }
          if (item.transport.sessionId) {
            if (!sessions.has(item.transport.sessionId))
              counts.set(clientId, (counts.get(clientId) ?? 0) + 1);
            sessions.set(item.transport.sessionId, item);
            // Capture before a later transport close clears its public session ID.
            // The callback closes over this through the transport instance.
            (
              item.transport as StreamableHTTPServerTransport & {
                __registeredSessionId?: string;
              }
            ).__registeredSessionId = item.transport.sessionId;
            const old = expiry.get(item.transport.sessionId);
            expiry.set(item.transport.sessionId, {
              created: old?.created ?? now,
              touched: now,
            });
          } else await item.transport.close();
        } catch {
          res.writeHead(400).end();
        }
      })(),
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.bind, resolve);
  });
  const sweep = setInterval(
    () => {
      const now = Date.now();
      for (const [sid, times] of expiry)
        if (now - times.touched > idleMs || now - times.created > absoluteMs)
          void cleanupSession(sid, true);
    },
    Math.min(idleMs, 30_000),
  );
  sweep.unref();
  server.on("close", () => {
    clearInterval(sweep);
    removeRevocationListener();
    removeResetListener();
    for (const sid of sessions.keys()) void cleanupSession(sid, true);
  });
  return server;
}
