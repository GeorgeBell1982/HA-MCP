import { SafeError } from "../domain.js";
export const CORE_PROXY_WS_URL = "ws://supervisor/core/websocket";
export function deriveWebSocketUrl(base: URL): URL {
  if (base.href === "http://supervisor/core/api")
    return new URL(CORE_PROXY_WS_URL);
  const result = new URL(base);
  result.protocol = result.protocol === "https:" ? "wss:" : "ws:";
  result.pathname = result.pathname.replace(/\/api\/?$/, "") + "/api/websocket";
  return result;
}
type SocketFactory = (url: string) => WebSocket;
export class HaWebSocketClient {
  private socket?: WebSocket;
  private nextId = 1;
  private pending = new Map<
    number,
    {
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();
  constructor(
    private readonly url: URL,
    private readonly token: string,
    private readonly timeoutMs = 8000,
    private readonly factory: SocketFactory = (u) => new WebSocket(u),
  ) {}
  async connect(retries = 2): Promise<void> {
    let last: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        await this.connectOnce();
        return;
      } catch (e) {
        last = e;
        if (attempt < retries)
          await new Promise((r) =>
            setTimeout(r, Math.min(250 * 2 ** attempt, 1000)),
          );
      }
    }
    throw last instanceof SafeError
      ? last
      : new SafeError("upstream_error", "WebSocket connection failed");
  }
  private connectOnce() {
    return new Promise<void>((resolve, reject) => {
      const ws = this.factory(this.url.href);
      this.socket = ws;
      const timer = setTimeout(() => {
        ws.close();
        reject(new SafeError("timeout", "WebSocket authentication timed out"));
      }, this.timeoutMs);
      ws.onmessage = (event) => {
        let msg: Record<string, unknown>;
        try {
          const parsed: unknown = JSON.parse(String(event.data));
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
            return;
          msg = parsed as Record<string, unknown>;
        } catch {
          return;
        }
        if (msg.type === "auth_required")
          ws.send(JSON.stringify({ type: "auth", access_token: this.token }));
        else if (msg.type === "auth_ok") {
          clearTimeout(timer);
          resolve();
        } else if (msg.type === "auth_invalid") {
          clearTimeout(timer);
          reject(
            new SafeError(
              "auth_failed",
              "Home Assistant WebSocket authentication failed",
            ),
          );
        } else if (typeof msg.id === "number") {
          const p = this.pending.get(msg.id);
          if (p) {
            clearTimeout(p.timer);
            this.pending.delete(msg.id);
            if (msg.success === false)
              p.reject(
                new SafeError(
                  "upstream_error",
                  "Home Assistant WebSocket command failed",
                ),
              );
            else p.resolve(msg.result);
          }
        }
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new SafeError("upstream_error", "WebSocket connection failed"));
      };
      ws.onclose = () => {
        for (const p of this.pending.values()) {
          clearTimeout(p.timer);
          p.reject(new SafeError("upstream_error", "WebSocket disconnected"));
        }
        this.pending.clear();
      };
    });
  }
  request(type: string, input: Record<string, unknown> = {}): Promise<unknown> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN)
      return Promise.reject(
        new SafeError("capability_unavailable", "WebSocket is not connected"),
      );
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new SafeError("timeout", "WebSocket request timed out"));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket!.send(JSON.stringify({ id, type, ...input }));
    });
  }
  close() {
    this.socket?.close();
  }
}
