import { SafeError } from "../domain.js";

export const CORE_PROXY_WS_URL = "ws://supervisor/core/websocket";
const MAX_MESSAGE_BYTES = 512_000;

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
  private socket: WebSocket | undefined;
  private authenticated = false;
  private connectPromise: Promise<void> | undefined;
  private nextId = 1;
  private pending = new Map<
    number,
    {
      resolve: (value: unknown) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();

  constructor(
    private readonly url: URL,
    private readonly token: string,
    private readonly timeoutMs = 8000,
    private readonly factory: SocketFactory = (url) => new WebSocket(url),
  ) {}

  connect(retries = 2): Promise<void> {
    if (this.authenticated && this.socket?.readyState === WebSocket.OPEN)
      return Promise.resolve();
    if (this.connectPromise) return this.connectPromise;
    const connecting = this.connectWithRetries(retries).finally(() => {
      if (this.connectPromise === connecting) this.connectPromise = undefined;
    });
    this.connectPromise = connecting;
    return connecting;
  }

  private async connectWithRetries(retries: number): Promise<void> {
    let last: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        await this.connectOnce();
        return;
      } catch (error) {
        last = error;
        if (attempt < retries)
          await new Promise((resolve) =>
            setTimeout(resolve, Math.min(250 * 2 ** attempt, 1000)),
          );
      }
    }
    throw last instanceof SafeError
      ? last
      : new SafeError("upstream_error", "WebSocket connection failed");
  }

  private connectOnce(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = this.factory(this.url.href);
      this.socket = ws;
      this.authenticated = false;
      let settled = false;
      const timer = setTimeout(() => {
        fail(new SafeError("timeout", "WebSocket authentication timed out"));
      }, this.timeoutMs);

      const settleFailure = (error: SafeError) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      };
      const fail = (error: SafeError) => {
        settleFailure(error);
        if (this.socket === ws) this.rejectPending(error);
        try {
          ws.close();
        } catch {
          // Preserve the original safe failure.
        }
      };

      ws.onmessage = (event) => {
        if (this.socket !== ws) return;
        if (typeof event.data !== "string") {
          fail(
            new SafeError("upstream_error", "WebSocket response was invalid"),
          );
          return;
        }
        if (Buffer.byteLength(event.data, "utf8") > MAX_MESSAGE_BYTES) {
          fail(
            new SafeError(
              "upstream_error",
              "Home Assistant WebSocket response exceeded the safe size limit",
            ),
          );
          return;
        }
        let message: Record<string, unknown>;
        try {
          const parsed: unknown = JSON.parse(event.data);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
            return;
          message = parsed as Record<string, unknown>;
        } catch {
          return;
        }
        if (message.type === "auth_required")
          ws.send(JSON.stringify({ type: "auth", access_token: this.token }));
        else if (message.type === "auth_ok") {
          if (this.socket !== ws) return;
          settled = true;
          clearTimeout(timer);
          this.authenticated = true;
          resolve();
        } else if (message.type === "auth_invalid") {
          fail(
            new SafeError(
              "auth_failed",
              "Home Assistant WebSocket authentication failed",
            ),
          );
        } else if (typeof message.id === "number") {
          const pending = this.pending.get(message.id);
          if (!pending) return;
          clearTimeout(pending.timer);
          this.pending.delete(message.id);
          if (message.success === false)
            pending.reject(
              new SafeError(
                "upstream_error",
                "Home Assistant WebSocket command failed",
              ),
            );
          else pending.resolve(message.result);
        }
      };
      ws.onerror = () => {
        if (this.socket !== ws) return;
        fail(new SafeError("upstream_error", "WebSocket connection failed"));
      };
      ws.onclose = () => {
        const isCurrent = this.socket === ws;
        if (isCurrent) {
          this.socket = undefined;
          this.authenticated = false;
        }
        const error = new SafeError("upstream_error", "WebSocket disconnected");
        settleFailure(error);
        if (isCurrent) this.rejectPending(error);
      };
    });
  }

  request(type: string, input: Record<string, unknown> = {}): Promise<unknown> {
    if (
      !this.authenticated ||
      !this.socket ||
      this.socket.readyState !== WebSocket.OPEN
    )
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

  async systemLogEntries(): Promise<unknown> {
    await this.connect();
    return this.request("system_log/list");
  }

  close(): void {
    this.socket?.close();
  }

  private rejectPending(error: SafeError): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }
}
