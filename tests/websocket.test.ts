import { describe, expect, it, vi } from "vitest";
import {
  CORE_PROXY_WS_URL,
  deriveWebSocketUrl,
  HaWebSocketClient,
} from "../src/ha/websocket.js";

class FakeSocket {
  readyState: number = WebSocket.OPEN;
  sent: string[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  send(value: string): void {
    this.sent.push(value);
  }

  close(): void {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.({} as CloseEvent);
  }

  message(value: unknown): void {
    const data = typeof value === "string" ? value : JSON.stringify(value);
    this.onmessage?.({ data } as MessageEvent);
  }
}

function harness(timeoutMs = 100) {
  const sockets: FakeSocket[] = [];
  const factory = vi.fn(() => {
    const socket = new FakeSocket();
    sockets.push(socket);
    return socket as unknown as WebSocket;
  });
  const client = new HaWebSocketClient(
    new URL(CORE_PROXY_WS_URL),
    "canary",
    timeoutMs,
    factory,
  );
  return { client, factory, sockets };
}

async function authenticate(
  client: HaWebSocketClient,
  sockets: FakeSocket[],
): Promise<void> {
  const connecting = client.connect(0);
  const socket = sockets[0]!;
  socket.message({ type: "auth_required" });
  expect(JSON.parse(socket.sent[0] ?? "{}")).toEqual({
    type: "auth",
    access_token: "canary",
  });
  socket.message({ type: "auth_ok" });
  await connecting;
}
function lastRequest(socket: FakeSocket): { id: number; type: string } {
  const parsed: unknown = JSON.parse(socket.sent.at(-1) ?? "{}");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("Fake socket request was invalid");
  const request = parsed as Record<string, unknown>;
  if (typeof request.id !== "number" || typeof request.type !== "string")
    throw new Error("Fake socket request was invalid");
  return { id: request.id, type: request.type };
}
describe("HA WebSocket", () => {
  it("derives direct and add-on WebSocket URLs", () => {
    expect(deriveWebSocketUrl(new URL("https://ha.test/api")).href).toBe(
      "wss://ha.test/api/websocket",
    );
    expect(deriveWebSocketUrl(new URL("http://supervisor/core/api")).href).toBe(
      CORE_PROXY_WS_URL,
    );
  });

  it("deduplicates authentication and reuses the connection", async () => {
    const { client, factory, sockets } = harness();
    const firstConnect = client.connect(0);
    const secondConnect = client.connect(0);
    expect(factory).toHaveBeenCalledOnce();
    const socket = sockets[0]!;
    socket.message({ type: "auth_required" });
    socket.message({ type: "auth_ok" });
    await Promise.all([firstConnect, secondConnect]);

    const first = client.systemLogEntries();
    await Promise.resolve();
    const firstRequest = lastRequest(socket);
    expect(firstRequest.type).toBe("system_log/list");
    socket.message({
      id: firstRequest.id,
      type: "result",
      success: true,
      result: [],
    });
    await expect(first).resolves.toEqual([]);

    const second = client.systemLogEntries();
    await Promise.resolve();
    const secondRequest = lastRequest(socket);
    socket.message({
      id: secondRequest.id,
      type: "result",
      success: true,
      result: [1],
    });
    await expect(second).resolves.toEqual([1]);
    expect(factory).toHaveBeenCalledOnce();
  });

  it("rejects pending commands on disconnect and reconnects", async () => {
    const { client, factory, sockets } = harness();
    const connecting = client.connect(0);
    sockets[0]!.message({ type: "auth_ok" });
    await connecting;
    const pending = client.systemLogEntries();
    await Promise.resolve();
    sockets[0]!.close();
    await expect(pending).rejects.toThrow("disconnected");

    const reconnecting = client.connect(0);
    expect(factory).toHaveBeenCalledTimes(2);
    sockets[1]!.message({ type: "auth_ok" });
    await reconnecting;
  });

  it("ignores delayed events from a replaced socket", async () => {
    const { client, sockets } = harness();
    const firstConnecting = client.connect(0);
    const first = sockets[0]!;
    first.message({ type: "auth_ok" });
    await firstConnecting;
    first.close();

    const secondConnecting = client.connect(0);
    const second = sockets[1]!;
    second.message({ type: "auth_ok" });
    await secondConnecting;
    const pending = client.systemLogEntries();
    await Promise.resolve();
    const request = lastRequest(second);

    first.message({
      id: request.id,
      type: "result",
      success: true,
      result: ["stale-response"],
    });
    first.message({ type: "auth_invalid" });
    first.message("x".repeat(512_001));
    first.onerror?.({} as Event);
    first.onclose?.({} as CloseEvent);
    second.message({
      id: request.id,
      type: "result",
      success: true,
      result: ["replacement-response"],
    });

    await expect(pending).resolves.toEqual(["replacement-response"]);
  });

  it.each([
    ["close", (socket: FakeSocket) => socket.close(), "disconnected"],
    [
      "error",
      (socket: FakeSocket) => socket.onerror?.({} as Event),
      "connection failed",
    ],
    [
      "invalid auth",
      (socket: FakeSocket) => socket.message({ type: "auth_invalid" }),
      "authentication failed",
    ],
  ])("rejects pre-auth %s", async (_name, fail, message) => {
    const { client, sockets } = harness();
    const connecting = client.connect(0);
    fail(sockets[0]!);
    await expect(connecting).rejects.toThrow(message);
  });

  it("returns a safe command failure", async () => {
    const { client, sockets } = harness();
    await authenticate(client, sockets);
    const pending = client.systemLogEntries();
    await Promise.resolve();
    const request = lastRequest(sockets[0]!);
    sockets[0]!.message({
      id: request.id,
      type: "result",
      success: false,
      error: { message: "upstream secret" },
    });
    await expect(pending).rejects.toThrow("command failed");
  });

  it("rejects and closes on an oversized incoming message", async () => {
    const { client, sockets } = harness();
    await authenticate(client, sockets);
    const pending = client.systemLogEntries();
    await Promise.resolve();
    sockets[0]!.message("x".repeat(512_001));
    await expect(pending).rejects.toThrow("safe size limit");
    expect(sockets[0]!.readyState).toBe(WebSocket.CLOSED);
  });
});
