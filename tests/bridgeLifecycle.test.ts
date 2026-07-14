import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { BridgeLifecycle } from "../src/bridgeLifecycle.js";

function harness(timeoutMs = 1500) {
  const stdin = new EventEmitter();
  const processEvents = new EventEmitter();
  const forceExit = vi.fn();
  const lifecycle = new BridgeLifecycle({
    stdin,
    process: processEvents,
    forceExit,
    timeoutMs,
  });
  lifecycle.install();
  return { lifecycle, stdin, processEvents, forceExit };
}

describe("BridgeLifecycle", () => {
  it.each(["end", "close"])(
    "remembers early stdin %s and closes a later remote without starting local service",
    async (event) => {
      const { lifecycle, stdin } = harness();
      stdin.emit(event);
      const remote = { close: vi.fn(async () => undefined) };
      lifecycle.attachRemote(remote);
      expect(lifecycle.isShuttingDown).toBe(true);
      lifecycle.startupFinished();
      await lifecycle.done;
      expect(remote.close).toHaveBeenCalledTimes(1);
      expect(stdin.listenerCount("end")).toBe(0);
      expect(stdin.listenerCount("close")).toBe(0);
    },
  );

  it.each(["SIGINT", "SIGTERM"])(
    "serializes repeated %s and chained transport callbacks",
    async (signal) => {
      const { lifecycle, processEvents, forceExit } = harness();
      const priorClose = vi.fn();
      const priorError = vi.fn();
      const transportClose = vi.fn(async () => transport.onclose?.());
      const transport = {
        close: transportClose,
        send: vi.fn(),
        onclose: priorClose,
        onerror: priorError,
      } as unknown as Transport;
      const server = { close: vi.fn(async () => undefined) };
      const remote = { close: vi.fn(async () => undefined) };
      lifecycle.attachRemote(remote);
      lifecycle.attachLocal(server, transport);
      lifecycle.startupFinished();
      processEvents.emit(signal);
      processEvents.emit(signal);
      await lifecycle.done;
      expect(server.close).toHaveBeenCalledTimes(1);
      expect(transportClose).toHaveBeenCalledTimes(1);
      expect(remote.close).toHaveBeenCalledTimes(1);
      expect(priorClose).toHaveBeenCalledTimes(1);
      expect(forceExit).not.toHaveBeenCalled();
    },
  );

  it("forces a nonzero exit only when the total shutdown deadline is exhausted", async () => {
    vi.useFakeTimers();
    try {
      const { lifecycle, stdin, forceExit } = harness(1500);
      lifecycle.attachRemote({ close: () => new Promise(() => undefined) });
      lifecycle.startupFinished();
      stdin.emit("end");
      const deadline = expect(lifecycle.done).rejects.toThrow(
        "exceeded its deadline",
      );
      await vi.advanceTimersByTimeAsync(1499);
      expect(forceExit).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      expect(forceExit).toHaveBeenCalledOnce();
      expect(forceExit).toHaveBeenCalledWith(1);
      await deadline;
    } finally {
      vi.useRealTimers();
    }
  });

  it("chains an existing transport error callback and converges on shutdown", async () => {
    const { lifecycle } = harness();
    const priorError = vi.fn();
    const transport = {
      close: vi.fn(async () => undefined),
      send: vi.fn(),
      onerror: priorError,
    } as unknown as Transport;
    lifecycle.attachLocal({ close: vi.fn(async () => undefined) }, transport);
    lifecycle.startupFinished();
    const failure = new Error("stdio failed");
    transport.onerror?.(failure);
    await lifecycle.done;
    expect(priorError).toHaveBeenCalledWith(failure);
  });
});
