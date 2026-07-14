import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { EventEmitter } from "node:events";

interface Closeable {
  close(): Promise<void>;
}

export interface BridgeLifecycleOptions {
  stdin: EventEmitter;
  process: EventEmitter;
  forceExit: (code: number) => void;
  timeoutMs?: number;
  setTimer?: (callback: () => void, milliseconds: number) => unknown;
  clearTimer?: (timer: unknown) => void;
}

/** Coordinates every bridge termination path under one bounded shutdown budget. */
export class BridgeLifecycle {
  private requested = false;
  private installed = false;
  private remote?: Closeable;
  private local?: {
    server: Closeable;
    transport: Transport;
    transportClosed: boolean;
  };
  private startupResolve!: () => void;
  private readonly startup = new Promise<void>((resolve) => {
    this.startupResolve = resolve;
  });
  private doneResolve!: () => void;
  private doneReject!: (error: Error) => void;
  readonly done = new Promise<void>((resolve, reject) => {
    this.doneResolve = resolve;
    this.doneReject = reject;
  });
  private shutdownPromise?: Promise<void>;
  private timer?: unknown;

  private readonly onInputEnd = () => void this.shutdown();
  private readonly onSignal = () => void this.shutdown();

  constructor(private readonly options: BridgeLifecycleOptions) {}

  install(): void {
    if (this.installed) return;
    this.installed = true;
    this.options.stdin.on("end", this.onInputEnd);
    this.options.stdin.on("close", this.onInputEnd);
    this.options.process.on("SIGINT", this.onSignal);
    this.options.process.on("SIGTERM", this.onSignal);
  }

  attachRemote(remote: Closeable): void {
    this.remote = remote;
    if (this.requested) void this.shutdown();
  }

  get isShuttingDown(): boolean {
    return this.requested;
  }

  attachLocal(server: Closeable, transport: Transport): void {
    const local = { server, transport, transportClosed: false };
    this.local = local;
    const previousClose = transport.onclose;
    const previousError = transport.onerror;
    transport.onclose = () => {
      local.transportClosed = true;
      try {
        previousClose?.();
      } finally {
        void this.shutdown();
      }
    };
    transport.onerror = (error) => {
      try {
        previousError?.(error);
      } finally {
        void this.shutdown();
      }
    };
    if (this.requested) void this.shutdown();
  }

  startupFinished(): void {
    this.startupResolve();
  }

  shutdown(): Promise<void> {
    if (this.shutdownPromise) return this.shutdownPromise;
    this.requested = true;
    const setTimer =
      this.options.setTimer ??
      ((callback: () => void, milliseconds: number) =>
        setTimeout(callback, milliseconds));
    this.timer = setTimer(() => {
      const error = new Error("Bridge shutdown exceeded its deadline");
      this.cleanupListeners();
      this.doneReject(error);
      this.options.forceExit(1);
    }, this.options.timeoutMs ?? 1500);
    this.shutdownPromise = this.performShutdown();
    return this.shutdownPromise;
  }

  private async performShutdown(): Promise<void> {
    await this.startup;
    if (this.local) {
      await closeContained(this.local.server);
      if (!this.local.transportClosed)
        await closeContained(this.local.transport);
    }
    if (this.remote) await closeContained(this.remote);
    if (this.timer !== undefined) {
      (this.options.clearTimer ?? clearTimeout)(this.timer as never);
    }
    this.cleanupListeners();
    this.doneResolve();
  }

  private cleanupListeners(): void {
    if (!this.installed) return;
    this.installed = false;
    this.options.stdin.off("end", this.onInputEnd);
    this.options.stdin.off("close", this.onInputEnd);
    this.options.process.off("SIGINT", this.onSignal);
    this.options.process.off("SIGTERM", this.onSignal);
  }
}

async function closeContained(closeable: Closeable): Promise<void> {
  try {
    await closeable.close();
  } catch {
    // Shutdown is best-effort and remains bounded by the lifecycle deadline.
  }
}
