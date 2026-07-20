import { phase3CanonicalRelativePathSchema } from "./contracts.js";

export type Phase3LockErrorCode =
  | "invalid_path"
  | "deadline_exceeded"
  | "operation_cancelled"
  | "max_waiters_exceeded";

export class Phase3LockError extends Error {
  constructor(
    public readonly code: Phase3LockErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Phase3LockError";
  }
}

export interface Phase3LockContext {
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
}

export interface Phase3LockLease {
  readonly path: string;
  release(): void;
}

interface Waiter {
  readonly path: string;
  active: boolean;
  timer: NodeJS.Timeout | undefined;
  readonly resolve: (lease: Phase3LockLease) => void;
  readonly reject: (error: Phase3LockError) => void;
  readonly abort: () => void;
  readonly context: Phase3LockContext;
}

interface LockState {
  held: boolean;
  readonly queue: Waiter[];
}

export class Phase3ResourceLocks {
  private readonly locks = new Map<string, LockState>();

  constructor(private readonly maxWaitersPerPath = 32) {}

  async acquire(
    path: string,
    context: Phase3LockContext,
  ): Promise<Phase3LockLease> {
    const canonical = canonicalPhase3Path(path);
    assertActive(context);
    const state = this.state(canonical);
    if (!state.held) {
      state.held = true;
      try {
        assertActive(context);
      } catch (error) {
        state.held = false;
        if (state.queue.length === 0) this.locks.delete(canonical);
        throw error;
      }
      return this.lease(canonical);
    }
    if (state.queue.length >= this.maxWaitersPerPath)
      throw new Phase3LockError(
        "max_waiters_exceeded",
        "Too many waiters for the locked resource",
      );
    return await new Promise<Phase3LockLease>((resolve, reject) => {
      const waiter: Waiter = {
        path: canonical,
        active: true,
        timer: undefined,
        resolve,
        reject,
        context,
        abort: () => {
          if (!waiter.active) return;
          waiter.active = false;
          this.removeWaiter(canonical, waiter);
          cleanup(waiter);
          reject(
            new Phase3LockError(
              "operation_cancelled",
              "Lock wait was cancelled",
            ),
          );
        },
      };
      try {
        assertActive(context);
      } catch (error) {
        reject(
          error instanceof Phase3LockError
            ? error
            : new Phase3LockError(
                "operation_cancelled",
                "Lock wait failed before enqueue",
              ),
        );
        return;
      }
      context.signal.addEventListener("abort", waiter.abort, { once: true });
      const delay = context.deadlineAt - Date.now();
      if (delay <= 0) {
        waiter.abort();
        return;
      }
      waiter.timer = setTimeout(() => {
        if (!waiter.active) return;
        waiter.active = false;
        this.removeWaiter(canonical, waiter);
        cleanup(waiter);
        reject(
          new Phase3LockError(
            "deadline_exceeded",
            "Lock wait deadline expired",
          ),
        );
      }, delay);
      state.queue.push(waiter);
    });
  }

  waiterCount(path: string): number {
    const parsed = phase3CanonicalRelativePathSchema.safeParse(path);
    if (!parsed.success) return 0;
    return this.locks.get(parsed.data)?.queue.length ?? 0;
  }

  private state(path: string): LockState {
    const existing = this.locks.get(path);
    if (existing) return existing;
    const created = { held: false, queue: [] };
    this.locks.set(path, created);
    return created;
  }

  private lease(path: string): Phase3LockLease {
    let released = false;
    return Object.freeze({
      path,
      release: () => {
        if (released) return;
        released = true;
        this.release(path);
      },
    });
  }

  private release(path: string): void {
    const state = this.locks.get(path);
    if (!state) return;
    for (;;) {
      const waiter = state.queue.shift();
      if (!waiter) {
        state.held = false;
        if (state.queue.length === 0) this.locks.delete(path);
        return;
      }
      if (!waiter.active) continue;
      try {
        assertActive(waiter.context);
      } catch (error) {
        waiter.active = false;
        cleanup(waiter);
        waiter.reject(
          error instanceof Phase3LockError
            ? error
            : new Phase3LockError(
                "operation_cancelled",
                "Lock wait failed before return",
              ),
        );
        continue;
      }
      waiter.active = false;
      cleanup(waiter);
      state.held = true;
      waiter.resolve(this.lease(path));
      return;
    }
  }

  private removeWaiter(path: string, waiter: Waiter): void {
    const state = this.locks.get(path);
    if (!state) return;
    const index = state.queue.indexOf(waiter);
    if (index >= 0) state.queue.splice(index, 1);
  }
}

export function canonicalPhase3Path(path: string): string {
  const parsed = phase3CanonicalRelativePathSchema.safeParse(path);
  if (!parsed.success)
    throw new Phase3LockError("invalid_path", "Resource path is invalid");
  return parsed.data;
}

function assertActive(context: Phase3LockContext): void {
  if (context.signal.aborted)
    throw new Phase3LockError("operation_cancelled", "Operation was cancelled");
  if (Date.now() >= context.deadlineAt)
    throw new Phase3LockError(
      "deadline_exceeded",
      "Operation deadline expired",
    );
}

function cleanup(waiter: Waiter): void {
  waiter.context.signal.removeEventListener("abort", waiter.abort);
  if (waiter.timer) clearTimeout(waiter.timer);
  waiter.timer = undefined;
}
