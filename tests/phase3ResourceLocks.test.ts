import { describe, expect, it, vi } from "vitest";
import {
  Phase3LockError,
  Phase3ResourceLocks,
} from "../src/phase3/resourceLocks.js";

const context = () => ({
  signal: new AbortController().signal,
  deadlineAt: Date.now() + 10_000,
});

describe("Phase 3A resource locks", () => {
  it("serializes identical canonical paths and allows distinct paths", async () => {
    const locks = new Phase3ResourceLocks();
    const first = await locks.acquire("automations/a.yaml", context());
    let secondAcquired = false;
    const second = locks
      .acquire("automations/a.yaml", context())
      .then((lease) => {
        secondAcquired = true;
        return lease;
      });
    const distinct = await locks.acquire("automations/b.yaml", context());
    expect(secondAcquired).toBe(false);
    distinct.release();
    first.release();
    const secondLease = await second;
    expect(secondAcquired).toBe(true);
    secondLease.release();
  });

  it("removes cancelled and deadline waiters", async () => {
    const locks = new Phase3ResourceLocks(2);
    const first = await locks.acquire("automations/a.yaml", context());
    const controller = new AbortController();
    const cancelled = locks.acquire("automations/a.yaml", {
      signal: controller.signal,
      deadlineAt: Date.now() + 10_000,
    });
    expect(locks.waiterCount("automations/a.yaml")).toBe(1);
    controller.abort();
    await expect(cancelled).rejects.toBeInstanceOf(Phase3LockError);
    expect(locks.waiterCount("automations/a.yaml")).toBe(0);
    const expired = locks.acquire("automations/a.yaml", {
      signal: new AbortController().signal,
      deadlineAt: Date.now() - 1,
    });
    await expect(expired).rejects.toMatchObject({ code: "deadline_exceeded" });
    first.release();
  });

  it("cleans an immediately expired acquisition so the next acquire succeeds", async () => {
    const locks = new Phase3ResourceLocks();
    const signal = new AbortController().signal;
    const now = vi
      .spyOn(Date, "now")
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(200);
    try {
      await expect(
        locks.acquire("automations/a.yaml", { signal, deadlineAt: 150 }),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
    } finally {
      now.mockRestore();
    }

    const lease = await locks.acquire("automations/a.yaml", context());
    expect(lease.path).toBe("automations/a.yaml");
    lease.release();
  });
  it("rejects invalid paths and bounded waiter overflow", async () => {
    const locks = new Phase3ResourceLocks(1);
    await expect(locks.acquire("../bad.yaml", context())).rejects.toMatchObject(
      {
        code: "invalid_path",
      },
    );
    const first = await locks.acquire("automations/a.yaml", context());
    const queued = locks.acquire("automations/a.yaml", context());
    await expect(
      locks.acquire("automations/a.yaml", context()),
    ).rejects.toMatchObject({
      code: "max_waiters_exceeded",
    });
    first.release();
    (await queued).release();
  });
});
