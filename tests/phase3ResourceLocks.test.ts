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
  it("serializes all paths in FIFO order and preserves each lease identity", async () => {
    const locks = new Phase3ResourceLocks();
    const first = await locks.acquire("automations/a.yaml", context());
    let secondAcquired = false;
    const second = locks
      .acquire("automations/a.yaml", context())
      .then((lease) => {
        secondAcquired = true;
        return lease;
      });
    let distinctAcquired = false;
    const distinct = locks
      .acquire("automations/b.yaml", context())
      .then((lease) => {
        distinctAcquired = true;
        return lease;
      });
    expect(secondAcquired).toBe(false);
    expect(distinctAcquired).toBe(false);
    first.release();
    const secondLease = await second;
    expect(secondAcquired).toBe(true);
    expect(distinctAcquired).toBe(false);
    expect(secondLease.path).toBe("automations/a.yaml");
    first.release();
    expect(distinctAcquired).toBe(false);
    secondLease.release();
    const distinctLease = await distinct;
    expect(distinctLease.path).toBe("automations/b.yaml");
    distinctLease.release();
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
    const queued = locks.acquire("automations/b.yaml", context());
    await expect(
      locks.acquire("automations/a.yaml", context()),
    ).rejects.toMatchObject({
      code: "max_waiters_exceeded",
    });
    first.release();
    (await queued).release();
  });
});
