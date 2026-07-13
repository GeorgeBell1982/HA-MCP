import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { describe, expect, it } from "vitest";
import {
  RemoteSession,
  type RemoteConnectionFactory,
} from "../src/remoteSession.js";

interface FakeClient {
  id: number;
}

interface ConnectionPlan {
  sessionId?: string;
  connectError?: Error;
  closeError?: Error;
}

function connections(plans: ConnectionPlan[]) {
  let created = 0;
  let connected = 0;
  const closed: number[] = [];
  const factory: RemoteConnectionFactory<FakeClient> = () => {
    const id = created++;
    const plan = plans[id];
    if (!plan) throw new Error(`Unexpected connection ${id}`);
    return {
      client: { id },
      transport: { sessionId: plan.sessionId },
      connect: async () => {
        connected++;
        if (plan.connectError) throw plan.connectError;
      },
      close: async () => {
        closed.push(id);
        if (plan.closeError) throw plan.closeError;
      },
    };
  };
  return {
    factory,
    counts: () => ({ created, connected, closed: [...closed] }),
  };
}

const expired = () => new StreamableHTTPError(404, "expired session");

describe("RemoteSession", () => {
  it("uses one connection and preserves strict FIFO operation order normally", async () => {
    const setup = connections([{ sessionId: "current" }]);
    const remote = await RemoteSession.connect(setup.factory);
    const events: string[] = [];
    let active = 0;
    let maximumActive = 0;
    const operation = (label: string) =>
      remote.run(async (client) => {
        active++;
        maximumActive = Math.max(maximumActive, active);
        events.push(`start-${label}-${client.id}`);
        await Promise.resolve();
        events.push(`end-${label}-${client.id}`);
        active--;
        return label;
      });

    await expect(
      Promise.all([operation("a"), operation("b")]),
    ).resolves.toEqual(["a", "b"]);
    expect(events).toEqual(["start-a-0", "end-a-0", "start-b-0", "end-b-0"]);
    expect(maximumActive).toBe(1);
    expect(setup.counts()).toEqual({ created: 1, connected: 1, closed: [] });
  });

  it("recovers one concurrent stale session without a reconnect storm or duplicate execution", async () => {
    const setup = connections([
      { sessionId: "stale" },
      { sessionId: "replacement" },
    ]);
    const remote = await RemoteSession.connect(setup.factory);
    const executed = new Map<string, number>();
    const operation = (label: string) =>
      remote.run(async (client) => {
        if (client.id === 0) throw expired();
        executed.set(label, (executed.get(label) ?? 0) + 1);
        return `${label}-${client.id}`;
      });

    await expect(
      Promise.all([operation("a"), operation("b"), operation("c")]),
    ).resolves.toEqual(["a-1", "b-1", "c-1"]);
    expect(Object.fromEntries(executed)).toEqual({ a: 1, b: 1, c: 1 });
    expect(setup.counts()).toEqual({
      created: 2,
      connected: 2,
      closed: [0],
    });
  });

  it("retries an expired operation only once", async () => {
    const setup = connections([
      { sessionId: "stale" },
      { sessionId: "also-stale" },
    ]);
    const remote = await RemoteSession.connect(setup.factory);

    await expect(
      remote.run(async () => Promise.reject(expired())),
    ).rejects.toMatchObject({ code: 404 });
    expect(setup.counts()).toEqual({
      created: 2,
      connected: 2,
      closed: [0],
    });
  });

  it.each([
    ["404 without a session", new StreamableHTTPError(404, "missing"), ""],
    ["401", new StreamableHTTPError(401, "unauthorized"), "session"],
    ["429", new StreamableHTTPError(429, "limited"), "session"],
    ["network failure", new Error("ECONNRESET"), "session"],
  ])("surfaces %s without reconnecting", async (_name, failure, sessionId) => {
    const setup = connections([{ sessionId }]);
    const remote = await RemoteSession.connect(setup.factory);

    await expect(remote.run(async () => Promise.reject(failure))).rejects.toBe(
      failure,
    );
    expect(setup.counts()).toEqual({ created: 1, connected: 1, closed: [] });
  });

  it("keeps the old connection and clears the queue after reconnect initialization fails", async () => {
    const connectFailure = new Error("candidate connect failed");
    const setup = connections([
      { sessionId: "stale" },
      { sessionId: "candidate", connectError: connectFailure },
      { sessionId: "replacement" },
    ]);
    const remote = await RemoteSession.connect(setup.factory);
    const operation = async (client: FakeClient) => {
      if (client.id === 0) throw expired();
      return client.id;
    };

    await expect(remote.run(operation)).rejects.toBe(connectFailure);
    await expect(remote.run(operation)).resolves.toBe(2);
    expect(setup.counts()).toEqual({
      created: 3,
      connected: 3,
      closed: [1, 0],
    });
  });

  it("keeps the replacement when closing the retired connection fails", async () => {
    const setup = connections([
      { sessionId: "stale", closeError: new Error("close failed") },
      { sessionId: "replacement" },
    ]);
    const remote = await RemoteSession.connect(setup.factory);
    const operation = async (client: FakeClient) => {
      if (client.id === 0) throw expired();
      return client.id;
    };

    await expect(remote.run(operation)).resolves.toBe(1);
    await expect(remote.run(operation)).resolves.toBe(1);
    expect(setup.counts()).toEqual({
      created: 2,
      connected: 2,
      closed: [0],
    });
  });
});
