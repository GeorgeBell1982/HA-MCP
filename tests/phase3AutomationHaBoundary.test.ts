import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { HomeAssistantAutomationBoundary } from "../src/phase3/automationHaBoundary.js";
import { sha256 } from "../src/phase3/contracts.js";
import type { Phase3VerificationProbeRequest } from "../src/phase3/verificationAdapter.js";

const automation = {
  id: "test",
  alias: "Test",
  triggers: [{ trigger: "event", event_type: "unused_test" }],
  conditions: [],
  actions: [{ delay: 0 }],
};
const bytes = Buffer.from(JSON.stringify([automation]));
const config = loadConfig({
  HA_BASE_URL: "http://localhost:8123",
  HA_ACCESS_TOKEN: "test-only-token",
});
const success = {
  triggers: { valid: true, error: null },
  conditions: { valid: true, error: null },
  actions: { valid: true, error: null },
};
const states = [
  { entity_id: "automation.test", state: "on", attributes: { id: "test" } },
];
function context() {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 5_000,
  };
}
function request(): Phase3VerificationProbeRequest {
  return {
    transactionId: "test-transaction",
    path: "automations.yaml",
    outcome: "candidate",
    expectedSha256: sha256(bytes),
    impact: "domain_reload",
    reloadTarget: "automation.reload",
    rollbackReloadRequired: false,
  };
}

class Socket {
  readyState: number = WebSocket.OPEN;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  constructor(
    private readonly handle: (message: Record<string, unknown>) => unknown,
  ) {
    queueMicrotask(() => this.message({ type: "auth_required" }));
  }
  send(text: string) {
    const parsed: unknown = JSON.parse(text);
    const message = parsed as Record<string, unknown>;
    if (message.type === "auth") {
      queueMicrotask(() => this.message({ type: "auth_ok" }));
      return;
    }
    const result = this.handle(message);
    if (result !== undefined)
      queueMicrotask(() =>
        this.message({ id: message.id, type: "result", success: true, result }),
      );
  }
  message(value: unknown) {
    if (this.readyState === WebSocket.OPEN)
      this.onmessage?.({ data: JSON.stringify(value) } as MessageEvent);
  }
  close() {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.({} as CloseEvent);
  }
}
function harness(
  handle: (message: Record<string, unknown>) => unknown = (message) =>
    message.type === "validate_config"
      ? success
      : message.type === "get_states"
        ? states
        : { config: automation },
) {
  const commands: Record<string, unknown>[] = [];
  const sockets: Socket[] = [];
  const factory = vi.fn((url: string) => {
    expect(url).toBe("ws://localhost:8123/api/websocket");
    const socket = new Socket((message) => {
      commands.push(message);
      return handle(message);
    });
    sockets.push(socket);
    return socket as unknown as WebSocket;
  });
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation(
      async (url) =>
        new Response(
          JSON.stringify(
            String(url).endsWith("/states")
              ? handle({ type: "get_states" })
              : { result: "valid", errors: null, warnings: null },
          ),
        ),
    );
  const owned: Uint8Array[] = [];
  const source = {
    read: vi.fn(async () => {
      const copy = Buffer.from(bytes);
      owned.push(copy);
      return { bytes: copy, sha256: sha256(copy) };
    }),
  };
  return {
    boundary: new HomeAssistantAutomationBoundary(
      config,
      source,
      fetcher,
      factory,
    ),
    commands,
    sockets,
    source,
    owned,
    fetcher,
    factory,
  };
}

describe("automation HA validation and loaded configuration proof", () => {
  it("validates checkpoint and candidate components before effects and closes the socket", async () => {
    const h = harness();
    await h.boundary.validate(bytes, "candidate_pre_apply", context());
    await h.boundary.validate(bytes, "checkpoint_pre_apply", context());
    expect(h.commands.map((command) => command.type)).toEqual([
      "validate_config",
      "validate_config",
    ]);
    expect(h.commands[0]).toMatchObject({
      triggers: automation.triggers,
      conditions: [],
      actions: automation.actions,
    });
    expect(h.fetcher).not.toHaveBeenCalled();
    expect(h.source.read).not.toHaveBeenCalled();
    expect(h.owned.every((buffer) => buffer.every((byte) => byte === 0))).toBe(
      true,
    );
    expect(
      h.sockets.every((socket) => socket.readyState === WebSocket.CLOSED),
    ).toBe(true);
  });

  it.each(["candidate_post_apply", "checkpoint_post_rollback"] as const)(
    "validates components and installed config for %s",
    async (phase) => {
      const h = harness();
      await h.boundary.validate(bytes, phase, context());
      expect(h.commands).toHaveLength(1);
      expect(h.fetcher).toHaveBeenCalledTimes(1);
      expect(h.source.read).not.toHaveBeenCalled();
    },
  );

  it.each([
    {},
    { ...success, triggers: { valid: false, error: "secret details" } },
    { ...success, actions: { valid: true, error: "secret details" } },
    { ...success, conditions: null },
  ])(
    "rejects malformed/negative component evidence without upstream text",
    async (result) => {
      const h = harness(() => result);
      await expect(
        h.boundary.validate(bytes, "candidate_pre_apply", context()),
      ).rejects.toMatchObject({
        code: "ha_automation_invalid",
        message: "Automation HA boundary failed: ha_automation_invalid",
      });
      expect(h.fetcher).not.toHaveBeenCalled();
    },
  );

  it.each([
    "- id: test\n  alias: Test\n  triggers: !include other.yaml\n  actions: []\n",
    "- &shared {id: test, alias: Test, triggers: [], actions: []}\n",
    "- {id: test, alias: Test, triggers: [], actions: [], variables: {secret: hidden}}\n",
    JSON.stringify([automation, automation]),
    JSON.stringify([{ ...automation, id: 1 }]),
    JSON.stringify([{ ...automation, alias: "" }]),
    JSON.stringify([{ ...automation, mode: "unknown" }]),
    JSON.stringify([{ ...automation, trigger: [] }]),
    JSON.stringify([{ id: "test", alias: "Test", actions: [] }]),
  ])(
    "rejects unsupported file classes before opening HA connections",
    async (input) => {
      const h = harness();
      await expect(
        h.boundary.validate(
          Buffer.from(input),
          "candidate_pre_apply",
          context(),
        ),
      ).rejects.toMatchObject({ code: "unsupported_automation" });
      expect(h.factory).not.toHaveBeenCalled();
      expect(h.fetcher).not.toHaveBeenCalled();
    },
  );

  it("binds exact raw loaded configuration and source digest, with frozen evidence", async () => {
    const h = harness();
    const result = await h.boundary.probe(request(), context());
    expect(result).toEqual({
      status: "verified",
      transactionId: request().transactionId,
      outcome: "candidate",
      expectedSha256: sha256(bytes),
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(h.commands.map((command) => command.type)).toEqual([
      "automation/config",
    ]);
    expect(h.commands[0]).toMatchObject({ entity_id: "automation.test" });
    expect(String(h.fetcher.mock.calls[0]![0])).toBe(
      "http://localhost:8123/api/states",
    );
    expect(h.owned.every((buffer) => buffer.every((byte) => byte === 0))).toBe(
      true,
    );
    await expect(
      h.boundary.probe(
        { ...request(), expectedSha256: sha256("stale") },
        context(),
      ),
    ).rejects.toMatchObject({ code: "ha_source_changed" });
  });

  it.each(
    [
      [],
      [...states, ...states],
      [{ ...states[0], state: "unavailable" }],
      [{ ...states[0], attributes: { id: "other" } }],
    ].map((observed) => [observed]),
  )(
    "rejects missing, duplicate, unavailable or mismatched loaded automations",
    async (observed) => {
      const h = harness(() => observed);
      await expect(
        h.boundary.probe(request(), context()),
      ).rejects.toMatchObject({ code: "ha_loaded_config_mismatch" });
    },
  );

  it("rejects stale loaded actions even when entity identity and state match", async () => {
    const h = harness((message) =>
      message.type === "get_states"
        ? states
        : { config: { ...automation, actions: [{ delay: 1 }] } },
    );
    await expect(h.boundary.probe(request(), context())).rejects.toMatchObject({
      code: "ha_loaded_config_mismatch",
    });
  });

  it("verifies automation configuration with more than 512 KB of unrelated state inventory", async () => {
    const inventory = [
      ...Array.from({ length: 4_000 }, (_, index) => ({
        entity_id: `sensor.unrelated_${index}`,
        state: "on",
        attributes: { description: "r".repeat(100) },
      })),
      ...states,
    ];
    expect(Buffer.byteLength(JSON.stringify(inventory))).toBeGreaterThan(
      512_000,
    );
    const h = harness((message) =>
      message.type === "get_states" ? inventory : { config: automation },
    );
    await expect(h.boundary.probe(request(), context())).resolves.toMatchObject(
      { status: "verified" },
    );
  });

  it("rejects state inventory exceeding the bounded REST observation limit", async () => {
    const h = harness((message) =>
      message.type === "get_states"
        ? [
            {
              entity_id: "sensor.oversized",
              attributes: { description: "r".repeat(2_000_001) },
            },
          ]
        : { config: automation },
    );
    await expect(h.boundary.probe(request(), context())).rejects.toMatchObject({
      code: "ha_response_invalid",
    });
  });

  it("accepts JSON object key reordering while retaining array order", async () => {
    const h = harness((message) =>
      message.type === "get_states"
        ? states
        : {
            config: {
              actions: automation.actions,
              conditions: [],
              triggers: automation.triggers,
              alias: "Test",
              id: "test",
            },
          },
    );
    await expect(h.boundary.probe(request(), context())).resolves.toMatchObject(
      { status: "verified" },
    );
  });

  it("cancels a stalled component request promptly and closes the connection", async () => {
    let entered!: () => void;
    const pending = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const h = harness(() => {
      entered();
      return undefined;
    });
    const controller = new AbortController();
    const result = expect(
      h.boundary.validate(bytes, "candidate_pre_apply", {
        ...context(),
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    await pending;
    controller.abort();
    await result;
    expect(
      h.sockets.every((socket) => socket.readyState === WebSocket.CLOSED),
    ).toBe(true);
  });
});
