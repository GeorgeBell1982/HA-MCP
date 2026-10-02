import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import {
  HomeAssistantPhase3Client,
  HomeAssistantPhase3Validation,
} from "../src/phase3/homeAssistantAdapter.js";

function context() {
  return {
    signal: new AbortController().signal,
    deadlineAt: Date.now() + 5_000,
  };
}
function config() {
  return loadConfig({
    HA_BASE_URL: "http://localhost:8123",
    HA_ACCESS_TOKEN: "test-only-token",
  });
}
function response(value: unknown) {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
  });
}

describe("isolated Home Assistant Phase 3 HTTP boundary", () => {
  it("uses real HTTP with fixed endpoints, authorization, and an empty reload payload", async () => {
    const calls: {
      path: string;
      method: string;
      authorization: string;
      body: string;
    }[] = [];
    const server = createServer((request, reply) => {
      void (async () => {
        let body = "";
        for await (const chunk of request) body += String(chunk);
        calls.push({
          path: request.url!,
          method: request.method!,
          authorization: request.headers.authorization!,
          body,
        });
        reply.setHeader("Content-Type", "application/json");
        reply.end(
          JSON.stringify(
            request.url?.endsWith("check_config")
              ? { result: "valid", errors: null }
              : [],
          ),
        );
      })().catch(() => {
        reply.statusCode = 500;
        reply.end();
      });
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    try {
      const cfg = loadConfig({
        HA_BASE_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        HA_ACCESS_TOKEN: "test-only-token",
      });
      const client = new HomeAssistantPhase3Client(cfg);
      await client.checkInstalledConfiguration(context());
      expect(await client.reload("automation.reload", context())).toEqual({
        status: "completed",
      });
      expect(calls).toEqual([
        {
          path: "/api/config/core/check_config",
          method: "POST",
          authorization: "Bearer test-only-token",
          body: "{}",
        },
        {
          path: "/api/services/automation/reload",
          method: "POST",
          authorization: "Bearer test-only-token",
          body: "{}",
        },
      ]);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it("keeps the Supervisor Core proxy prefix", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(response({ result: "valid", errors: null }));
    const client = new HomeAssistantPhase3Client(
      loadConfig({ HA_MODE: "addon", SUPERVISOR_TOKEN: "test-only-token" }),
      fetcher,
    );
    await client.checkInstalledConfiguration(context());
    expect(String(fetcher.mock.calls[0]![0])).toBe(
      "http://supervisor/core/api/config/core/check_config",
    );
    expect(fetcher.mock.calls[0]![1]?.redirect).toBe("error");
  });

  it.each([
    { result: "invalid", errors: "SECRET CONFIG" },
    { result: "valid", errors: "SECRET CONFIG" },
    { result: "valid", errors: null, warnings: "SECRET CONFIG" },
    {},
    [],
  ])(
    "rejects invalid or malformed configuration evidence without exposing its body",
    async (value) => {
      const client = new HomeAssistantPhase3Client(
        config(),
        vi.fn<typeof fetch>().mockResolvedValue(response(value)),
      );
      await expect(
        client.checkInstalledConfiguration(context()),
      ).rejects.toMatchObject({
        code: "ha_configuration_invalid",
        message:
          "Home Assistant Phase 3 operation failed: ha_configuration_invalid",
      });
    },
  );

  it.each([401, 403, 404, 500, 302])(
    "never retries a reload after HTTP %s",
    async (status) => {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response("SECRET CONFIG", { status }));
      const client = new HomeAssistantPhase3Client(config(), fetcher);
      expect(await client.reload("automation.reload", context())).toEqual({
        status: "outcome_unknown",
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );

  it("does not dispatch cancelled, expired, or unsupported effects", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = new HomeAssistantPhase3Client(config(), fetcher);
    const controller = new AbortController();
    controller.abort();
    for (const active of [
      { ...context(), signal: controller.signal },
      { ...context(), deadlineAt: Date.now() - 1 },
    ])
      expect(await client.reload("automation.reload", active)).toEqual({
        status: "not_dispatched",
      });
    expect(await client.reload("script.reload", context())).toEqual({
      status: "not_dispatched",
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("classifies disconnects and malformed successful replies as unknown effects", async () => {
    for (const fetcher of [
      vi.fn<typeof fetch>().mockRejectedValue(new Error("SECRET CONFIG")),
      vi.fn<typeof fetch>().mockResolvedValue(response({})),
    ]) {
      expect(
        await new HomeAssistantPhase3Client(config(), fetcher).reload(
          "automation.reload",
          context(),
        ),
      ).toEqual({ status: "outcome_unknown" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });

  it("bounds streamed replies even without content-length", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(1_000_001));
        controller.enqueue(new Uint8Array(1_000_001));
      },
      cancel() {
        cancelled = true;
      },
    });
    const client = new HomeAssistantPhase3Client(
      config(),
      vi.fn<typeof fetch>().mockResolvedValue(new Response(body)),
    );
    await expect(
      client.checkInstalledConfiguration(context()),
    ).rejects.toMatchObject({ code: "ha_response_invalid" });
    expect(cancelled).toBe(true);
  });

  it("aborts a real pending HTTP request at the caller deadline", async () => {
    const server = createServer(() => {});
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    try {
      const cfg = loadConfig({
        HA_BASE_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        HA_ACCESS_TOKEN: "test-only-token",
      });
      await expect(
        new HomeAssistantPhase3Client(cfg).checkInstalledConfiguration({
          ...context(),
          deadlineAt: Date.now() + 100,
        }),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it.each(["abort", "deadline"])(
    "preserves unknown reload outcome after headers when caller %s interrupts a stalled body",
    async (kind) => {
      let entered!: () => void;
      const requestEntered = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const server = createServer((_, reply) => {
        reply.setHeader("Content-Type", "application/json");
        reply.flushHeaders();
        reply.write("[");
        entered();
      });
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", resolve),
      );
      try {
        const cfg = loadConfig({
          HA_BASE_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
          HA_ACCESS_TOKEN: "test-only-token",
        });
        const fetcher = vi.fn<typeof fetch>((...args) => fetch(...args));
        const controller = new AbortController();
        const result = new HomeAssistantPhase3Client(cfg, fetcher).reload(
          "automation.reload",
          {
            signal: controller.signal,
            deadlineAt: Date.now() + (kind === "deadline" ? 150 : 5_000),
          },
        );
        await requestEntered;
        if (kind === "abort") controller.abort();
        expect(await result).toEqual({ status: "outcome_unknown" });
        expect(fetcher).toHaveBeenCalledTimes(1);
      } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );

  it("checks installed semantics after apply and rollback while retaining pre-apply YAML rejection", async () => {
    const check = vi.fn().mockResolvedValue(undefined);
    const validation = new HomeAssistantPhase3Validation({
      checkInstalledConfiguration: check,
    });
    await validation.validate(
      Buffer.from("[]\n"),
      "candidate_pre_apply",
      context(),
    );
    expect(check).not.toHaveBeenCalled();
    await validation.validate(
      Buffer.from("[]\n"),
      "candidate_post_apply",
      context(),
    );
    await validation.validate(
      Buffer.from("[]\n"),
      "checkpoint_post_rollback",
      context(),
    );
    expect(check).toHaveBeenCalledTimes(2);
    check.mockRejectedValue(new Error("rejected"));
    await expect(
      validation.validate(
        Buffer.from("[]\n"),
        "candidate_post_apply",
        context(),
      ),
    ).rejects.toThrow("rejected");
    await expect(
      validation.validate(
        Buffer.from("broken: ["),
        "candidate_pre_apply",
        context(),
      ),
    ).rejects.toThrow();
  });

  it("copies endpoint configuration and rejects credentials or extra endpoint paths", () => {
    for (const baseUrl of [
      new URL("http://user:password@localhost/api"),
      new URL("http://localhost/api?token=secret"),
      new URL("http://localhost/api/other"),
    ])
      expect(
        () => new HomeAssistantPhase3Client({ ...config(), baseUrl }),
      ).toThrow("ha_endpoint_invalid");
    expect(
      () =>
        new HomeAssistantPhase3Client({ ...config(), token: "bad\r\nheader" }),
    ).toThrow("ha_endpoint_invalid");
  });
});
