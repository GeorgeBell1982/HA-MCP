import { describe, expect, it, vi } from "vitest";
import { HaRestClient } from "../src/ha/rest.js";
describe("HA REST", () => {
  it("uses bearer only on fixed request and parses config", async () => {
    const fetcher = vi.fn(
      async (_url: URL | RequestInfo, init?: RequestInit) =>
        new Response(JSON.stringify({ version: "2026.7.1" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const client = new HaRestClient(
      new URL("http://supervisor/core/api"),
      "canary",
      1000,
      fetcher as typeof fetch,
    );
    expect(await client.config()).toMatchObject({ version: "2026.7.1" });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(String(fetcher.mock.calls[0]?.[0])).toBe(
      "http://supervisor/core/api/config",
    );
    expect(fetcher.mock.calls[0]?.[1]?.redirect).toBe("error");
  });
  it("returns generic auth failure", async () => {
    const client = new HaRestClient(
      new URL("https://ha.test/api"),
      "canary",
      1000,
      (async () => new Response("", { status: 401 })) as typeof fetch,
    );
    await expect(client.config()).rejects.toThrow("authentication failed");
  });
  it("rejects malformed state items", async () => {
    const client = new HaRestClient(
      new URL("https://ha.test/api"),
      "x",
      1000,
      (async () =>
        new Response(
          JSON.stringify([{ entity_id: "light.bad", state: "on" }]),
          { headers: { "content-type": "application/json" } },
        )) as typeof fetch,
    );
    await expect(client.states()).rejects.toThrow("state item was invalid");
  });
  it("retries one safe 5xx read", async () => {
    let calls = 0;
    const client = new HaRestClient(
      new URL("https://ha.test/api"),
      "x",
      1000,
      (async () => {
        calls++;
        return calls === 1
          ? new Response("", { status: 503 })
          : new Response(JSON.stringify({ version: "1" }), {
              headers: { "content-type": "application/json" },
            });
      }) as typeof fetch,
    );
    await client.config();
    expect(calls).toBe(2);
  });
  it("normalizes config and rejects malformed consumed fields", async () => {
    const client = new HaRestClient(
      new URL("https://ha.test/api"),
      "x",
      1000,
      (async () =>
        new Response(
          JSON.stringify({
            version: "1",
            latitude: "bad",
            unexpected: "secret",
          }),
          { headers: { "content-type": "application/json" } },
        )) as typeof fetch,
    );
    await expect(client.config()).rejects.toThrow(
      "config response was invalid",
    );
  });
});
