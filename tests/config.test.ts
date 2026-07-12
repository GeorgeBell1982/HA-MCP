import { describe, expect, it } from "vitest";
import { loadConfig, publicPolicy } from "../src/config.js";
describe("configuration", () => {
  it("fixes add-on origin and disables mutation", () => {
    const c = loadConfig({ HA_MODE: "addon", SUPERVISOR_TOKEN: "canary" });
    expect(c.baseUrl.href).toBe("http://supervisor/core/api");
    expect(c).toMatchObject({
      enableWrites: false,
      enableRestart: false,
      enableDeletes: false,
    });
  });
  it("rejects credential-bearing origins", () =>
    expect(() =>
      loadConfig({
        HA_MODE: "local",
        HA_BASE_URL: "https://u:p@ha.test",
        HA_ACCESS_TOKEN: "x",
      }),
    ).toThrow());
  it("never enables mutation from environment", () =>
    expect(
      publicPolicy({
        HA_ENABLE_WRITES: "true",
        HA_ENABLE_RESTART: "true",
        HA_ENABLE_DELETES: "true",
      }).mutations,
    ).toEqual({ writes: false, restart: false, deletes: false }));
  it("normalizes a local origin to the documented API root", () =>
    expect(
      loadConfig({
        HA_MODE: "local",
        HA_BASE_URL: "https://ha.test",
        HA_ACCESS_TOKEN: "x",
      }).baseUrl.href,
    ).toBe("https://ha.test/api"));
  it("rejects unexpected local paths", () =>
    expect(() =>
      loadConfig({
        HA_MODE: "local",
        HA_BASE_URL: "https://ha.test/custom",
        HA_ACCESS_TOKEN: "x",
      }),
    ).toThrow());
});
