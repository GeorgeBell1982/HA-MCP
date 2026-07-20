import { describe, expect, it } from "vitest";
import { loadConfig, publicPolicy } from "../src/config.js";
describe("configuration", () => {
  it("fixes add-on origin and disables mutation", () => {
    const c = loadConfig({ HA_MODE: "addon", SUPERVISOR_TOKEN: "canary" });
    expect(c.baseUrl.href).toBe("http://supervisor/core/api");
    expect(c).toMatchObject({
      enablePhase2: false,
      enableWrites: false,
      enableRestart: false,
      enableDeletes: false,
    });
  });
  it("enables Phase 2 only for explicit add-on configuration", () => {
    expect(
      loadConfig({
        HA_MODE: "addon",
        SUPERVISOR_TOKEN: "canary",
        HA_ENABLE_PHASE2: "true",
      }).enablePhase2,
    ).toBe(true);
    expect(
      loadConfig({
        HA_MODE: "local",
        HA_BASE_URL: "https://ha.test",
        HA_ACCESS_TOKEN: "x",
        HA_ENABLE_PHASE2: "true",
      }).enablePhase2,
    ).toBe(false);
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
  it("does not advertise Phase 2 active from environment intent alone", () => {
    expect(
      publicPolicy({ HA_MODE: "addon", HA_ENABLE_PHASE2: "true" }),
    ).toMatchObject({
      configMapping: false,
      phase2Enabled: false,
      phase2Requested: true,
    });
    expect(
      publicPolicy(
        { HA_MODE: "addon", HA_ENABLE_PHASE2: "true" },
        { phase2Active: true, configMapping: true },
      ),
    ).toMatchObject({
      configMapping: true,
      phase2Enabled: true,
      phase2Requested: true,
    });
  });
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
