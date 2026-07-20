import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ReadTools } from "../src/application.js";
import { phase2ToolNames } from "../src/phase2Contracts.js";
import { phase3Contract } from "../src/phase3/contracts.js";

const phase3Files = [
  "contracts.ts",
  "approval.ts",
  "resourceLocks.ts",
  "applyCoordinator.ts",
] as const;

describe("Phase 3A isolation", () => {
  it("does not register tools or enable writes", () => {
    const phase1Names = ReadTools.prototype.names.call({});
    expect(phase1Names.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase2ToolNames.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase3Contract.registered).toBe(false);
    expect(phase3Contract.writesEnabled).toBe(false);
    expect(phase3Contract.liveAdapters).toBe("absent");
  });

  it("keeps root and add-on Phase 3A source mirrors exact", () => {
    for (const file of phase3Files) {
      const root = readFileSync(`src/phase3/${file}`, "utf8");
      const addon = readFileSync(`addon/app/src/phase3/${file}`, "utf8");
      expect(addon).toBe(root);
    }
  });
});
