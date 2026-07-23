import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ModuleKind, ScriptTarget, transpileModule } from "typescript";
import { ReadTools } from "../src/application.js";
import { phase2ToolNames } from "../src/phase2Contracts.js";
import { phase3Contract } from "../src/phase3/contracts.js";

const phase3Files = [
  "contracts.ts",
  "approval.ts",
  "durableApproval.ts",
  "approvalCustody.ts",
  "resourceLocks.ts",
  "applyCoordinator.ts",
  "proposalAdapter.ts",
  "journal.ts",
  "checkpoints.ts",
  "sourceAdapter.ts",
  "atomicApply.ts",
  "validationAdapter.ts",
  "reloadAdapter.ts",
  "verificationAdapter.ts",
] as const;

const phase3NativeFiles = ["openat2-replace.c", "approval-custody.c"] as const;

describe("Phase 3A through Phase 3O isolation", () => {
  it("does not register tools or enable writes", () => {
    const phase1Names = ReadTools.prototype.names.call({});
    expect(phase1Names.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase2ToolNames.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase3Contract.registered).toBe(false);
    expect(phase3Contract.writesEnabled).toBe(false);
    expect(phase3Contract.liveAdapters).toBe("absent");
  });

  it("keeps the Phase 3B through Phase 3O adapters out of runtime composition", () => {
    for (const path of [
      "src/index.ts",
      "src/phase2Activation.ts",
      "src/toolRegistry.ts",
      "src/cli.ts",
      "src/config.ts",
      "package.json",
      "pnpm-workspace.yaml",
      "addon/Dockerfile",
      "addon/config.yaml",
      "addon/app/package.json",
      "addon/app/src/index.ts",
      "addon/app/src/phase2Activation.ts",
      "addon/app/src/toolRegistry.ts",
      "addon/app/src/cli.ts",
      "addon/app/src/config.ts",
    ]) {
      const source = readFileSync(path, "utf8");
      expect(source).not.toContain("proposalAdapter");
      expect(source).not.toContain("phase3/journal");
      expect(source).not.toContain("phase3/checkpoints");
      expect(source).not.toContain("sourceAdapter");
      expect(source).not.toContain("phase3/sourceAdapter");
      expect(source).not.toContain("atomicApply");
      expect(source).not.toContain("phase3/atomicApply");
      expect(source).not.toContain("validationAdapter");
      expect(source).not.toContain("phase3/validationAdapter");
      expect(source).not.toContain("reloadAdapter");
      expect(source).not.toContain("phase3/reloadAdapter");
      expect(source).not.toContain("verificationAdapter");
      expect(source).not.toContain("phase3/verificationAdapter");
      expect(source).not.toContain("openat2-replace");
      expect(source).not.toContain("durableApproval");
      expect(source).not.toContain("approvalCustody");
      expect(source).not.toContain("approval-custody");
    }
  });

  it("keeps the Phase 3N approval source on an inert narrow import boundary", () => {
    const source = readFileSync("src/phase3/durableApproval.ts", "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/gu)]
      .map((match) => match[1])
      .sort();
    expect(imports).toEqual([
      "../proposals/durability.js",
      "./approval.js",
      "./contracts.js",
      "node:crypto",
      "node:fs",
      "node:fs/promises",
      "node:path",
      "node:util",
      "zod",
    ]);
    for (const forbidden of [
      "../ha/",
      "phase3Contract",
      "toolRegistry",
      "application",
      "fetch(",
      "axios",
    ])
      expect(source).not.toContain(forbidden);
  });

  it("keeps the Phase 3O custody adapter on an inert narrow import boundary", () => {
    const source = readFileSync("src/phase3/approvalCustody.ts", "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/gu)]
      .map((match) => match[1])
      .sort();
    expect(imports).toEqual([
      "./durableApproval.js",
      "node:child_process",
      "node:fs",
      "node:fs/promises",
      "node:path",
      "node:perf_hooks",
      "node:stream",
    ]);
    for (const forbidden of [
      "../ha/",
      "phase3Contract",
      "toolRegistry",
      "application",
      "fetch(",
      "axios",
      "process.kill",
      "detached: true",
    ])
      expect(source).not.toContain(forbidden);
  });

  it("keeps root and add-on Phase 3A through Phase 3O source mirrors exact", () => {
    for (const file of phase3Files) {
      const root = readFileSync(`src/phase3/${file}`, "utf8");
      const addon = readFileSync(`addon/app/src/phase3/${file}`, "utf8");
      expect(addon).toBe(root);
    }
    for (const file of phase3NativeFiles) {
      const root = readFileSync(`src/phase3/native/${file}`, "utf8");
      const addon = readFileSync(`addon/app/src/phase3/native/${file}`, "utf8");
      expect(addon).toBe(root);
    }
  });

  it("freezes the Phase 3O native manifest at exactly N001 through N025", () => {
    const source = readFileSync(
      "scripts/linux/phase3-custody-harness.mjs",
      "utf8",
    );
    const registry =
      /CUSTODY_EVIDENCE_IDS = Object\.freeze\(\[(.*?)\]\);/su.exec(source)?.[1];
    expect(
      [...(registry ?? "").matchAll(/"(N\d{3} [^"]+)"/gu)].map(
        (match) => match[1],
      ),
    ).toEqual([
      "N001 env_linux",
      "N002 env_arch",
      "N003 env_libc",
      "N004 env_compiler",
      "N005 env_uid0",
      "N006 env_filesystem_recorded_supported",
      "N007 uid0_acquire",
      "N008 nonroot_acquire_via_uid_drop",
      "N009 same_root_contention",
      "N010 different_root_independence",
      "N011 clean_release_handoff",
      "N012 helper_sigkill_reacquire",
      "N013 holder_parent_death",
      "N014 waiter_parent_death",
      "N015 root_replaced_while_waiting_rejected",
      "N016 symlink_root_rejected",
      "N017 nondirectory_root_rejected",
      "N018 unsafe_mode_rejected",
      "N019 wrong_owner_rejected",
      "N020 unsupported_filesystem_rejected",
      "N021 zero_eof_abandonment",
      "N022 malformed_control",
      "N023 duplicate_control",
      "N024 trailing_control",
      "N025 phase3n_remediation_api_mechanics",
    ]);
    expect(source).toContain("registryValid");
    expect(source).toContain('row.status === "PASSED"');
    expect(source).toContain("if (!allPassed) process.exitCode = 1");
  });

  it("keeps the Phase 3K source bridge on an inert type-only import boundary", () => {
    const source = readFileSync("src/phase3/sourceAdapter.ts", "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/gu)]
      .map((match) => match[1])
      .sort();
    expect(imports).toEqual([
      "../phase2Contracts.js",
      "../repository/repositoryReads.js",
      "../security/repositoryBoundary.js",
      "./applyCoordinator.js",
      "./resourceLocks.js",
      "./verificationAdapter.js",
      "node:crypto",
    ]);
    expect(source).toContain(
      'import type { Phase3PostEffectSourceDigestPort } from "./verificationAdapter.js";',
    );
    const emitted = transpileModule(source, {
      compilerOptions: {
        module: ModuleKind.ES2022,
        target: ScriptTarget.ES2022,
      },
    }).outputText;
    expect(emitted).not.toContain("verificationAdapter");
    for (const forbidden of [
      "../ha/",
      "reloadAdapter",
      "Phase3TrustedVerificationProbePort",
      "system_log",
      "logbook",
      "fetch(",
      "axios",
    ])
      expect(source.toLowerCase()).not.toContain(forbidden.toLowerCase());
  });

  it("keeps the Phase 3J adapter on an exact narrow import allowlist", () => {
    const source = readFileSync("src/phase3/verificationAdapter.ts", "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/gu)]
      .map((match) => match[1])
      .sort();
    expect(imports).toEqual(["./applyCoordinator.js", "./contracts.js"]);

    for (const forbidden of [
      "../ha/rest",
      "../ha/websocket",
      "application",
      "fetch(",
      "axios",
      "system_log/list",
      "system_log",
      "entity",
      "logbook",
      "get_logs",
    ])
      expect(source.toLowerCase()).not.toContain(forbidden);
  });
});
