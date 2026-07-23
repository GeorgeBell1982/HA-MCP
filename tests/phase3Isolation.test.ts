import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ModuleKind,
  ScriptTarget,
  SyntaxKind,
  createSourceFile,
  forEachChild,
  isCallExpression,
  isExportDeclaration,
  isExternalModuleReference,
  isIdentifier,
  isImportDeclaration,
  isImportEqualsDeclaration,
  isPropertyAccessExpression,
  isStringLiteralLike,
  transpileModule,
  type Expression,
  type Node,
} from "typescript";
import { ReadTools } from "../src/application.js";
import { phase2ToolNames } from "../src/phase2Contracts.js";
import { phase3Contract } from "../src/phase3/contracts.js";

const phase3Files = [
  "contracts.ts",
  "approval.ts",
  "durableApproval.ts",
  "approvalCustody.ts",
  "approvalKey.ts",
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

describe("Phase 3A through Phase 3P isolation", () => {
  it("does not register tools or enable writes", () => {
    const phase1Names = ReadTools.prototype.names.call({});
    expect(phase1Names.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase2ToolNames.some((name) => name.includes("phase3"))).toBe(false);
    expect(phase3Contract.registered).toBe(false);
    expect(phase3Contract.writesEnabled).toBe(false);
    expect(phase3Contract.liveAdapters).toBe("absent");
  });

  it("keeps the Phase 3B through Phase 3P adapters out of runtime composition", () => {
    for (const path of [
      "src/index.ts",
      "src/application.ts",
      "src/bridge.ts",
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
      "addon/app/src/application.ts",
      "addon/app/src/bridge.ts",
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
      expect(source).not.toContain("approvalKey");
      expect(source).not.toContain("phase3/approvalKey");
      expect(source).not.toContain("provisionPhase3ApprovalKey");
      expect(source).not.toContain("loadPhase3ApprovalKey");
    }
  });

  it("keeps the Phase 3P approval key on an inert test-only import boundary", () => {
    const source = readFileSync("src/phase3/approvalKey.ts", "utf8");
    const imports = moduleSpecifiers(
      "src/phase3/approvalKey.ts",
      source,
    ).sort();
    expect(imports).toEqual([
      "node:crypto",
      "node:fs",
      "node:fs/promises",
      "node:path",
    ]);
    for (const forbidden of [
      "./durableApproval",
      "../ha/",
      "phase3Contract",
      "toolRegistry",
      "application",
      "fetch(",
      "axios",
      "mkdir",
      "unlink",
      "rename",
    ])
      expect(source).not.toContain(forbidden);

    const importers = [
      ...typescriptFiles("src"),
      ...typescriptFiles("addon/app/src"),
      ...typescriptFiles("tests"),
    ]
      .flatMap((path) =>
        moduleSpecifiers(path, readFileSync(path, "utf8"))
          .filter(isApprovalKeySpecifier)
          .map(() => path),
      )
      .sort();
    expect(importers).toEqual(["tests/phase3ApprovalKey.test.ts"]);

    const guardedForms = [
      `import "../src/phase3/approvalKey.js";`,
      `export * from "../src/phase3/approvalKey.js";`,
      `void import("../src/phase3/approvalKey.js");`,
      `require("../src/phase3/approvalKey.js");`,
      `module.require("../src/phase3/approvalKey.js");`,
      `require.resolve("../src/phase3/approvalKey.js");`,
      `import key = require("../src/phase3/approvalKey.js");`,
    ].join("\n");
    expect(
      moduleSpecifiers("approval-key-isolation-fixture.ts", guardedForms)
        .filter(isApprovalKeySpecifier)
        .sort(),
    ).toEqual(Array.from({ length: 7 }, () => "../src/phase3/approvalKey.js"));
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

  it("keeps root and add-on Phase 3A through Phase 3P source mirrors exact", () => {
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

function typescriptFiles(root: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name).replaceAll("\\", "/");
    if (entry.isDirectory()) files.push(...typescriptFiles(path));
    else if (
      entry.isFile() &&
      [".ts", ".tsx", ".mts", ".cts"].some((suffix) => path.endsWith(suffix))
    )
      files.push(path);
  }
  return files;
}

function moduleSpecifiers(path: string, source: string): string[] {
  const parsed = createSourceFile(path, source, ScriptTarget.Latest, true);
  const specifiers: string[] = [];
  const visit = (node: Node): void => {
    if (
      (isImportDeclaration(node) || isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      isStringLiteralLike(node.moduleSpecifier)
    )
      specifiers.push(node.moduleSpecifier.text);
    else if (
      isImportEqualsDeclaration(node) &&
      isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined &&
      isStringLiteralLike(node.moduleReference.expression)
    )
      specifiers.push(node.moduleReference.expression.text);
    else if (
      isCallExpression(node) &&
      isModuleLoader(node.expression) &&
      node.arguments[0] !== undefined &&
      isStringLiteralLike(node.arguments[0])
    )
      specifiers.push(node.arguments[0].text);
    forEachChild(node, visit);
  };
  visit(parsed);
  return specifiers;
}

function isModuleLoader(expression: Expression): boolean {
  if (expression.kind === SyntaxKind.ImportKeyword) return true;
  if (isIdentifier(expression)) return expression.text === "require";
  if (!isPropertyAccessExpression(expression)) return false;
  return (
    (isIdentifier(expression.expression) &&
      expression.expression.text === "module" &&
      expression.name.text === "require") ||
    (isIdentifier(expression.expression) &&
      expression.expression.text === "require" &&
      expression.name.text === "resolve")
  );
}

function isApprovalKeySpecifier(specifier: string): boolean {
  const normalized = specifier.replaceAll("\\", "/");
  return (
    normalized === "approvalKey.js" || normalized.endsWith("/approvalKey.js")
  );
}
