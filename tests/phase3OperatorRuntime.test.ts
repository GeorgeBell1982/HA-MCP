import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import {
  parsePhase3OperatorCommand,
  runPhase3OperatorCommand,
  assertPhase3BootstrapParentIsFresh,
  phase3OperatorFailureDetails,
  completePhase3Cleanup,
  Phase3OperatorCleanupUncertain,
} from "../src/phase3/operatorRuntime.js";
import {
  Phase3OperatorAuditUncertain,
  Phase3OperatorError,
} from "../src/phase3/operatorApproval.js";

const proposalId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const config = loadConfig({
  HA_MODE: "local",
  HA_BASE_URL: "http://localhost:8123",
  HA_ACCESS_TOKEN: "test-only",
});
const terminal = {
  inputIsTTY: true,
  outputIsTTY: true,
  write: async () => {},
  readConfirmation: async () => "unused",
};
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
describe("explicit Phase 3 operator command boundary", () => {
  it.each([0, 1, 2, 3])(
    "attempts every cleanup when cleanup %s fails, with lease release last",
    async (failure) => {
      const calls: number[] = [];
      expect(
        await completePhase3Cleanup(
          [0, 1, 2, 3].map((index) => async () => {
            calls.push(index);
            if (index === failure) throw new Error("cleanup");
          }),
        ),
      ).toBe(false);
      expect(calls).toEqual([0, 1, 2, 3]);
    },
  );
  it("preserves settled identity when cleanup failed after an effect", () => {
    expect(
      phase3OperatorFailureDetails(
        new Phase3OperatorCleanupUncertain(
          proposalId,
          "verification_succeeded",
        ),
      ),
    ).toEqual({
      code: "post_settlement_cleanup_uncertain",
      transactionId: proposalId,
      state: "verification_succeeded",
    });
  });
  it.each(["init", "rotate", "resume"])(
    "accepts explicit offline %s without enabling live writes",
    (operation) => {
      expect(parsePhase3OperatorCommand([operation])).toEqual({ operation });
    },
  );
  it("requires the literal per-command opt-in for both paths that can change HA", () => {
    expect(
      parsePhase3OperatorCommand([
        "apply-proposal",
        proposalId,
        "--enable-writes",
      ]),
    ).toEqual({ operation: "apply-proposal", proposalId });
    expect(parsePhase3OperatorCommand(["recover", "--enable-writes"])).toEqual({
      operation: "recover",
    });
    expect(config.enableWrites).toBe(false);
  });
  it.each(
    [
      [],
      ["apply-proposal", proposalId],
      ["recover"],
      ["apply-proposal", proposalId, "--yes"],
      ["apply-proposal", proposalId, "--enable-writes", "--yes"],
      ["apply-proposal", proposalId.toUpperCase(), "--enable-writes"],
      ["apply-proposal", "bad", "--enable-writes"],
      ["init", "--enable-writes"],
      ["rotate", "--path", "/arbitrary"],
      ["grant", proposalId],
      ["apply-proposal", proposalId, "--grant", proposalId],
      ["resume", "--yes"],
    ].map((args) => ({ args })),
  )(
    "refuses extra, missing, bearer-grant, path, and automation inputs %j",
    ({ args }) => {
      expect(() => parsePhase3OperatorCommand(args)).toThrow();
    },
  );
  it("rejects pipes before any filesystem, key, or HA access", async () => {
    await expect(
      runPhase3OperatorCommand(["init"], config, {
        ...terminal,
        inputIsTTY: false,
      }),
    ).rejects.toMatchObject({ code: "interactive_terminal_required" });
    await expect(
      runPhase3OperatorCommand(["init"], config, {
        ...terminal,
        outputIsTTY: false,
      }),
    ).rejects.toMatchObject({ code: "interactive_terminal_required" });
  });
  it("refuses generalized local deployments before persistent access", async () => {
    await expect(
      runPhase3OperatorCommand(["init"], config, terminal),
    ).rejects.toMatchObject({ code: "managed_linux_operator_required" });
  });
  it("the actual built CLI refuses --yes before loading runtime credentials", async () => {
    try {
      await promisify(execFile)(
        process.execPath,
        ["dist/cli.js", "phase3", "apply-proposal", proposalId, "--yes"],
        { env: {}, timeout: 10000 },
      );
      throw new Error("CLI unexpectedly succeeded");
    } catch (error) {
      expect(error).toMatchObject({ code: 1 });
      const output = (error as { stderr: string }).stderr;
      expect(output).toContain("invalid_command_or_writes_disabled");
      expect((JSON.parse(output) as { code: string }).code).toBe(
        "invalid_command_or_writes_disabled",
      );
      expect(output).not.toContain("credential");
    }
  });
  it("the actual built CLI hides unknown canary-bearing Phase 3 exceptions", async () => {
    const canary = "phase3-private-upstream-canary";
    const preload = `data:text/javascript,${encodeURIComponent(`process.argv.slice = () => { throw new Error("${canary}"); };`)}`;
    try {
      await promisify(execFile)(
        process.execPath,
        ["--import", preload, "dist/cli.js", "phase3", "init"],
        { env: {}, timeout: 10000 },
      );
      throw new Error("CLI unexpectedly succeeded");
    } catch (error) {
      expect(error).toMatchObject({ code: 1 });
      const result = error as { stdout: string; stderr: string };
      expect(result.stdout + result.stderr).not.toContain(canary);
      expect(JSON.parse(result.stderr)).toEqual({
        ok: false,
        error: "Phase 3 operator command failed",
        code: "operator_storage_or_boundary_unavailable",
      });
    }
  });
  it("bootstrap preflight refuses existing epochs before any new key action", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase3-bootstrap-test-"));
    roots.push(root);
    await writeFile(join(root, "operator.lock"), "", { mode: 0o600 });
    const lease = { assertHeld: async () => {} };
    await expect(
      assertPhase3BootstrapParentIsFresh(root, lease),
    ).resolves.toBeUndefined();
    await mkdir(join(root, "active"));
    await expect(
      assertPhase3BootstrapParentIsFresh(root, lease),
    ).rejects.toMatchObject({ code: "bootstrap_state_not_fresh" });
    expect(await readdir(root)).toEqual(["active", "operator.lock"]);
  });
  it("emits only typed bounded failure identity and outcome fields", () => {
    expect(
      phase3OperatorFailureDetails(
        new Phase3OperatorAuditUncertain(proposalId, "verification_succeeded"),
      ),
    ).toEqual({
      code: "post_settlement_audit_uncertain",
      transactionId: proposalId,
      state: "verification_succeeded",
    });
    expect(
      phase3OperatorFailureDetails(
        new Phase3OperatorError("confirmation_rejected"),
      ),
    ).toEqual({ code: "confirmation_rejected" });
    expect(
      phase3OperatorFailureDetails({
        code: "secret-injected",
        token: "never-emit",
      }),
    ).toEqual({ code: "operator_storage_or_boundary_unavailable" });
  });
});
