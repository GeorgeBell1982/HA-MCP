import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { buildPhase3McpRegistry as build } from "../src/phase3/mcpTools.js";
import type { Config } from "../src/config.js";
const audit = { health: async () => {}, append: vi.fn(async () => {}) };
const buildPhase3McpRegistry = (config: Config, active: boolean) =>
  build(config, active, audit);
const env = {
  HA_MODE: "addon",
  SUPERVISOR_TOKEN: "test-only",
  HA_ENABLE_PHASE2: "true",
  HA_ENABLE_MCP_WRITES: "true",
};
describe("guarded MCP activation", () => {
  it("audits preflight refusals and fails closed when attempt audit is unavailable", async () => {
    const registry = buildPhase3McpRegistry(loadConfig(env), true)!;
    audit.append.mockClear();
    await registry.call("ha_apply_proposal", {
      proposalId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
    expect(audit.append).toHaveBeenCalledWith(
      expect.objectContaining({ result: "attempt", risk: "guarded-write" }),
    );
    expect(audit.append).toHaveBeenCalledWith(
      expect.objectContaining({ result: "failure" }),
    );
    const requestApproval = vi.fn(async () => "unused");
    const failed = build(loadConfig(env), true, {
      health: async () => {},
      append: async () => {
        throw new Error("disk");
      },
    })!;
    expect(
      await failed.call(
        "ha_check_approval",
        {},
        { signal: new AbortController().signal, requestApproval },
      ),
    ).toMatchObject({ ok: false, error: { code: "audit_unavailable" } });
    expect(requestApproval).not.toHaveBeenCalled();
  });
  it("returns uncertainty when outcome audit fails without repeating the operation", async () => {
    let records = 0;
    const registry = build(loadConfig(env), true, {
      health: async () => {},
      append: async () => {
        if (++records === 2) throw new Error("disk");
      },
    })!;
    const requestApproval = vi.fn(
      async ({ confirmation }: { confirmation: string }) => confirmation,
    );
    expect(
      await registry.call(
        "ha_check_approval",
        {},
        { signal: new AbortController().signal, requestApproval },
      ),
    ).toMatchObject({
      ok: false,
      error: { code: "post_operation_audit_uncertain" },
    });
    expect(requestApproval).toHaveBeenCalledOnce();
  });
  it("requires all activation gates and leaves generic capabilities disabled", () => {
    const config = loadConfig(env);
    expect(config).toMatchObject({
      enableMcpWrites: true,
      enableWrites: false,
      enableRestart: false,
      enableDeletes: false,
    });
    expect(buildPhase3McpRegistry(config, false)).toBeUndefined();
    expect(
      buildPhase3McpRegistry(
        loadConfig({ ...env, HA_ENABLE_MCP_WRITES: "false" }),
        true,
      ),
    ).toBeUndefined();
    expect(
      buildPhase3McpRegistry(
        loadConfig({ ...env, HA_ENABLE_PHASE2: "false" }),
        true,
      ),
    ).toBeUndefined();
    const local = loadConfig({
      ...env,
      HA_MODE: "local",
      HA_BASE_URL: "http://localhost:8123",
      HA_ACCESS_TOKEN: "test-only",
    });
    expect(local.enableMcpWrites).toBe(false);
    expect(buildPhase3McpRegistry(local, true)).toBeUndefined();
  });
  it("refuses approval-bearing input and unsupported clients before runtime access", async () => {
    const registry = buildPhase3McpRegistry(loadConfig(env), true)!;
    expect(
      await registry.call("ha_apply_proposal", {
        proposalId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        approved: true,
      }),
    ).toMatchObject({ ok: false, error: { code: "invalid_input" } });
    expect(
      await registry.call("ha_apply_proposal", {
        proposalId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      }),
    ).toMatchObject({
      ok: false,
      error: { code: "chat_approval_unavailable" },
    });
    expect(await registry.call("ha_rotate_epoch", {})).toMatchObject({
      ok: false,
      error: { code: "chat_approval_unavailable" },
    });
  });
  it("checks approval without invoking any production runtime", async () => {
    const registry = buildPhase3McpRegistry(loadConfig(env), true)!;
    const requestApproval = vi.fn(
      async ({ confirmation }: { confirmation: string }) => confirmation,
    );
    expect(
      await registry.call(
        "ha_check_approval",
        {},
        { signal: new AbortController().signal, requestApproval },
      ),
    ).toMatchObject({
      ok: true,
      result: { approvalConfirmed: true, homeAssistantChanged: false },
    });
    expect(requestApproval).toHaveBeenCalledOnce();
    expect(
      await registry.call(
        "ha_check_approval",
        {},
        {
          signal: new AbortController().signal,
          requestApproval: async () => "yes",
        },
      ),
    ).toMatchObject({ ok: false, error: { code: "confirmation_rejected" } });
    expect(registry.descriptor("ha_apply_proposal")?.annotations).toMatchObject(
      { readOnlyHint: false, idempotentHint: false },
    );
    expect(registry.descriptor("ha_rotate_epoch")?.annotations).toMatchObject({
      readOnlyHint: false,
      idempotentHint: false,
    });
  });
});
