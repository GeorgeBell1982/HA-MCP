import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HaDashboardClient, dashboardHash } from "../src/ha/dashboards.js";
import {
  buildDashboardChangeRegistry,
  applyDashboardPatch,
} from "../src/dashboardTools.js";
import {
  GuardedActionService,
  buildGuardedChangeRegistry,
} from "../src/guardedChanges.js";
import { JsonlAudit } from "../src/audit.js";
import { ReadTools } from "../src/application.js";
import { redact } from "../src/redaction.js";
import type { HaRestClient } from "../src/ha/rest.js";
import type {
  ToolCallContext,
  ToolApprovalRequest,
} from "../src/toolRegistry.js";

const roots: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    roots.splice(0).map((r) => rm(r, { recursive: true, force: true })),
  );
});
const config = () => ({
  views: [
    {
      type: "panel",
      cards: [
        {
          type: "vertical-stack",
          cards: [{ type: "markdown", content: "Solar" }],
        },
      ],
    },
  ],
  private: { password: "checkpoint-canary" },
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "ha-dashboard-"));
  roots.push(root);
  const audit = new JsonlAudit(join(root, "audit.jsonl"));
  const lease = {
    assertHeld: vi.fn(async () => {}),
    release: vi.fn(async () => {}),
  };
  const actions = new GuardedActionService(
    join(root, "changes"),
    audit,
    async () => lease,
  );
  let current = config();
  const request = vi.fn(
    async (type: string, input?: Record<string, unknown>) => {
      if (type === "lovelace/dashboards/list")
        return [
          {
            id: "solar",
            url_path: "dashboard-sunsynk",
            title: "Sunsynk",
            mode: "storage",
          },
        ];
      if (type === "lovelace/config") return structuredClone(current);
      if (type === "lovelace/config/save") {
        current = structuredClone(input!.config) as ReturnType<typeof config>;
        return null;
      }
      throw new Error("Unexpected command");
    },
  );
  const ha = new HaDashboardClient({ connect: async () => {}, request });
  const tools = buildDashboardChangeRegistry(ha, actions, audit);
  const propose = () =>
    tools.call("ha_propose_dashboard_change", {
      urlPath: "dashboard-sunsynk",
      expectedSha256: dashboardHash(current),
      patch: [
        {
          op: "add",
          path: "/views/0/cards/0/card_mod",
          value: { style: ":host { padding-top: 8px; }" },
        },
      ],
    });
  return {
    root,
    audit,
    actions,
    lease,
    ha,
    tools,
    request,
    propose,
    current: () => current,
    drift: () => {
      current.views[0]!.type = "masonry";
    },
  };
}
function context(
  requestApproval?: ToolCallContext["requestApproval"],
): ToolCallContext {
  return {
    signal: new AbortController().signal,
    ...(requestApproval ? { requestApproval } : {}),
  };
}
describe("guarded dashboard changes", () => {
  it("audits invalid and status calls and refuses operations when audit preflight fails", async () => {
    const f = await fixture();
    const tools = buildGuardedChangeRegistry(f.actions, f.audit);
    expect(
      (
        await tools.call(
          "ha_apply_change",
          { proposalId: "invalid" },
          context(),
        )
      ).ok,
    ).toBe(false);
    const unknown = "11111111-1111-4111-8111-111111111111";
    expect(
      (await tools.call("ha_get_change_status", { proposalId: unknown })).ok,
    ).toBe(false);
    expect(
      (await readFile(join(f.root, "audit.jsonl"), "utf8")).trim().split("\n"),
    ).toHaveLength(4);
    const get = vi.spyOn(f.actions, "get");
    vi.spyOn(f.audit, "health").mockRejectedValue(new Error("disk"));
    expect(
      await tools.call("ha_get_change_status", { proposalId: unknown }),
    ).toMatchObject({ error: { code: "audit_unavailable" } });
    expect(get).not.toHaveBeenCalled();
  });
  it("reports post-operation audit uncertainty without claiming refusal or replaying", async () => {
    const f = await fixture();
    const proposal = await f.propose();
    const id = (proposal as unknown as { result: { proposalId: string } })
      .result.proposalId;
    const append = f.audit.append.bind(f.audit);
    vi.spyOn(f.audit, "append").mockImplementation(async (row) => {
      if (row.tool === "ha_apply_change" && row.result === "success")
        throw new Error("disk");
      await append(row);
    });
    const result = await buildGuardedChangeRegistry(f.actions, f.audit).call(
      "ha_apply_change",
      { proposalId: id },
      context(async (r) => r.confirmation),
    );
    expect(JSON.stringify(result)).toContain("do not retry");
    expect(
      f.request.mock.calls.filter(([t]) => t === "lovelace/config/save"),
    ).toHaveLength(1);
    expect(await f.actions.get(id)).toMatchObject({ status: "verified" });
  });
  it("archives settled checkpoints with approval and reads history when setup is disabled", async () => {
    const f = await fixture();
    f.actions.register("setup", {
      inspect: async () => {},
      execute: async () => ({}),
      verify: async () => ({}),
    });
    const proposal = await f.actions.propose({
      kind: "setup",
      target: "app:test",
      summary: {},
      payload: {},
    });
    await f.actions.apply(
      proposal.proposalId,
      context(async (r) => r.confirmation),
    );
    const fresh = new GuardedActionService(
      join(f.root, "changes"),
      f.audit,
      async () => f.lease,
    );
    const archive = await fresh.proposeArchive();
    const staleArchive = await fresh.proposeArchive();
    expect(
      (await readdir(join(f.root, "changes"))).filter((name) =>
        name.endsWith(".jsonl"),
      ),
    ).toHaveLength(1);
    await fresh.apply(
      archive.proposalId,
      context(async (r) => r.confirmation),
    );
    const approval = vi.fn(async (r: ToolApprovalRequest) => r.confirmation);
    await expect(
      fresh.apply(staleArchive.proposalId, context(approval)),
    ).rejects.toThrow("Archive source changed");
    expect(approval).not.toHaveBeenCalled();
    expect(await fresh.get(proposal.proposalId)).toMatchObject({
      kind: "setup",
      status: "verified",
    });
    expect(await readdir(join(f.root, "changes", "archive"))).toEqual([
      `${proposal.proposalId}.jsonl`,
    ]);
  });
  it("reads storage dashboards via HA API, redacts secrets and hashes original source", async () => {
    const f = await fixture();
    const tools = new ReadTools(
      {} as HaRestClient,
      { systemLogEntries: async () => [] },
      f.audit,
      f.ha,
    );
    const result = await tools.call("ha_get_dashboard", {
      urlPath: "dashboard-sunsynk",
    });
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).not.toContain("checkpoint-canary");
    expect(result.data).toMatchObject({ sha256: dashboardHash(f.current()) });
    expect((await tools.call("ha_list_dashboards", {})).ok).toBe(true);
  });
  it("proposes without saving, then checks exact approval and verifies a single save", async () => {
    const f = await fixture();
    const result = await f.propose();
    expect(result.ok).toBe(true);
    const id = (result as unknown as { result: { proposalId: string } }).result
      .proposalId;
    expect(
      f.request.mock.calls.filter(([t]) => t === "lovelace/config/save"),
    ).toHaveLength(0);
    let prompt = "";
    const applied = await f.actions.apply(
      id,
      context(async (r) => {
        prompt = r.message;
        return r.confirmation;
      }),
    );
    expect(applied).toMatchObject({ status: "verified" });
    expect(prompt).toContain("padding-top: 8px");
    expect(prompt).not.toContain("checkpoint-canary");
    expect(
      f.request.mock.calls.filter(([t]) => t === "lovelace/config/save"),
    ).toHaveLength(1);
    expect(f.current().private.password).toBe("checkpoint-canary");
    expect(f.lease.release).toHaveBeenCalledOnce();
    expect(await f.actions.get(id)).toMatchObject({ status: "verified" });
    expect(JSON.stringify(await f.actions.get(id))).not.toContain(
      "checkpoint-canary",
    );
    const record = await readFile(
      join(f.root, "changes", `${id}.jsonl`),
      "utf8",
    );
    expect(record).toContain("checkpoint-canary");
    await expect(
      f.actions.apply(
        id,
        context(async (r) => r.confirmation),
      ),
    ).rejects.toThrow("already attempted");
  });
  it.each(["unsupported", "wrong", "cancelled"])(
    "refuses %s approval with zero save",
    async (mode) => {
      const f = await fixture();
      const p = await f.propose();
      const id = (p as unknown as { result: { proposalId: string } }).result
        .proposalId;
      const controller = new AbortController();
      const c =
        mode === "unsupported"
          ? context()
          : {
              signal: controller.signal,
              requestApproval: async () => {
                if (mode === "cancelled") controller.abort();
                return "wrong";
              },
            };
      await expect(f.actions.apply(id, c)).rejects.toThrow();
      expect(
        f.request.mock.calls.some(([t]) => t === "lovelace/config/save"),
      ).toBe(false);
      if (mode === "unsupported")
        expect(await readdir(f.root)).not.toContain("changes");
      else expect(await readdir(join(f.root, "changes"))).toEqual([]);
    },
  );
  it("rechecks source after approval and refuses concurrent UI drift", async () => {
    const f = await fixture();
    const p = await f.propose();
    const id = (p as unknown as { result: { proposalId: string } }).result
      .proposalId;
    await expect(
      f.actions.apply(
        id,
        context(async (r) => {
          f.drift();
          return r.confirmation;
        }),
      ),
    ).rejects.toThrow("changed since proposal");
    expect(
      f.request.mock.calls.some(([t]) => t === "lovelace/config/save"),
    ).toBe(false);
  });
  it("checks source again after durable checkpoint sync before saving", async () => {
    const f = await fixture();
    const p = await f.propose();
    const id = (p as unknown as { result: { proposalId: string } }).result
      .proposalId;
    let checks = 0;
    f.lease.assertHeld.mockImplementation(async () => {
      if (++checks === 2) f.drift();
    });
    await expect(
      f.actions.apply(
        id,
        context(async (r) => r.confirmation),
      ),
    ).rejects.toThrow("changed since proposal");
    expect(
      f.request.mock.calls.some(([t]) => t === "lovelace/config/save"),
    ).toBe(false);
    expect(await f.actions.get(id)).toMatchObject({ status: "not_sent" });
  });
  it("retains uncertain send checkpoint across restart and blocks another mutation", async () => {
    const f = await fixture();
    const p = await f.propose();
    const id = (p as unknown as { result: { proposalId: string } }).result
      .proposalId;
    const original = f.request.getMockImplementation()!;
    f.request.mockImplementation(async (t, i) => {
      const r = await original(t, i);
      if (t === "lovelace/config/save") throw new Error("lost response");
      return r;
    });
    await expect(
      f.actions.apply(
        id,
        context(async (r) => r.confirmation),
      ),
    ).rejects.toThrow("uncertain");
    const restarted = new GuardedActionService(
      join(f.root, "changes"),
      f.audit,
    );
    buildDashboardChangeRegistry(f.ha, restarted, f.audit);
    expect(await restarted.get(id)).toMatchObject({ status: "uncertain" });
    const next = await restarted.propose({
      kind: "dashboard",
      target: "dashboard:dashboard-sunsynk",
      summary: "second",
      payload: {},
    });
    await expect(
      restarted.apply(
        next.proposalId,
        context(async (r) => r.confirmation),
      ),
    ).rejects.toThrow("earlier change is uncertain");
    expect(
      f.request.mock.calls.filter(([t]) => t === "lovelace/config/save"),
    ).toHaveLength(1);
  });
  it("does not ask approval or save when durable attempt audit fails", async () => {
    const f = await fixture();
    const p = await f.propose();
    const id = (p as unknown as { result: { proposalId: string } }).result
      .proposalId;
    vi.spyOn(f.audit, "append").mockRejectedValue(
      new Error("disk unavailable"),
    );
    const approve = vi.fn(async (r: ToolApprovalRequest) => r.confirmation);
    await expect(f.actions.apply(id, context(approve))).rejects.toThrow();
    expect(approve).not.toHaveBeenCalled();
    expect(
      f.request.mock.calls.some(([t]) => t === "lovelace/config/save"),
    ).toBe(false);
  });
  it("refuses spoofed approval fields and unregistered mutation tool inputs", async () => {
    const f = await fixture();
    const tools = buildGuardedChangeRegistry(f.actions, f.audit);
    expect(
      (
        await tools.call(
          "ha_apply_change",
          {
            proposalId: "11111111-1111-4111-8111-111111111111",
            approved: true,
          },
          context(),
        )
      ).ok,
    ).toBe(false);
  });
});
describe("bounded dashboard patches", () => {
  it.each([
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "credential",
    "passwd",
  ])("redacts and refuses secret-key changes: %s", (key) => {
    const source = { ...config(), [key]: "bare-canary" };
    expect(JSON.stringify(redact(source))).not.toContain("bare-canary");
    expect(() =>
      applyDashboardPatch(source, [
        { op: "replace", path: `/${key}`, value: "new" },
      ]),
    ).toThrow();
  });
  it.each([
    "/__proto__/polluted",
    "/views/constructor/x",
    "/views/00/type",
    "/views/2/type",
    "/views/0/~2",
  ])("rejects unsafe pointer %s", (path) => {
    expect(() =>
      applyDashboardPatch(config(), [{ op: "add", path, value: true }]),
    ).toThrow();
  });
  it("preserves unrelated fields and supports array insertion/removal", () => {
    const c = config();
    const { after } = applyDashboardPatch(c, [
      {
        op: "add",
        path: "/views/0/cards/-",
        value: { type: "markdown", content: "Second" },
      },
      { op: "remove", path: "/views/0/cards/0" },
    ]);
    expect((after.views as { cards: unknown[] }[])[0]!.cards).toEqual([
      { type: "markdown", content: "Second" },
    ]);
    expect(c.views[0]!.cards).toHaveLength(1);
  });
  it("refuses secret-bearing changes and redaction placeholders", () => {
    expect(() =>
      applyDashboardPatch(config(), [
        { op: "replace", path: "/private/password", value: "new" },
      ]),
    ).toThrow();
    expect(() =>
      applyDashboardPatch(config(), [
        { op: "add", path: "/title", value: "[REDACTED]" },
      ]),
    ).toThrow();
  });
  it("hashes object keys independently of source key order", () => {
    expect(dashboardHash({ views: [], title: "x" })).toBe(
      dashboardHash({ title: "x", views: [] }),
    );
  });
});
