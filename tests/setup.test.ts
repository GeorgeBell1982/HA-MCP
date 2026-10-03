import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GuardedActionService } from "../src/guardedChanges.js";
import { SetupApiClient } from "../src/setup/api.js";
import { SetupService } from "../src/setup/service.js";
import { buildSetupRegistry } from "../src/setup/tools.js";

const temporary: string[] = [];
afterEach(async () => {
  for (const path of temporary.splice(0))
    await rm(path, { recursive: true, force: true });
});
const audit = () => ({
  health: vi.fn(async () => undefined),
  append: vi.fn(async () => undefined),
});
const repo = () => ({
  id: "42",
  full_name: "test/example",
  name: "Example",
  category: "plugin",
  installed: false,
  available_version: "1.2.3",
  can_download: true,
});
const app = () => ({
  slug: "example_app",
  version: "1.0",
  state: "stopped",
  options: { port: 1883, password: "do-not-leak", api_key: "also-private" },
  schema: { port: "port", password: "password", api_key: "str" },
  system_managed: false,
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "ha-setup-test-"));
  temporary.push(root);
  let repository = repo();
  let application = app();
  const appSources: { slug: string; source: string }[] = [];
  const hacsSources: ReturnType<typeof repo>[] = [];
  const api = {
    setupFrontendOrigin: vi.fn(async () => "http://192.168.50.160:8123"),
    installedApps: vi.fn(async () => ({ addons: [application] })),
    coreInfo: vi.fn(async () => ({
      version: "2026.9.4",
      image: "core-image",
      boot: true,
    })),
    coreConfig: vi.fn(async () => ({ version: "2026.9.4", state: "RUNNING" })),
    restartCore: vi.fn(async () => undefined),
    restartApp: vi.fn(async () => undefined),
    flowHandlers: vi.fn(async () => ["example"]),
    entries: vi.fn(async () => [] as unknown[]),
    startFlow: vi.fn(async () => ({
      type: "form",
      flow_id: "flow_1",
      handler: "example",
      step_id: "user",
      data_schema: [{ name: "host", required: true, type: "string" }],
    })),
    refreshFlow: vi.fn(async () => ({
      type: "form",
      flow_id: "flow_1",
      handler: "example",
      step_id: "user",
      data_schema: [{ name: "host", required: true, type: "string" }],
    })),
    submitFlow: vi.fn(async () => ({
      type: "form",
      flow_id: "flow_1",
      handler: "example",
      step_id: "confirm",
      data_schema: [],
    })),
    hacsCatalog: vi.fn(async () => [repository, ...hacsSources]),
    addHacsRepository: vi.fn(
      async (full_name: string, category: "integration" | "plugin") => {
        hacsSources.push({ ...repo(), id: "43", full_name, category });
      },
    ),
    appRepositories: vi.fn(async () => appSources),
    addAppRepository: vi.fn(async (source: string) => {
      appSources.push({ slug: "test_source", source });
    }),
    installHacs: vi.fn(async () => {
      repository = {
        ...repository,
        installed: true,
        installed_version: "1.2.3",
      } as typeof repository;
    }),
    appCatalog: vi.fn(async () => ({
      addons: [{ slug: "example_app", name: "Example" }],
    })),
    appStoreInfo: vi.fn(async () => ({
      slug: "example_app",
      version: "1.0",
      installed: false,
      privileged: ["SYS_ADMIN"],
      full_access: true,
    })),
    appInfo: vi.fn(async () => application),
    installApp: vi.fn(async () => undefined),
    appOptions: vi.fn(
      async (_slug: string, options: Record<string, unknown>) => {
        application = {
          ...application,
          options: options as typeof application.options,
        };
      },
    ),
    startApp: vi.fn(async () => {
      application = { ...application, state: "started" };
    }),
  };
  const journal = audit();
  const actions = new GuardedActionService(root, journal);
  const service = new SetupService(api as unknown as SetupApiClient, actions);
  const context = {
    signal: new AbortController().signal,
    requestApproval: vi.fn(
      async (request: { confirmation: string }) => request.confirmation,
    ),
  };
  return { api, actions, service, context, journal };
}

describe("bounded third-party setup", () => {
  it("submits exactly an offered simple menu choice and hands off unsupported menus", async () => {
    const f = await fixture();
    const menu = {
      type: "menu",
      flow_id: "flow_1",
      handler: "example",
      step_id: "user",
      menu_options: ["local", "cloud"],
    };
    f.api.startFlow.mockResolvedValue(menu as never);
    f.api.refreshFlow.mockResolvedValue(menu as never);
    const start = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(start.proposalId, f.context);
    expect(await f.service.status("flow", "flow_1")).toHaveProperty(
      "menuOptions",
      ["local", "cloud"],
    );
    await expect(
      f.service.propose({
        action: "integration_submit",
        flowId: "flow_1",
        fields: { next_step_id: "unknown" },
      }),
    ).rejects.toThrow("offered");
    const submit = await f.service.propose({
      action: "integration_submit",
      flowId: "flow_1",
      fields: { next_step_id: "local" },
    });
    await f.actions.apply(submit.proposalId, f.context);
    expect(f.api.submitFlow).toHaveBeenCalledWith("flow_1", {
      next_step_id: "local",
    });
    const unsupported = await fixture();
    unsupported.api.startFlow.mockResolvedValue({
      ...menu,
      menu_options: [{ step: "custom" }],
    } as never);
    const other = await unsupported.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await unsupported.actions.apply(other.proposalId, unsupported.context);
    expect(await unsupported.service.status("flow", "flow_1")).toHaveProperty(
      "secureHandoff",
    );
  });
  it("does not treat Supervisor's uninstalled catalog fallback as proof of installation", async () => {
    const f = await fixture();
    f.api.appInfo.mockResolvedValue({
      ...app(),
      version: "1.0",
      state: "unknown",
    });
    f.api.installedApps.mockResolvedValue({ addons: [] });
    const p = await f.service.propose({
      action: "app_install",
      slug: "example_app",
    });
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
    expect(f.api.installApp).toHaveBeenCalledOnce();
    expect(JSON.stringify(await f.actions.get(p.proposalId))).toContain(
      "uncertain",
    );
  });
  it("requires installed-only membership even if a fallback claims a started state", async () => {
    const f = await fixture();
    f.api.installedApps.mockResolvedValue({ addons: [] });
    const p = await f.service.propose({
      action: "app_install",
      slug: "example_app",
    });
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
  });
  it("refuses an integration flow without a usable ID or with a different handler", async () => {
    for (const invalid of [
      { type: "form", handler: "other", flow_id: "flow_1" },
      { type: "form", handler: "example" },
      { type: "made_up", handler: "example", flow_id: "flow_1" },
    ]) {
      const f = await fixture();
      f.api.startFlow.mockResolvedValue(invalid as never);
      const p = await f.service.propose({
        action: "integration_start",
        domain: "example",
      });
      await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow(
        "uncertain",
      );
      await expect(f.service.status("flow", "flow_1")).rejects.toThrow(
        "not started",
      );
    }
  });
  it("rejects a submission result that substitutes the flow ID", async () => {
    const f = await fixture();
    const start = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(start.proposalId, f.context);
    f.api.submitFlow.mockResolvedValue({
      type: "form",
      handler: "example",
      flow_id: "different",
      step_id: "confirm",
      data_schema: [],
    });
    const submit = await f.service.propose({
      action: "integration_submit",
      flowId: "flow_1",
      fields: { host: "192.168.1.2" },
    });
    await expect(f.actions.apply(submit.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
    expect(f.api.submitFlow).toHaveBeenCalledOnce();
  });
  it("does not submit when flow refresh substitutes the handler despite identical field schema", async () => {
    const f = await fixture();
    const start = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(start.proposalId, f.context);
    f.api.refreshFlow.mockResolvedValue({
      type: "form",
      flow_id: "flow_1",
      handler: "other",
      step_id: "user",
      data_schema: [{ name: "host", required: true, type: "string" }],
    });
    const submit = await f.service.propose({
      action: "integration_submit",
      flowId: "flow_1",
      fields: { host: "192.168.1.2" },
    });
    await expect(f.actions.apply(submit.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
    expect(f.api.submitFlow).not.toHaveBeenCalled();
  });
  it("requires a safe frontend origin before an integration proposal", async () => {
    const f = await fixture();
    f.api.setupFrontendOrigin.mockRejectedValue(new Error("no URL"));
    await expect(
      f.service.propose({ action: "integration_start", domain: "example" }),
    ).rejects.toThrow("no URL");
    expect(f.api.startFlow).not.toHaveBeenCalled();
  });
  it("requires separate exact approval for Core and app restart and never restarts during proposal", async () => {
    const f = await fixture();
    const core = await f.service.propose({ action: "core_restart" });
    expect(core.target).toBe("system:core");
    expect(JSON.stringify(core.summary)).toContain("Disruptive");
    expect(f.api.restartCore).not.toHaveBeenCalled();
    await f.actions.apply(core.proposalId, f.context);
    expect(f.api.restartCore).toHaveBeenCalledOnce();
    f.api.appInfo.mockResolvedValue({ ...app(), state: "started" });
    const appRestart = await f.service.propose({
      action: "app_restart",
      slug: "example_app",
    });
    expect(f.api.restartApp).not.toHaveBeenCalled();
    await f.actions.apply(appRestart.proposalId, f.context);
    expect(f.api.restartApp).toHaveBeenCalledOnce();
    expect(f.api.restartApp).toHaveBeenCalledWith("example_app");
  });
  it("does not retry a restart with a lost upstream response", async () => {
    const f = await fixture();
    f.api.restartCore.mockRejectedValue(new Error("response lost"));
    const core = await f.service.propose({ action: "core_restart" });
    await expect(f.actions.apply(core.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
    await expect(f.actions.apply(core.proposalId, f.context)).rejects.toThrow();
    expect(f.api.restartCore).toHaveBeenCalledOnce();
  });
  it("registers only exact approved GitHub repositories and verifies catalog registration", async () => {
    const f = await fixture();
    const hacs = await f.service.propose({
      action: "hacs_add_repository",
      repository: "owner/frontend",
      category: "plugin",
    });
    expect(f.api.addHacsRepository).not.toHaveBeenCalled();
    await f.actions.apply(hacs.proposalId, f.context);
    expect(f.api.addHacsRepository).toHaveBeenCalledWith(
      "owner/frontend",
      "plugin",
    );
    const appSource = await f.service.propose({
      action: "app_add_repository",
      repository: "owner/apps",
    });
    await f.actions.apply(appSource.proposalId, f.context);
    expect(f.api.addAppRepository).toHaveBeenCalledWith(
      "https://github.com/owner/apps",
    );
    await expect(
      f.service.propose({
        action: "app_add_repository",
        repository: "https://evil.invalid/repo",
      }),
    ).rejects.toThrow();
    await expect(
      f.service.propose({
        action: "hacs_add_repository",
        repository: "owner/../evil",
        category: "plugin",
      }),
    ).rejects.toThrow();
    await expect(
      f.service.propose({
        action: "hacs_add_repository",
        repository: "owner/frontend",
        category: "plugin",
      }),
    ).rejects.toThrow("already");
  });
  it("does not claim an install with the wrong observed version succeeded", async () => {
    const f = await fixture();
    f.api.appInfo.mockResolvedValue({ ...app(), version: "different" });
    const p = await f.service.propose({
      action: "app_install",
      slug: "example_app",
    });
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow(
      "uncertain",
    );
    expect(f.api.installApp).toHaveBeenCalledOnce();
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow();
  });
  it("refuses fields not offered by the flow and required credential steps", async () => {
    const f = await fixture();
    f.api.startFlow.mockResolvedValue({
      type: "form",
      flow_id: "flow_1",
      handler: "example",
      step_id: "user",
      data_schema: [{ name: "password", required: true, type: "string" }],
    });
    const start = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(start.proposalId, f.context);
    const status = await f.service.status("flow", "flow_1");
    expect(status).toHaveProperty("secureHandoff");
    await expect(
      f.service.propose({
        action: "integration_submit",
        flowId: "flow_1",
        fields: {},
      }),
    ).rejects.toThrow("credentials");
    expect(f.api.refreshFlow).not.toHaveBeenCalled();
    expect(f.api.submitFlow).not.toHaveBeenCalled();
  });
  it("reads catalogs and status without initializing or advancing a flow", async () => {
    const f = await fixture();
    expect((await f.service.catalog("integration")).items).toEqual([
      { domain: "example" },
    ]);
    expect((await f.service.catalog("app")).items).toEqual([
      { slug: "example_app", name: "Example" },
    ]);
    await f.service.status("integration");
    expect(f.api.startFlow).not.toHaveBeenCalled();
    expect(f.api.refreshFlow).not.toHaveBeenCalled();
  });
  it("proposes a pinned HACS download, changes nothing until exact approval, verifies installed version", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "hacs_install",
      repositoryId: "42",
      version: "1.2.3",
    });
    expect(f.api.installHacs).not.toHaveBeenCalled();
    const result = await f.actions.apply(p.proposalId, f.context);
    expect(f.api.installHacs).toHaveBeenCalledOnce();
    expect(f.api.installHacs).toHaveBeenCalledWith("42", "1.2.3");
    expect(JSON.stringify(result)).toContain('"verified":true');
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow();
  });
  it("refuses wrong versions and catalog misses before proposing", async () => {
    const f = await fixture();
    await expect(
      f.service.propose({
        action: "hacs_install",
        repositoryId: "42",
        version: "main",
      }),
    ).rejects.toThrow("unavailable");
    await expect(
      f.service.propose({
        action: "hacs_install",
        repositoryId: "99",
        version: "1.2.3",
      }),
    ).rejects.toThrow("not found");
  });
  it("never sends installation after declined approval", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "app_install",
      slug: "example_app",
    });
    await expect(
      f.actions.apply(p.proposalId, {
        ...f.context,
        requestApproval: async () => "no",
      }),
    ).rejects.toThrow();
    expect(f.api.installApp).not.toHaveBeenCalled();
  });
  it("includes app privileges in the approval summary", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "app_install",
      slug: "example_app",
    });
    expect(JSON.stringify(p.summary)).toContain("SYS_ADMIN");
    expect(JSON.stringify(p.summary)).toContain('"full_access":true');
  });
  it("rejects self-management and credentials", async () => {
    const f = await fixture();
    await expect(
      f.service.propose({
        action: "app_start",
        slug: "da397bfb_home_assistant_engineering_mcp",
      }),
    ).rejects.toThrow("itself");
    await expect(
      f.service.propose({
        action: "app_options",
        slug: "example_app",
        options: { password: "private" },
      }),
    ).rejects.toThrow("Credential");
    await expect(
      f.service.propose({
        action: "app_options",
        slug: "example_app",
        options: { api_key: "private" },
      }),
    ).rejects.toThrow("Credential");
  });
  it("redacts secret app fields in read results and approval summaries, preserves them in a non-secret merge", async () => {
    const f = await fixture();
    const status = JSON.stringify(await f.service.status("app", "example_app"));
    expect(status).not.toContain("do-not-leak");
    expect(status).not.toContain("also-private");
    const p = await f.service.propose({
      action: "app_options",
      slug: "example_app",
      options: { port: 1884 },
    });
    expect(JSON.stringify(p)).not.toContain("do-not-leak");
    expect(JSON.stringify(p)).not.toContain("also-private");
    await f.actions.apply(p.proposalId, f.context);
    expect(f.api.appOptions).toHaveBeenCalledWith("example_app", {
      port: 1884,
      password: "do-not-leak",
      api_key: "also-private",
    });
  });
  it("starts and verifies only the stopped specified app", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "app_start",
      slug: "example_app",
    });
    await f.actions.apply(p.proposalId, f.context);
    expect(f.api.startApp).toHaveBeenCalledWith("example_app");
  });
  it("refuses stale target state after approval without sending", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "hacs_install",
      repositoryId: "42",
      version: "1.2.3",
    });
    f.context.requestApproval.mockImplementation(async (request) => {
      f.api.hacsCatalog.mockResolvedValue([
        { ...repo(), available_version: "1.2.4" },
      ]);
      return request.confirmation;
    });
    await expect(f.actions.apply(p.proposalId, f.context)).rejects.toThrow();
    expect(f.api.installHacs).not.toHaveBeenCalled();
  });
  it("starts a flow only after approval and exposes cached state passively", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    expect(f.api.startFlow).not.toHaveBeenCalled();
    expect(JSON.stringify(p.summary)).toContain(
      '"frontendOrigin":"http://192.168.50.160:8123"',
    );
    await f.actions.apply(p.proposalId, f.context);
    expect(await f.service.status("flow", "flow_1")).toMatchObject({
      type: "form",
      step_id: "user",
    });
    expect(f.api.refreshFlow).not.toHaveBeenCalled();
  });
  it("refreshes and submits only an unchanged non-secret approved flow step", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(p.proposalId, f.context);
    const submit = await f.service.propose({
      action: "integration_submit",
      flowId: "flow_1",
      fields: { host: "192.168.1.2" },
    });
    expect(JSON.stringify(submit.summary)).toContain(
      '"frontendOrigin":"http://192.168.50.160:8123"',
    );
    await f.actions.apply(submit.proposalId, f.context);
    expect(f.api.refreshFlow).toHaveBeenCalledOnce();
    expect(f.api.submitFlow).toHaveBeenCalledWith("flow_1", {
      host: "192.168.1.2",
    });
  });
  it("does not submit when the approved flow refresh changes its step", async () => {
    const f = await fixture();
    const p = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(p.proposalId, f.context);
    f.api.refreshFlow.mockResolvedValue({
      type: "form",
      flow_id: "flow_1",
      handler: "example",
      step_id: "other",
      data_schema: [],
    });
    const submit = await f.service.propose({
      action: "integration_submit",
      flowId: "flow_1",
      fields: { host: "192.168.1.2" },
    });
    await expect(
      f.actions.apply(submit.proposalId, f.context),
    ).rejects.toThrow();
    expect(f.api.submitFlow).not.toHaveBeenCalled();
  });
  it("returns secure OAuth handoff without exposing URLs, tokens or schema defaults", async () => {
    const f = await fixture();
    f.api.startFlow.mockResolvedValue({
      type: "external",
      flow_id: "flow_1",
      handler: "example",
      step_id: "oauth",
      data_schema: [],
      url: "https://provider/?state=private-code",
      data: { access_token: "private" },
    } as never);
    const p = await f.service.propose({
      action: "integration_start",
      domain: "example",
    });
    await f.actions.apply(p.proposalId, f.context);
    const status = JSON.stringify(await f.service.status("flow", "flow_1"));
    expect(status).toContain("secureHandoff");
    expect(status).not.toContain("private");
    expect(status).not.toContain("https://provider/");
  });
  it("blocks every call if attempt audit cannot be written", async () => {
    const f = await fixture();
    const unavailable = {
      health: vi.fn(async () => {
        throw new Error("down");
      }),
      append: vi.fn(),
    };
    const root = await mkdtemp(join(tmpdir(), "ha-setup-registry-"));
    temporary.push(root);
    const registry = buildSetupRegistry(
      f.api as unknown as SetupApiClient,
      new GuardedActionService(root, unavailable),
      unavailable,
    );
    expect(
      await registry.call("ha_list_setup_catalog", { kind: "hacs" }),
    ).toMatchObject({ ok: false, error: { code: "audit_unavailable" } });
    expect(f.api.hacsCatalog).not.toHaveBeenCalled();
  });
});

describe("finite setup API boundary", () => {
  it("supplies HA-Frontend-Base on create, advancing GET and submission, without leaking a proxy origin", async () => {
    const fetcher = vi.fn<typeof fetch>(
      async () => new Response("{}", { status: 200 }),
    );
    const ws = {
      connect: vi.fn(async () => undefined),
      request: vi.fn(async () => ({})),
    };
    const api = new SetupApiClient(
      new URL("http://supervisor/core/api"),
      "hidden",
      ws,
      true,
      fetcher,
      new URL("http://192.168.50.160:8123"),
    );
    await api.startFlow("example");
    await api.refreshFlow("flow_1");
    await api.submitFlow("flow_1", { host: "example.local" });
    for (const [, options] of fetcher.mock.calls)
      expect(options?.headers).toHaveProperty(
        "HA-Frontend-Base",
        "http://192.168.50.160:8123",
      );
  });
  it("derives a safe configured Core frontend URL or refuses before starting a flow", async () => {
    const fetcher = vi.fn<typeof fetch>(
      async () =>
        new Response('{"internal_url":"https://ha.example.test"}', {
          status: 200,
        }),
    );
    const ws = {
      connect: vi.fn(async () => undefined),
      request: vi.fn(async () => ({})),
    };
    const api = new SetupApiClient(
      new URL("http://supervisor/core/api"),
      "hidden",
      ws,
      true,
      fetcher,
    );
    await api.startFlow("example");
    expect(fetcher.mock.calls[1]?.[1]?.headers).toHaveProperty(
      "HA-Frontend-Base",
      "https://ha.example.test",
    );
    fetcher.mockClear();
    fetcher.mockImplementation(
      async () =>
        new Response('{"internal_url":null,"external_url":null}', {
          status: 200,
        }),
    );
    await expect(api.startFlow("example")).rejects.toThrow(
      "browser-accessible",
    );
    expect(fetcher).toHaveBeenCalledOnce();
    expect(String(fetcher.mock.calls[0]?.[0])).toContain("/config");
  });
  it("uses fixed routes and never retries a failed mutation", async () => {
    const fetcher = vi.fn<typeof fetch>(
      async () => new Response("private-token", { status: 503 }),
    );
    const ws = {
      connect: vi.fn(async () => undefined),
      request: vi.fn(async () => ({})),
    };
    const api = new SetupApiClient(
      new URL("http://supervisor/core/api"),
      "hidden",
      ws,
      true,
      fetcher,
    );
    await expect(api.installApp("test_app")).rejects.toThrow("503");
    expect(fetcher).toHaveBeenCalledOnce();
    expect(String(fetcher.mock.calls[0]?.[0])).toBe(
      "http://supervisor/store/addons/test_app/install",
    );
    expect(() => api.startApp("../escape")).toThrow("identifier");
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it("rejects Supervisor management outside the add-on and confines HACS commands", async () => {
    const fetcher = vi.fn();
    const ws = {
      connect: vi.fn(async () => undefined),
      request: vi.fn(async () => ({})),
    };
    const api = new SetupApiClient(
      new URL("http://localhost:8123/api"),
      "hidden",
      ws,
      false,
      fetcher,
    );
    await expect(api.appCatalog()).rejects.toThrow("add-on runtime");
    expect(fetcher).not.toHaveBeenCalled();
    await api.installHacs("42", "1.2.3");
    expect(ws.request).toHaveBeenCalledWith("hacs/repository/download", {
      repository: "42",
      version: "1.2.3",
    });
  });
});
