import { SafeError } from "../domain.js";

export interface SetupWebSocket {
  connect(): Promise<void>;
  request(type: string, input?: Record<string, unknown>): Promise<unknown>;
}

/** Finite Core/HACS/Supervisor routes. Mutations are never retried. */
export class SetupApiClient {
  constructor(
    private readonly core: URL,
    private readonly token: string,
    private readonly ws: SetupWebSocket,
    private readonly supervisorAvailable: boolean,
    private readonly fetcher: typeof fetch = fetch,
    private readonly frontendBase?: URL,
  ) {}

  private async http(
    supervisor: boolean,
    path: string,
    method: "GET" | "POST",
    body?: unknown,
    frontendOrigin?: string,
  ): Promise<unknown> {
    if (supervisor && !this.supervisorAvailable)
      throw new SafeError(
        "capability_unavailable",
        "Supervisor setup requires the add-on runtime",
      );
    const target = supervisor
      ? new URL(`http://supervisor${path}`)
      : new URL(this.core);
    if (!supervisor)
      target.pathname = this.core.pathname.replace(/\/$/, "") + path;
    try {
      const response = await this.fetcher(target, {
        method,
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
          ...(frontendOrigin ? { "HA-Frontend-Base": frontendOrigin } : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(method === "POST" ? 180_000 : 15_000),
        redirect: "error",
      });
      if (!response.ok)
        throw new SafeError(
          response.status === 401 || response.status === 403
            ? "auth_failed"
            : "upstream_error",
          `Setup API returned HTTP ${response.status}; inspect status before retrying`,
        );
      if (Number(response.headers.get("content-length")) > 2_000_000)
        throw new SafeError(
          "upstream_error",
          "Setup response exceeded its size limit",
        );
      const text = await response.text();
      if (Buffer.byteLength(text) > 2_000_000)
        throw new SafeError(
          "upstream_error",
          "Setup response exceeded its size limit",
        );
      const result: unknown = text ? JSON.parse(text) : {};
      if (!supervisor) return result;
      if (
        !result ||
        typeof result !== "object" ||
        Array.isArray(result) ||
        (result as Record<string, unknown>).result !== "ok"
      )
        throw new SafeError(
          "upstream_error",
          "Supervisor setup operation failed; inspect status before retrying",
        );
      return (result as Record<string, unknown>).data;
    } catch (error) {
      if (error instanceof SafeError) throw error;
      // Never return upstream exception bodies or credential-bearing URLs.
      throw new SafeError(
        "upstream_error",
        "Setup API result is uncertain; inspect status before retrying",
      );
    }
  }

  flowHandlers(): Promise<unknown> {
    return this.http(false, "/config/config_entries/flow_handlers", "GET");
  }
  setupFrontendOrigin(): Promise<string> {
    return this.flowFrontendOrigin();
  }
  entries(): Promise<unknown> {
    return this.http(false, "/config/config_entries/entry", "GET");
  }
  async startFlow(domain: string): Promise<unknown> {
    return this.http(
      false,
      "/config/config_entries/flow",
      "POST",
      {
        handler: identifier(domain),
      },
      await this.flowFrontendOrigin(),
    );
  }
  /** Core GET configures/advances the flow. Call only inside an approved action. */
  async refreshFlow(id: string): Promise<unknown> {
    return this.http(
      false,
      `/config/config_entries/flow/${identifier(id)}`,
      "GET",
      undefined,
      await this.flowFrontendOrigin(),
    );
  }
  async submitFlow(
    id: string,
    fields: Record<string, unknown>,
  ): Promise<unknown> {
    return this.http(
      false,
      `/config/config_entries/flow/${identifier(id)}`,
      "POST",
      fields,
      await this.flowFrontendOrigin(),
    );
  }
  async hacsCatalog(): Promise<unknown> {
    await this.ws.connect();
    return this.ws.request("hacs/repositories/list", {
      categories: ["integration", "plugin"],
    });
  }
  async installHacs(id: string, version: string): Promise<unknown> {
    await this.ws.connect();
    return this.ws.request("hacs/repository/download", {
      repository: identifier(id),
      version,
    });
  }
  async addHacsRepository(
    repository: string,
    category: "integration" | "plugin",
  ): Promise<unknown> {
    await this.ws.connect();
    return this.ws.request("hacs/repositories/add", { repository, category });
  }
  appRepositories(): Promise<unknown> {
    return this.http(true, "/store/repositories", "GET");
  }
  addAppRepository(repository: string): Promise<unknown> {
    return this.http(true, "/store/repositories", "POST", { repository });
  }
  appCatalog(): Promise<unknown> {
    return this.http(true, "/store/addons", "GET");
  }
  installedApps(): Promise<unknown> {
    return this.http(true, "/addons", "GET");
  }
  appStoreInfo(slug: string): Promise<unknown> {
    return this.http(true, `/store/addons/${identifier(slug)}`, "GET");
  }
  appInfo(slug: string): Promise<unknown> {
    return this.http(true, `/addons/${identifier(slug)}/info`, "GET");
  }
  installApp(slug: string): Promise<unknown> {
    return this.http(
      true,
      `/store/addons/${identifier(slug)}/install`,
      "POST",
      { background: false },
    );
  }
  appOptions(slug: string, options: Record<string, unknown>): Promise<unknown> {
    return this.http(true, `/addons/${identifier(slug)}/options`, "POST", {
      options,
    });
  }
  startApp(slug: string): Promise<unknown> {
    return this.http(true, `/addons/${identifier(slug)}/start`, "POST", {});
  }
  restartApp(slug: string): Promise<unknown> {
    return this.http(true, `/addons/${identifier(slug)}/restart`, "POST", {});
  }
  coreInfo(): Promise<unknown> {
    return this.http(true, "/core/info", "GET");
  }
  coreConfig(): Promise<unknown> {
    return this.http(false, "/config", "GET");
  }
  restartCore(): Promise<unknown> {
    return this.http(true, "/core/restart", "POST", {});
  }
  private async flowFrontendOrigin(): Promise<string> {
    if (this.frontendBase) return frontendOrigin(this.frontendBase.href);
    if (this.core.hostname !== "supervisor")
      return frontendOrigin(this.core.origin);
    const config = await this.coreConfig();
    if (config && typeof config === "object" && !Array.isArray(config)) {
      const values = config as Record<string, unknown>;
      for (const key of ["internal_url", "external_url"] as const) {
        if (typeof values[key] === "string") {
          try {
            return frontendOrigin(values[key]);
          } catch {
            /* Try the other configured frontend URL. */
          }
        }
      }
    }
    throw new SafeError(
      "capability_unavailable",
      "Integration setup needs a browser-accessible HA frontend URL. Configure setup_frontend_url or continue authentication securely in Home Assistant at /config/integrations; no flow was sent",
    );
  }
}

function frontendOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new SafeError("invalid_input", "Invalid HA setup frontend URL");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.hostname === "supervisor"
  )
    throw new SafeError(
      "invalid_input",
      "HA setup frontend URL must be a credential-free browser-accessible origin",
    );
  return url.origin;
}

function identifier(value: string): string {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(value) || value === "self")
    throw new SafeError("invalid_input", "Invalid setup target identifier");
  return value;
}
