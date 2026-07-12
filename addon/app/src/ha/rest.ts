import { SafeError } from "../domain.js";
import { safeMessage } from "../redaction.js";
export interface HaState {
  entity_id: string;
  state: string;
  attributes: Record<string, unknown>;
  last_changed: string;
  last_updated: string;
}
export interface HaConfig {
  components?: string[];
  config_dir?: string;
  elevation?: number;
  latitude?: number;
  longitude?: number;
  location_name?: string;
  time_zone?: string;
  unit_system?: Record<string, string>;
  version: string;
  state?: string;
}
export class HaRestClient {
  constructor(
    private readonly base: URL,
    private readonly token: string,
    private readonly timeoutMs = 8_000,
    private readonly fetcher: typeof fetch = fetch,
  ) {}
  private async get(
    path: string,
    options: { maxBytes?: number; contentType?: "json" | "text" } = {},
  ): Promise<unknown> {
    const maxBytes = options.maxBytes ?? 2_000_000;
    if (!path.startsWith("/") || path.includes(".."))
      throw new SafeError("invalid_input", "Invalid Core API path");
    const target = new URL(this.base);
    target.pathname = this.base.pathname.replace(/\/$/, "") + path;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let response: Response | undefined;
      for (let attempt = 0; attempt < 2; attempt++) {
        response = await this.fetcher(target, {
          headers: {
            Authorization: `Bearer ${this.token}`,
            Accept: "application/json",
          },
          redirect: "error",
          signal: controller.signal,
        });
        if (response.status < 500 || attempt === 1) break;
      }
      if (!response)
        throw new SafeError("upstream_error", "Home Assistant did not respond");
      if (response.status === 401 || response.status === 403)
        throw new SafeError(
          "auth_failed",
          "Home Assistant authentication failed",
        );
      if (!response.ok)
        throw new SafeError(
          "upstream_error",
          `Home Assistant returned HTTP ${response.status}`,
        );
      const declared = response.headers.get("content-length");
      if (declared && Number(declared) > maxBytes)
        throw new SafeError(
          "upstream_error",
          "Home Assistant response exceeded the safe size limit",
        );
      const text = await response.text();
      if (Buffer.byteLength(text) > maxBytes)
        throw new SafeError(
          "upstream_error",
          "Home Assistant response exceeded the safe size limit",
        );
      const mediaType = response.headers
        .get("content-type")
        ?.split(";")[0]
        ?.trim()
        .toLowerCase();
      if (options.contentType === "text") {
        if (mediaType && mediaType !== "text/plain")
          throw new SafeError(
            "upstream_error",
            "Home Assistant error log response had an invalid content type",
          );
        if (text.includes("\0") || text.includes("\uFFFD"))
          throw new SafeError(
            "upstream_error",
            "Home Assistant error log response was malformed",
          );
        return text;
      }
      if (mediaType && mediaType !== "application/json")
        throw new SafeError(
          "upstream_error",
          "Home Assistant JSON response had an invalid content type",
        );
      try {
        return JSON.parse(text) as unknown;
      } catch {
        throw new SafeError(
          "upstream_error",
          "Home Assistant returned malformed JSON",
        );
      }
    } catch (error) {
      if (error instanceof SafeError) throw error;
      if (controller.signal.aborted)
        throw new SafeError("timeout", "Home Assistant request timed out");
      throw new SafeError("upstream_error", safeMessage(error));
    } finally {
      clearTimeout(timer);
    }
  }
  async config(): Promise<HaConfig> {
    const v = await this.get("/config");
    if (!v || typeof v !== "object")
      throw new SafeError(
        "upstream_error",
        "Home Assistant config response was invalid",
      );
    const raw = v as Record<string, unknown>;
    if (typeof raw.version !== "string")
      throw new SafeError(
        "upstream_error",
        "Home Assistant config response was invalid",
      );
    const result: HaConfig = { version: raw.version };
    for (const key of [
      "config_dir",
      "location_name",
      "time_zone",
      "state",
    ] as const) {
      const value = raw[key];
      if (value !== undefined && typeof value !== "string")
        throw new SafeError(
          "upstream_error",
          "Home Assistant config response was invalid",
        );
      if (typeof value === "string") result[key] = value;
    }
    for (const key of ["elevation", "latitude", "longitude"] as const) {
      const value = raw[key];
      if (
        value !== undefined &&
        (typeof value !== "number" || !Number.isFinite(value))
      )
        throw new SafeError(
          "upstream_error",
          "Home Assistant config response was invalid",
        );
      if (typeof value === "number") result[key] = value;
    }
    if (raw.components !== undefined) {
      if (
        !Array.isArray(raw.components) ||
        !raw.components.every((x) => typeof x === "string")
      )
        throw new SafeError(
          "upstream_error",
          "Home Assistant config response was invalid",
        );
      result.components = raw.components;
    }
    if (raw.unit_system !== undefined) {
      if (
        !raw.unit_system ||
        typeof raw.unit_system !== "object" ||
        Array.isArray(raw.unit_system) ||
        !Object.values(raw.unit_system).every((x) => typeof x === "string")
      )
        throw new SafeError(
          "upstream_error",
          "Home Assistant config response was invalid",
        );
      result.unit_system = raw.unit_system as Record<string, string>;
    }
    return result;
  }
  async states(): Promise<HaState[]> {
    const v = await this.get("/states");
    if (!Array.isArray(v))
      throw new SafeError(
        "upstream_error",
        "Home Assistant states response was invalid",
      );
    return v.map((x) => validateState(x));
  }
  async state(id: string): Promise<HaState> {
    const v = await this.get(`/states/${encodeURIComponent(id)}`);
    return validateState(v);
  }
  async errors(): Promise<string> {
    const v = await this.get("/error_log", {
      maxBytes: 512_000,
      contentType: "text",
    });
    return typeof v === "string" ? v : JSON.stringify(v);
  }
}

function validateState(value: unknown): HaState {
  if (!value || typeof value !== "object")
    throw new SafeError(
      "upstream_error",
      "Home Assistant state item was invalid",
    );
  const v = value as Record<string, unknown>;
  if (
    typeof v.entity_id !== "string" ||
    !/^[a-z0-9_]+\.[a-z0-9_]+$/.test(v.entity_id) ||
    typeof v.state !== "string" ||
    !v.attributes ||
    typeof v.attributes !== "object" ||
    Array.isArray(v.attributes) ||
    typeof v.last_changed !== "string" ||
    typeof v.last_updated !== "string"
  )
    throw new SafeError(
      "upstream_error",
      "Home Assistant state item was invalid",
    );
  return {
    entity_id: v.entity_id,
    state: v.state,
    attributes: v.attributes as Record<string, unknown>,
    last_changed: v.last_changed,
    last_updated: v.last_updated,
  };
}
