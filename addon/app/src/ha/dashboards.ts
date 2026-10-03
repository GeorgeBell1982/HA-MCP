import { createHash } from "node:crypto";
import { z } from "zod";
import { SafeError } from "../domain.js";

export const dashboardPathSchema = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
  .max(100)
  .nullable();
export interface DashboardSocket {
  connect(): Promise<void>;
  request(type: string, input?: Record<string, unknown>): Promise<unknown>;
}
export interface DashboardInfo {
  id: string;
  url_path: string;
  title: string;
  mode: string;
}
export class HaDashboardClient {
  constructor(private readonly ws: DashboardSocket) {}
  async list(): Promise<DashboardInfo[]> {
    await this.ws.connect();
    const data = await this.ws.request("lovelace/dashboards/list");
    const schema = z
      .array(
        z
          .object({
            id: z.string(),
            url_path: dashboardPathSchema.unwrap(),
            title: z.string(),
            mode: z.string(),
          })
          .passthrough(),
      )
      .max(128);
    const parsed = schema.safeParse(data);
    if (!parsed.success)
      throw new SafeError(
        "upstream_error",
        "Dashboard list response is invalid",
      );
    return parsed.data;
  }
  async read(urlPath: string | null): Promise<Record<string, unknown>> {
    if (!dashboardPathSchema.safeParse(urlPath).success)
      throw new SafeError("invalid_input", "Invalid dashboard path");
    await this.ws.connect();
    const config = await this.ws.request("lovelace/config", {
      url_path: urlPath,
      force: true,
    });
    validateDashboardConfig(config);
    return config;
  }
  async assertStorage(urlPath: string | null): Promise<void> {
    // Require an explicit dashboard identity so default routing cannot silently
    // switch between YAML and storage dashboards across Home Assistant versions.
    if (!urlPath)
      throw new SafeError(
        "capability_unavailable",
        "Select an explicit storage dashboard URL path",
      );
    const item = (await this.list()).find((d) => d.url_path === urlPath);
    if (!item || item.mode !== "storage")
      throw new SafeError(
        "capability_unavailable",
        "Only existing storage dashboards can be changed",
      );
  }
  async save(urlPath: string, config: Record<string, unknown>): Promise<void> {
    validateDashboardConfig(config);
    await this.ws.connect();
    // A mutation is sent once. The WebSocket client does not replay commands.
    await this.ws.request("lovelace/config/save", {
      url_path: urlPath,
      config,
    });
  }
}
export function canonicalJson(value: unknown): string {
  let nodes = 0;
  const visit = (v: unknown, depth: number): unknown => {
    const prototype: unknown =
      v && typeof v === "object" ? Object.getPrototypeOf(v) : undefined;
    if (++nodes > 20_000 || depth > 64)
      throw new SafeError(
        "invalid_input",
        "Dashboard exceeds structure limits",
      );
    if (v === null || typeof v === "string" || typeof v === "boolean") return v;
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (Array.isArray(v)) return v.map((x) => visit(x, depth + 1));
    if (
      v &&
      typeof v === "object" &&
      (prototype === Object.prototype || prototype === null)
    ) {
      return Object.fromEntries(
        Object.entries(v)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, x]) => [k, visit(x, depth + 1)]),
      );
    }
    throw new SafeError("invalid_input", "Dashboard contains a non-JSON value");
  };
  const text = JSON.stringify(visit(value, 0));
  if (Buffer.byteLength(text) > 300_000)
    throw new SafeError("invalid_input", "Dashboard exceeds size limit");
  return text;
}
export function dashboardHash(config: unknown): string {
  return createHash("sha256").update(canonicalJson(config)).digest("hex");
}
export function validateDashboardConfig(
  value: unknown,
): asserts value is Record<string, unknown> {
  canonicalJson(value);
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !Array.isArray((value as Record<string, unknown>).views) ||
    !(value as { views: unknown[] }).views.every(
      (v) => v && typeof v === "object" && !Array.isArray(v),
    )
  )
    throw new SafeError(
      "invalid_input",
      "Dashboard must be an object with a views array",
    );
}
