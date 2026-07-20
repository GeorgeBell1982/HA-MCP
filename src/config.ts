import { z } from "zod";
import { SafeError } from "./domain.js";
const bool = z
  .enum(["true", "false"])
  .default("false")
  .transform((v) => v === "true");
const schema = z.object({
  HA_MODE: z.enum(["addon", "local"]).default("local"),
  HA_BASE_URL: z.string().optional(),
  HA_ACCESS_TOKEN: z.string().optional(),
  SUPERVISOR_TOKEN: z.string().optional(),
  HA_AUDIT_LOG_PATH: z.string().default("./data/audit.jsonl"),
  HA_ENABLE_HTTP: bool,
  HA_ENABLE_PHASE2: bool,
  HA_ENABLE_WRITES: bool,
  HA_ENABLE_RESTART: bool,
  HA_ENABLE_DELETES: bool,
});
export interface Config {
  mode: "addon" | "local";
  baseUrl: URL;
  token: string;
  auditPath: string;
  enableHttp: boolean;
  enablePhase2: boolean;
  enableWrites: false;
  enableRestart: false;
  enableDeletes: false;
}
export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success)
    throw new SafeError("invalid_input", "Invalid environment configuration");
  const d = parsed.data;
  const raw =
    d.HA_MODE === "addon" ? "http://supervisor/core/api" : d.HA_BASE_URL;
  const token = d.HA_MODE === "addon" ? d.SUPERVISOR_TOKEN : d.HA_ACCESS_TOKEN;
  if (!raw || !token)
    throw new SafeError(
      "auth_failed",
      "Home Assistant endpoint or runtime credential is unavailable",
    );
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SafeError("invalid_input", "Home Assistant endpoint is invalid");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (d.HA_MODE === "addon" && url.href !== "http://supervisor/core/api") ||
    (d.HA_MODE === "local" && !["/", ""].includes(url.pathname))
  )
    throw new SafeError(
      "invalid_input",
      "Home Assistant endpoint violates origin policy",
    );
  if (d.HA_MODE === "local") url.pathname = "/api";
  return {
    mode: d.HA_MODE,
    baseUrl: url,
    token,
    auditPath: d.HA_AUDIT_LOG_PATH,
    enableHttp: d.HA_ENABLE_HTTP,
    enablePhase2: d.HA_MODE === "addon" && d.HA_ENABLE_PHASE2,
    enableWrites: false,
    enableRestart: false,
    enableDeletes: false,
  };
}
export function publicPolicy(
  env: NodeJS.ProcessEnv,
  runtime: {
    readonly phase2Active?: boolean;
    readonly configMapping?: boolean;
  } = {},
) {
  return {
    transport: { stdio: true, httpEnabled: env.HA_ENABLE_HTTP === "true" },
    mutations: { writes: false, restart: false, deletes: false },
    configMapping: runtime.configMapping === true,
    phase2Enabled: runtime.phase2Active === true,
    phase2Requested: env.HA_MODE === "addon" && env.HA_ENABLE_PHASE2 === "true",
  };
}
