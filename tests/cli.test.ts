import { execFile } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execute = promisify(execFile);

describe("diagnostic CLI", () => {
  it("reports bounded capabilities without credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "cli-"));
    const { stdout, stderr } = await execute(
      process.execPath,
      [join(process.cwd(), "dist/cli.js"), "list-capabilities"],
      {
        env: {
          ...process.env,
          HA_MODE: "local",
          HA_BASE_URL: "http://127.0.0.1:8123",
          HA_ACCESS_TOKEN: "cli-canary",
          HA_AUDIT_LOG_PATH: join(root, "audit.jsonl"),
        },
      },
    );
    expect(stderr).toBe("");
    expect(JSON.parse(stdout)).toMatchObject({
      restReads: true,
      mutations: false,
      http: false,
    });
    expect(stdout).not.toContain("cli-canary");
  });
});
