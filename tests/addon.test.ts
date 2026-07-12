import { access, readFile } from "node:fs/promises";
import { isAbsolute, normalize } from "node:path";
import { describe, expect, it } from "vitest";
import { assertHttpCanStart } from "../src/http.js";
describe("installable add-on packaging", () => {
  it("is aarch64-only and least privilege", async () => {
    const manifest = await readFile("addon/config.yaml", "utf8");
    expect(manifest).toContain("- aarch64");
    expect(manifest).toContain("homeassistant_api: true");
    expect(manifest).toContain("map: []");
    expect(manifest).toContain("enable_http: false");
    expect(manifest).toContain("ingress_port: 8099");
    expect(manifest).not.toContain("8099/tcp");
    for (const forbidden of [
      "config:rw",
      "privileged:",
      "docker_api:",
      "host_network:",
    ])
      expect(manifest).not.toContain(forbidden);
  });
  it("has reproducible pinned build inputs", async () => {
    const docker = await readFile("addon/Dockerfile", "utf8");
    expect(docker).toContain("node:22.17.1-alpine3.22");
    expect(docker).toContain("pnpm install --frozen-lockfile");
    expect(await readFile("repository.yaml", "utf8")).toContain("name:");
    for (const copy of dockerCopies(docker)) {
      for (const source of copy.sources) {
        expect(isAbsolute(source)).toBe(false);
        expect(normalize(source).startsWith(".."), source).toBe(false);
        if (!copy.fromStage)
          await expect(
            access(`addon/${source}`),
            source,
          ).resolves.toBeUndefined();
      }
    }
    for (const input of [
      "package.json",
      "pnpm-lock.yaml",
      "pnpm-workspace.yaml",
      "tsconfig.json",
      "tsconfig.build.json",
      "src/index.ts",
    ])
      await expect(readFile(`addon/app/${input}`)).resolves.toBeDefined();
  });
  it("permits the internal container wildcard only in add-on mode", () => {
    expect(() =>
      assertHttpCanStart({
        enabled: true,
        tlsCertificate: "cert",
        pairedClients: 1,
        bind: "0.0.0.0",
        addonMode: true,
      }),
    ).not.toThrow();
    expect(() =>
      assertHttpCanStart({
        enabled: true,
        tlsCertificate: "cert",
        pairedClients: 1,
        bind: "0.0.0.0",
      }),
    ).toThrow();
  });
});
function dockerCopies(dockerfile: string) {
  const copies: { fromStage: boolean; sources: string[] }[] = [];
  for (const logical of dockerfile.replace(/\\\r?\n/g, " ").split(/\r?\n/)) {
    const match = logical.match(/^COPY\s+((?:--\S+\s+)*)(.+)$/i);
    if (!match?.[2]) continue;
    const value = match[2].trim();
    let sources: string[];
    if (value.startsWith("[")) {
      const parsed = JSON.parse(value) as string[];
      sources = parsed.slice(0, -1);
    } else {
      const tokens = value.match(/(?:"[^"]*"|'[^']*'|\S+)/g) ?? [];
      sources = tokens.slice(0, -1).map((x) => x.replace(/^["']|["']$/g, ""));
    }
    copies.push({ fromStage: /--from=/i.test(match[1] ?? ""), sources });
  }
  return copies;
}
