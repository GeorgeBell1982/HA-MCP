import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { isAbsolute, normalize } from "node:path";
import { describe, expect, it } from "vitest";
import { assertHttpCanStart } from "../src/http.js";

const NODE_INDEX =
  "sha256:5539840ce9d013fa13e3b9814c9353024be7ac75aca5db6d039504a56c04ea59";
const NODE_AMD64 =
  "sha256:99351363debf40f3495cb7fc657a777334c3b21143e594dbfcc7de187439633c";
const HA_AMD64 =
  "sha256:f243712420b3493e9c23d821e4a44c1a1c152c294a9242624de947041cf036cc";
const HA_ARM64 =
  "sha256:b530091383543737310fd0b3512123de3e3b5165f221f244d0171b858528d963";

const nativeMirrors = [
  [
    "src/security/native/openat2-read.c",
    "addon/app/src/security/native/openat2-read.c",
  ],
  [
    "src/repository/native/openat2-list.c",
    "addon/app/src/repository/native/openat2-list.c",
  ],
  ["src/git/native/git-broker.c", "addon/app/src/git/native/git-broker.c"],
] as const;

const nativeOutputs = ["openat2-read", "openat2-list", "git-broker"] as const;

describe("installable add-on packaging", () => {
  it("is aarch64-only, released at 0.1.7, and least privilege", async () => {
    const manifest = await readFile("addon/config.yaml", "utf8");
    expect(manifest).toMatch(/^version: "0\.1\.7"$/m);
    expect(manifest).toContain("- aarch64");
    expect(manifest).toContain("homeassistant_api: true");
    expect(manifest).toMatch(/^map: \[\]$/m);
    expect(manifest).toContain("enable_http: false");
    expect(manifest).toContain("ingress_port: 8099");
    expect(manifest).not.toContain("8099/tcp");
    for (const forbidden of [
      "homeassistant_config",
      "config:rw",
      "config:ro",
      "privileged:",
      "docker_api:",
      "host_network:",
    ])
      expect(manifest).not.toContain(forbidden);
  });

  it("pins candidate build and runtime inputs to immutable aarch64 evidence", async () => {
    const docker = await readFile("addon/Dockerfile", "utf8");
    await expect(access("addon/build.yaml")).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(docker).toContain(`node:22.17.1-alpine3.22@${NODE_INDEX}`);
    expect(docker).toContain(
      `--build-arg HA_BASE_FROM=ghcr.io/home-assistant/base:3.22@${HA_AMD64} --build-arg NODE_BUILD_FROM=node:22.17.1-alpine3.22@${NODE_AMD64}`,
    );
    expect(docker).toContain(
      `ARG HA_BASE_FROM=ghcr.io/home-assistant/aarch64-base:3.22@${HA_ARM64}`,
    );
    expect(docker).toMatch(/^FROM \$\{HA_BASE_FROM\}$/m);
    expect(docker).not.toMatch(/^ARG BUILD_FROM(?:=|\s|$)/m);
    expect(docker).not.toContain("FROM ${BUILD_FROM}");
    for (const digest of [NODE_INDEX, NODE_AMD64, HA_AMD64, HA_ARM64])
      expect(digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    for (const input of [
      "build-base=0.5-r3",
      "gcc=14.2.0-r6",
      "binutils=2.44-r3",
      "file=5.46-r2",
      "linux-headers=6.14.2-r0",
      "musl-dev=1.2.5-r12",
      "git=2.49.1-r0",
      "nodejs=22.23.0-r0",
      "openssl=3.5.7-r0",
    ])
      expect(docker).toContain(input);
    expect(docker).toContain("pnpm install --frozen-lockfile");
    expect(await readFile("repository.yaml", "utf8")).toContain("name:");
  });

  it("compiles the three exact native mirrors as hardened inert candidates", async () => {
    const docker = await readFile("addon/Dockerfile", "utf8");
    for (const flag of [
      "-fPIE",
      "-fstack-protector-strong",
      "-D_FORTIFY_SOURCE=2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-Wformat=2",
      "-Wformat-security",
      "-pie",
      "-Wl,-z,relro,-z,now,-z,noexecstack",
    ])
      expect(docker).toContain(flag);
    for (const [root, addon] of nativeMirrors) {
      expect(await sha256(root)).toBe(await sha256(addon));
      expect(docker).toContain(addon.replace(/^addon\/app\//, ""));
    }
    const broker = await readFile(nativeMirrors[2][0], "utf8");
    expect(broker).toContain(
      "if(ferror(stream)){\n    denied=1;\n  }\n  free(line);",
    );
    expect(broker).not.toContain("if(ferror(stream))denied=1;free");
    expect(broker).toContain(
      "no_promisor_packs(objects_fd)){\n    failed=1;\n  }\n  if(post_config_fd>=0){",
    );
    for (const output of nativeOutputs) {
      expect(docker).toContain(`-o /build/native/${output}`);
      expect(docker).toContain(`/build/native/${output}`);
    }
    expect(docker).toContain(
      "COPY --from=build --chown=0:0 --chmod=0555 /build/native/ /app/native/",
    );
  });

  it("keeps candidate helpers inert and preserves the shipped entrypoint", async () => {
    const docker = await readFile("addon/Dockerfile", "utf8");
    const run = await readFile("addon/run.sh", "utf8");
    expect(docker).toMatch(/^CMD \["\/run\.sh"\]$/m);
    expect(run).toMatch(/^exec node \/app\/dist\/index\.js$/m);
    expect(run).not.toMatch(/\/app\/native|openat2|git-broker|HA_.*HELPER/u);
    expect(docker).not.toMatch(/^ENV .*?(?:HELPER|OPENAT2|GIT_BROKER)/mu);
    expect(docker).not.toContain("/homeassistant");
  });

  it("has only bounded build-context COPY sources", async () => {
    const docker = await readFile("addon/Dockerfile", "utf8");
    for (const copy of dockerCopies(docker)) {
      for (const source of copy.sources) {
        if (isAbsolute(source)) {
          expect(copy.fromStage, source).toBe(true);
          expect(source).toBe("/build/native/");
        } else {
          expect(normalize(source).startsWith(".."), source).toBe(false);
          if (!copy.fromStage)
            await expect(
              access(`addon/${source}`),
              source,
            ).resolves.toBeUndefined();
        }
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

async function sha256(path: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

describe("add-on TypeScript source mirrors", () => {
  it.each([
    [
      "proposal storage",
      "src/proposals/storage.ts",
      "addon/app/src/proposals/storage.ts",
    ],
    [
      "Phase 2 audit",
      "src/proposals/phase2Audit.ts",
      "addon/app/src/proposals/phase2Audit.ts",
    ],
  ] as const)("keeps %s mirrored", async (_label, rootPath, addonPath) => {
    const rootSource = (await readFile(rootPath, "utf8")).replace(
      /\r\n/g,
      "\n",
    );
    const addonSource = (await readFile(addonPath, "utf8")).replace(
      /\r\n/g,
      "\n",
    );
    expect(addonSource).toBe(rootSource);
  });
});
