import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../src/phase2Contracts.js";
import {
  RESOURCE_MAX_RESOURCES,
  RepositoryResourceService,
} from "../src/repository/resourceProjection.js";
import {
  REPOSITORY_MAX_TOTAL_BYTES,
  RepositoryCursorCodec,
  type CatalogDirectory,
  type CatalogFile,
  type RepositoryCatalog,
  type RepositoryCatalogProvider,
} from "../src/repository/repositoryReads.js";
import {
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
  type SecureFileReader,
} from "../src/security/repositoryBoundary.js";

const operation = (
  signal: AbortSignal = new AbortController().signal,
): Phase2OperationContext => ({
  requestId: randomUUID(),
  operationId: randomUUID(),
  deadlineAt: Date.now() + 30_000,
  signal,
});
const identity = (inode: string): FileIdentity => ({ device: "1", inode });
const sha = (value: string) => createHash("sha256").update(value).digest("hex");

interface FixtureFile {
  content: string;
  inode?: string;
}

class FixtureReader implements SecureFileReader {
  rootIdentity = identity("root");
  readonly transferred: Buffer[] = [];
  readonly reads: string[] = [];
  constructor(readonly files: Map<string, FixtureFile>) {}
  async read(path: string): Promise<SecureFileRead> {
    this.reads.push(path);
    const file = this.files.get(path);
    if (!file) throw new RepositoryBoundaryError("path_denied", "missing");
    const bytes = Buffer.from(file.content);
    this.transferred.push(bytes);
    return {
      path,
      identity: identity(file.inode ?? path),
      rootIdentity: this.rootIdentity,
      bytes,
    };
  }
}

class MutableCatalog implements RepositoryCatalogProvider {
  constructor(public value: RepositoryCatalog) {}
  async catalog(): Promise<RepositoryCatalog> {
    return this.value;
  }
}

const fileEntry = (path: string, file: FixtureFile): CatalogFile => ({
  path,
  identity: identity(file.inode ?? path),
  size: Buffer.byteLength(file.content),
  mtimeNanoseconds: "1",
  ctimeNanoseconds: "1",
});
const directoryEntry = (path: string): CatalogDirectory => ({
  path,
  identity: identity(`dir:${path}`),
  mtimeNanoseconds: "1",
  ctimeNanoseconds: "1",
});

async function serviceFixture(
  values: Record<string, string | FixtureFile>,
  directories: string[] = [],
) {
  const files = new Map<string, FixtureFile>(
    Object.entries(values).map(([path, value]) => [
      path,
      typeof value === "string" ? { content: value } : value,
    ]),
  );
  if (!files.has("secrets.yaml"))
    files.set("secrets.yaml", {
      content: "protected_value: supersecretvalue",
      inode: "protected",
    });
  const reader = new FixtureReader(files);
  const protectedRegistry = new ProtectedIdentityRegistry(reader);
  await protectedRegistry.initialize(
    ["secrets.yaml"],
    { loadExactValues: async () => ["supersecretvalue"] },
    operation(),
  );
  const provider = new MutableCatalog({
    rootIdentity: identity("root"),
    directories: directories
      .map(directoryEntry)
      .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))),
    files: [...files.entries()]
      .map(([path, file]) => fileEntry(path, file))
      .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))),
  });
  const cursors = new RepositoryCursorCodec(Buffer.alloc(32, 7));
  return {
    files,
    reader,
    provider,
    protectedRegistry,
    cursors,
    service: new RepositoryResourceService(
      provider,
      reader,
      protectedRegistry,
      cursors,
    ),
  };
}

const ordinaryFiles = {
  "configuration.yaml": [
    "automation: !include_dir_merge_list automations",
    "scene labeled: !include scenes.yaml",
    "script: !include_dir_merge_named scripts",
    "input_boolean:",
    "  lamp:",
    "ignored: !include_dir_list lists",
    "ignored_named: !include_dir_named lists",
    "homeassistant:",
    "  packages: !include_dir_named packages",
  ].join("\n"),
  "automations/a.yaml": [
    "- id: auto_a",
    "  secret_plain: !secret PLAIN_SECRET_CANARY",
    '  secret_quoted: !secret "QUOTED_SECRET_CANARY"',
    "  value: keep_me",
  ].join("\n"),
  "automations/b.yaml": "- id: auto_b\n  value: second",
  "scenes.yaml": "- id: scene_one\n  name: Scene",
  "scripts/a.yaml": "alpha:\n  sequence: []",
  "scripts/b.yaml": "beta:\n  sequence: []",
  "lists/empty.yaml": "",
  "lists/value.yaml": "plain scalar root",
  "lists/ignored.yml": "%YAML malformed orphan",
  "packages/p1.yaml": [
    "automation: !include ../nested/package-auto.yaml",
    "input_text:",
    "  package_name:",
  ].join("\n"),
  "nested/package-auto.yaml": "- id: package_auto\n  value: nested",
};

describe("Slice E repository resource projection", () => {
  it("expands all five include tags in UTF-8 order with packages and nested relative provenance", async () => {
    const value = await serviceFixture(ordinaryFiles, [
      "automations",
      "scripts",
      "lists",
      "packages",
      "nested",
    ]);
    const automations = await value.service.list(
      { resourceType: "automation", limit: 20 },
      operation(),
    );
    expect(automations.items.map((item) => item.resourceId)).toEqual([
      "auto_a",
      "auto_b",
      "package_auto",
    ]);
    expect(automations.items.map((item) => item.path)).toEqual([
      "automations/a.yaml",
      "automations/b.yaml",
      "nested/package-auto.yaml",
    ]);
    await expect(
      value.service.list({ resourceType: "scene", limit: 20 }, operation()),
    ).resolves.toMatchObject({
      items: [{ resourceId: "scene_one", path: "scenes.yaml" }],
    });
    expect(
      (
        await value.service.list(
          { resourceType: "script", limit: 20 },
          operation(),
        )
      ).items.map((item) => item.resourceId),
    ).toEqual(["alpha", "beta"]);
    expect(
      (
        await value.service.list(
          { resourceType: "helper", limit: 20 },
          operation(),
        )
      ).items.map((item) => item.resourceId),
    ).toEqual(["input_boolean.lamp", "input_text.package_name"]);
  });

  it("returns exact source SHA while masking plain and quoted secret spans before full redaction", async () => {
    const value = await serviceFixture(ordinaryFiles, [
      "automations",
      "scripts",
      "lists",
      "packages",
      "nested",
    ]);
    const result = await value.service.get("automation", "auto_a", operation());
    const original = ordinaryFiles["automations/a.yaml"];
    expect(result.sha256).toBe(sha(original));
    expect(result.content).toContain("auto_a");
    expect(result.content).toContain("keep_me");
    expect(result.content).not.toContain("PLAIN_SECRET_CANARY");
    expect(result.content).not.toContain("QUOTED_SECRET_CANARY");
    expect(result.content).toContain("!secret");
    expect(value.reader.transferred.at(-1)?.every((byte) => byte === 0)).toBe(
      true,
    );
  });

  it("binds resource cursor operation, type, snapshot and offset without changing width", async () => {
    const value = await serviceFixture(ordinaryFiles, [
      "automations",
      "scripts",
      "lists",
      "packages",
      "nested",
    ]);
    const first = await value.service.list(
      { resourceType: "automation", limit: 1 },
      operation(),
    );
    expect(first.nextCursor).toHaveLength(136);
    await expect(
      value.service.list(
        {
          resourceType: "script",
          cursor: first.nextCursor!,
          limit: 1,
        },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });

    value.files.set("automations/a.yaml", {
      content: ordinaryFiles["automations/a.yaml"].replace("auto_a", "auto_c"),
    });
    value.provider.value = {
      ...value.provider.value,
      files: [...value.files.entries()]
        .map(([path, file]) => fileEntry(path, file))
        .sort((a, b) =>
          Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)),
        ),
    };
    await expect(
      value.service.list(
        {
          resourceType: "automation",
          cursor: first.nextCursor!,
          limit: 1,
        },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "stale_source" });
  });

  it("projects all three blueprint domains independently and excludes ordinary orphans", async () => {
    const value = await serviceFixture(
      {
        "blueprints/automation/author/a.yaml":
          "blueprint:\n  name: Auto\n  domain: automation",
        "blueprints/script/author/s.yaml":
          "blueprint:\n  name: Script\n  domain: script",
        "blueprints/template/author/t.yaml":
          "blueprint:\n  name: Template\n  domain: template",
        "orphan.yaml": "automation:\n  - id: orphan",
      },
      [
        "blueprints",
        "blueprints/automation",
        "blueprints/automation/author",
        "blueprints/script",
        "blueprints/script/author",
        "blueprints/template",
        "blueprints/template/author",
      ],
    );
    expect(
      (
        await value.service.list(
          { resourceType: "blueprint", limit: 20 },
          operation(),
        )
      ).items.map((item) => item.resourceId),
    ).toEqual([
      "automation/author/a.yaml",
      "script/author/s.yaml",
      "template/author/t.yaml",
    ]);
    await expect(
      value.service.list(
        { resourceType: "automation", limit: 20 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("isolates malformed blueprints from ordinary projection", async () => {
    const value = await serviceFixture(
      {
        ...ordinaryFiles,
        "blueprints/automation/bad.yaml":
          "blueprint:\n  name: Bad\n  domain: script",
      },
      [
        "automations",
        "scripts",
        "lists",
        "packages",
        "nested",
        "blueprints",
        "blueprints/automation",
      ],
    );
    const ordinary = await value.service.list(
      { resourceType: "automation", limit: 20 },
      operation(),
    );
    expect(ordinary.items.length).toBeGreaterThan(0);
    await expect(
      value.service.list({ resourceType: "blueprint", limit: 20 }, operation()),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("fails cycles, missing/escaped targets, protected identity aliases and merge-shape errors", async () => {
    const cases: Array<{
      files: Record<string, string | FixtureFile>;
      directories?: string[];
    }> = [
      {
        files: {
          "configuration.yaml": "automation: !include a.yaml",
          "a.yaml": "!include configuration.yaml",
        },
      },
      {
        files: {
          "configuration.yaml": "automation: !include missing.yaml",
        },
      },
      {
        files: {
          "configuration.yaml": "automation: !include ../../escape.yaml",
        },
      },
      {
        files: {
          "configuration.yaml": "automation: !include alias.yaml",
          "alias.yaml": { content: "- id: hidden", inode: "protected" },
        },
      },
      {
        files: {
          "configuration.yaml":
            "automation: !include_dir_merge_list empty-lists",
          "empty-lists/a.yaml": "",
        },
        directories: ["empty-lists"],
      },
      {
        files: {
          "configuration.yaml":
            "script: !include_dir_merge_named duplicate-maps",
          "duplicate-maps/a.yaml": "same: {}",
          "duplicate-maps/b.yaml": "same: {}",
        },
        directories: ["duplicate-maps"],
      },
    ];
    for (const item of cases) {
      const value = await serviceFixture(item.files, item.directories ?? []);
      await expect(
        value.service.list(
          { resourceType: "automation", limit: 20 },
          operation(),
        ),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
    }
  });

  it("rejects invalid identity shapes and duplicates while omitting absent/empty IDs", async () => {
    for (const invalid of [
      "- id: 1",
      "- id: null",
      "- id: true",
      "- id: !secret SECRET_ID_CANARY",
      "- id: &anchored anchored",
      "- id: !input input_id",
    ]) {
      const value = await serviceFixture({
        "configuration.yaml": "automation: !include invalid.yaml",
        "invalid.yaml": invalid,
      });
      await expect(
        value.service.list(
          { resourceType: "automation", limit: 10 },
          operation(),
        ),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
    }

    const omitted = await serviceFixture({
      "configuration.yaml": "automation: !include omitted.yaml",
      "omitted.yaml": "- name: absent\n- id: ''\n  name: empty",
    });
    await expect(
      omitted.service.get("automation", "missing", operation()),
    ).rejects.toMatchObject({ code: "resource_not_found" });

    const duplicate = await serviceFixture({
      "configuration.yaml":
        "automation: !include root.yaml\nhomeassistant:\n  packages:\n    p:\n      automation: !include package.yaml",
      "root.yaml": "- id: duplicate",
      "package.yaml": "- id: duplicate",
    });
    await expect(
      duplicate.service.list(
        { resourceType: "automation", limit: 10 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("enforces include depth and edge limits at N and N+1", async () => {
    const chain = (edges: number) => {
      const files: Record<string, string> = {
        "configuration.yaml": "ignored: !include depth-0.yaml",
      };
      for (let index = 0; index < edges; index += 1)
        files["depth-" + index + ".yaml"] =
          index + 1 < edges
            ? "!include depth-" + (index + 1) + ".yaml"
            : "terminal: true";
      return files;
    };
    await expect(
      (await serviceFixture(chain(64))).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      (await serviceFixture(chain(65))).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });

    const edgeFixture = async (extra: boolean) => {
      const files: Record<string, string> = {
        "configuration.yaml": "ignored: !include_dir_list layers",
        "target.yaml": "",
      };
      for (let file = 0; file < 200; file += 1) {
        const references = 99 + (extra && file === 0 ? 1 : 0);
        files["layers/" + String(file).padStart(3, "0") + ".yaml"] = Array.from(
          { length: references },
          () => "- !include ../target.yaml",
        ).join("\n");
      }
      return serviceFixture(files, ["layers"]);
    };
    const withinEdges = await edgeFixture(false);
    await expect(
      withinEdges.service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    expect(
      withinEdges.reader.reads.filter((path) => path === "target.yaml"),
    ).toHaveLength(1);
    await expect(
      (await edgeFixture(true)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });
  it("enforces repeated-directory projection work at N and N+1 without rescanning the catalog", async () => {
    const repeatedDirectoryFixture = async (count: number) => {
      const files: Record<string, string> = {
        "configuration.yaml": "ignored: !include_dir_list repeaters",
        "payload/value.yaml":
          "[" + Array.from({ length: 100 }, () => "null").join(",") + "]",
      };
      for (let index = 0; index < count; index += 1)
        files["repeaters/" + String(index).padStart(4, "0") + ".yaml"] =
          "!include_dir_list ../payload";
      return serviceFixture(files, ["payload", "repeaters"]);
    };

    await expect(
      (await repeatedDirectoryFixture(1_706)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      (await repeatedDirectoryFixture(1_707)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({
      code: "service_unhealthy",
      message: "Projection work limit exceeded",
    });
  }, 30_000);
  it("enforces unique parsed-file and retained-string limits at N and N+1", async () => {
    const uniqueFixture = async (filesInDirectory: number) => {
      const files: Record<string, string> = {
        "configuration.yaml": "ignored: !include_dir_list unique",
      };
      for (let index = 0; index < filesInDirectory; index += 1)
        files["unique/" + index + ".yaml"] = "";
      return serviceFixture(files, ["unique"]);
    };
    await expect(
      (await uniqueFixture(1_999)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      (await uniqueFixture(2_000)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });

    const stringFixture = async (layerFiles: number) => {
      const target = "t".repeat(495) + ".yaml";
      const raw = "../" + target;
      const files: Record<string, string> = {
        "configuration.yaml": "ignored: !include_dir_list strings",
      };
      files[target] = "";
      for (let index = 0; index < layerFiles; index += 1)
        files["strings/" + index + ".yaml"] = Array.from(
          { length: 55 },
          () => "- !include " + raw,
        ).join("\n");
      return serviceFixture(files, ["strings"]);
    };
    await expect(
      (await stringFixture(151)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      (await stringFixture(152)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });
  it("accepts explicit empty merge collections as no-ops while rejecting empty documents", async () => {
    const accepted = await serviceFixture(
      {
        "configuration.yaml": [
          "automation: !include_dir_merge_list empty-lists",
          "script: !include_dir_merge_named empty-maps",
        ].join("\n"),
        "empty-lists/a.yaml": "[]",
        "empty-maps/a.yaml": "{}",
      },
      ["empty-lists", "empty-maps"],
    );
    await expect(
      accepted.service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      accepted.service.list({ resourceType: "script", limit: 1 }, operation()),
    ).resolves.toMatchObject({ items: [] });

    for (const [tag, directory] of [
      ["!include_dir_merge_list", "empty-lists"],
      ["!include_dir_merge_named", "empty-maps"],
    ] as const) {
      const rejected = await serviceFixture(
        {
          "configuration.yaml": "ignored: " + tag + " " + directory,
          [directory + "/a.yaml"]: "",
        },
        [directory],
      );
      await expect(
        rejected.service.list(
          { resourceType: "automation", limit: 1 },
          operation(),
        ),
      ).rejects.toMatchObject({ code: "service_unhealthy" });
    }
  });

  it("enforces the inclusive aggregate 16 MiB source boundary at N and N+1", async () => {
    const aggregateFixture = async (extra: number) => {
      const configuration = "ignored: !include_dir_list bytes";
      const files: Record<string, string> = {
        "configuration.yaml": configuration,
      };
      let remaining =
        REPOSITORY_MAX_TOTAL_BYTES - Buffer.byteLength(configuration) + extra;
      for (let index = 0; remaining > 0; index += 1) {
        const size = Math.min(PHASE2_MAX_TEXT_BYTES, remaining);
        const prefix = "value: |\n  ";
        files["bytes/" + String(index).padStart(2, "0") + ".yaml"] =
          prefix + "x".repeat(size - Buffer.byteLength(prefix));
        remaining -= size;
      }
      return serviceFixture(files, ["bytes"]);
    };

    await expect(
      (await aggregateFixture(0)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      (await aggregateFixture(1)).service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  }, 30_000);
  it("enforces the inclusive resource limit with generated fixtures", async () => {
    const make = (count: number) =>
      Array.from({ length: count }, (_, index) => `- id: a${index}`).join("\n");
    const within = await serviceFixture({
      "configuration.yaml": "automation: !include generated.yaml",
      "generated.yaml": make(RESOURCE_MAX_RESOURCES),
    });
    await expect(
      within.service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).resolves.toMatchObject({ items: [{ resourceId: "a0" }] });

    const exceeded = await serviceFixture({
      "configuration.yaml": "automation: !include generated.yaml",
      "generated.yaml": make(RESOURCE_MAX_RESOURCES + 1),
    });
    await expect(
      exceeded.service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });

  it("indexes deterministic immutable list pages and exact get lookups", async () => {
    const automations = Array.from(
      { length: 600 },
      (_, index) => `- id: a${String(index).padStart(3, "0")}`,
    ).join("\n");
    const fixture = await serviceFixture({
      "configuration.yaml": [
        "automation: !include automations.yaml",
        "script: !include scripts.yaml",
      ].join("\n"),
      "automations.yaml": automations,
      "scripts.yaml": "z_script:\n  sequence: []",
    });

    const first = await fixture.service.list(
      { resourceType: "automation", limit: 500 },
      operation(),
    );
    expect(first.items).toHaveLength(500);
    expect(first.items[0]?.resourceId).toBe("a000");
    expect(first.items[499]?.resourceId).toBe("a499");
    expect(Object.isFrozen(first.items)).toBe(true);
    expect(Object.isFrozen(first.items[0])).toBe(true);
    expect(first.nextCursor).not.toBeNull();

    const second = await fixture.service.list(
      {
        resourceType: "automation",
        cursor: first.nextCursor!,
        limit: 500,
      },
      operation(),
    );
    expect(second.items).toHaveLength(100);
    expect(second.items[0]?.resourceId).toBe("a500");
    expect(second.items[99]?.resourceId).toBe("a599");

    await expect(
      fixture.service.get("automation", "a599", operation()),
    ).resolves.toMatchObject({
      resourceType: "automation",
      resourceId: "a599",
      path: "automations.yaml",
    });
    await expect(
      fixture.service.get("script", "a599", operation()),
    ).rejects.toMatchObject({ code: "resource_not_found" });
  });

  it("polls cancellation and deadlines across high-cardinality extraction scans", async () => {
    const rootNoise = Array.from(
      { length: 2_000 },
      (_, index) => `root_noise_${index}: true`,
    );
    const packageNoise = Array.from(
      { length: 2_000 },
      (_, index) => `      package_noise_${index}: true`,
    );
    const automationNoise = Array.from(
      { length: 2_000 },
      (_, index) => `    automation_noise_${index}: true`,
    );
    const ordinarySource = [
      ...rootNoise,
      "homeassistant:",
      "  packages:",
      "    noisy_package:",
      ...packageNoise,
      "automation:",
      "  - alias: noisy",
      ...automationNoise,
      "    id: target_id",
    ].join("\n");
    const measure = await serviceFixture({
      "configuration.yaml": ordinarySource,
    });
    let totalChecks = 0;
    const measuringSignal = {
      get aborted() {
        totalChecks += 1;
        return false;
      },
    } as AbortSignal;
    await expect(
      measure.service.list(
        { resourceType: "automation", limit: 1 },
        operation(measuringSignal),
      ),
    ).resolves.toMatchObject({ items: [{ resourceId: "target_id" }] });
    expect(totalChecks).toBeGreaterThan(20);

    const cancelled = await serviceFixture({
      "configuration.yaml": ordinarySource,
    });
    let cancellationChecks = 0;
    const cancellationSignal = {
      get aborted() {
        cancellationChecks += 1;
        return cancellationChecks >= totalChecks - 2;
      },
    } as AbortSignal;
    await expect(
      cancelled.service.list(
        { resourceType: "automation", limit: 1 },
        operation(cancellationSignal),
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });

    const blueprintMetadata = [
      "blueprint:",
      ...Array.from(
        { length: 4_000 },
        (_, index) => `  metadata_noise_${index}: true`,
      ),
      "  name: Noisy blueprint",
      "  domain: automation",
    ].join("\n");
    const blueprintValues = {
      "configuration.yaml": "ignored: true",
      "blueprints/automation/noisy.yaml": blueprintMetadata,
    };
    const clockBase = 50_000;
    const deadlineMeasure = await serviceFixture(blueprintValues, [
      "blueprints",
      "blueprints/automation",
    ]);
    let totalClockChecks = 0;
    const measuringClock = vi.spyOn(Date, "now").mockImplementation(() => {
      totalClockChecks += 1;
      return clockBase;
    });
    try {
      await deadlineMeasure.service.list(
        { resourceType: "blueprint", limit: 1 },
        { ...operation(), deadlineAt: clockBase + 30_000 },
      );
    } finally {
      measuringClock.mockRestore();
    }
    expect(totalClockChecks).toBeGreaterThan(10);

    const deadlineFixture = await serviceFixture(blueprintValues, [
      "blueprints",
      "blueprints/automation",
    ]);
    let deadlineChecks = 0;
    const expiringClock = vi.spyOn(Date, "now").mockImplementation(() => {
      deadlineChecks += 1;
      return deadlineChecks >= totalClockChecks - 2
        ? clockBase + 30_000
        : clockBase;
    });
    try {
      await expect(
        deadlineFixture.service.list(
          { resourceType: "blueprint", limit: 1 },
          { ...operation(), deadlineAt: clockBase + 30_000 },
        ),
      ).rejects.toMatchObject({ code: "deadline_exceeded" });
    } finally {
      expiringClock.mockRestore();
    }
  });
  it("polls cancellation while building the directory index and during secret/snapshot finishing work", async () => {
    const indexedFiles: Record<string, string> = {
      "configuration.yaml": "ignored: true",
    };
    for (let index = 0; index < 1_000; index += 1)
      indexedFiles["orphans/" + index + ".yaml"] = "";
    const indexed = await serviceFixture(indexedFiles, ["orphans"]);
    let indexChecks = 0;
    const indexSignal = {
      get aborted() {
        indexChecks += 1;
        return indexChecks >= 3;
      },
    } as AbortSignal;
    await expect(
      indexed.service.list(
        { resourceType: "automation", limit: 1 },
        operation(indexSignal),
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
    expect(indexChecks).toBeGreaterThanOrEqual(3);

    const finishingSource = [
      ...Array.from(
        { length: 100 },
        (_, index) => "secret_" + index + ": !secret VALUE_" + index,
      ),
      ...Array.from(
        { length: 5_000 },
        (_, index) => "ignored_" + index + ": value",
      ),
    ].join("\n");
    const measure = await serviceFixture({
      "configuration.yaml": finishingSource,
    });
    let totalChecks = 0;
    const measuringSignal = {
      get aborted() {
        totalChecks += 1;
        return false;
      },
    } as AbortSignal;
    await measure.service.list(
      { resourceType: "automation", limit: 1 },
      operation(measuringSignal),
    );
    expect(totalChecks).toBeGreaterThan(10);

    const interrupted = await serviceFixture({
      "configuration.yaml": finishingSource,
    });
    let finishChecks = 0;
    const finishSignal = {
      get aborted() {
        finishChecks += 1;
        return finishChecks >= totalChecks - 2;
      },
    } as AbortSignal;
    await expect(
      interrupted.service.list(
        { resourceType: "automation", limit: 1 },
        operation(finishSignal),
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });
  });
  it("polls cancellation during large projection work and rejects root identity drift", async () => {
    const content = Array.from(
      { length: 10_000 },
      (_, index) => `- id: cancel_${index}`,
    ).join("\n");
    const cancelled = await serviceFixture({
      "configuration.yaml": "automation: !include generated.yaml",
      "generated.yaml": content,
    });
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks >= 30;
      },
    } as AbortSignal;
    await expect(
      cancelled.service.list(
        { resourceType: "automation", limit: 1 },
        operation(signal),
      ),
    ).rejects.toMatchObject({ code: "operation_cancelled" });

    const drifted = await serviceFixture(ordinaryFiles, [
      "automations",
      "scripts",
      "lists",
      "packages",
      "nested",
    ]);
    drifted.reader.rootIdentity = identity("changed-root");
    await expect(
      drifted.service.list(
        { resourceType: "automation", limit: 1 },
        operation(),
      ),
    ).rejects.toMatchObject({ code: "service_unhealthy" });
  });
});
