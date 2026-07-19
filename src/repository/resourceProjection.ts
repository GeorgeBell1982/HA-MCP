import { createHash, type Hash } from "node:crypto";
import { posix } from "node:path";
import {
  configResourceTypeSchema,
  relativeConfigPathSchema,
  resourceIdSchema,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import {
  REPOSITORY_MAX_TOTAL_BYTES,
  RepositoryCursorCodec,
  type CatalogFile,
  type RepositoryCatalog,
  type RepositoryCatalogProvider,
  type RepositoryPage,
} from "./repositoryReads.js";
import {
  ProtectedIdentityRegistry,
  RepositoryBoundaryError,
  assertOperationActive,
  type FileIdentity,
  type SecureFileReader,
} from "../security/repositoryBoundary.js";
import {
  validateAndProjectYaml,
  YamlGateError,
  type ProjectedYamlMapEntry,
  type ProjectedYamlNode,
  type StrictYamlProjection,
  type YamlSourceRange,
} from "../yaml/strictYamlGate.js";

export const RESOURCE_PROJECTION_RULES_VERSION = 1;
export const RESOURCE_MAX_UNIQUE_FILES = 2_000;
export const RESOURCE_MAX_EDGES = 20_000;
export const RESOURCE_MAX_INCLUDE_DEPTH = 64;
export const RESOURCE_MAX_WORK = 200_000;
export const RESOURCE_MAX_RETAINED_NODES = 200_000;
export const RESOURCE_MAX_RESOURCES = 20_000;
export const RESOURCE_MAX_STRING_BYTES = 4 * 1024 * 1024;

export type ConfigResourceType =
  | "automation"
  | "script"
  | "helper"
  | "scene"
  | "blueprint";

export interface RepositoryResourceSummary {
  readonly resourceType: ConfigResourceType;
  readonly resourceId: string;
  readonly path: string;
  readonly sha256: string;
}

export interface RepositoryResourceContent extends RepositoryResourceSummary {
  readonly content: string;
}

interface SourceRecord {
  readonly path: string;
  readonly identity: FileIdentity;
  readonly sha256: string;
  readonly bytes: number;
  readonly projection: StrictYamlProjection;
  readonly secretRanges: readonly YamlSourceRange[];
}

interface IncludeEdge {
  readonly tag: string;
  readonly source: string;
  readonly target: string;
  readonly order: number;
}

interface ResourceRecord extends RepositoryResourceSummary {
  readonly provenance: string;
}

interface ProjectionGraph {
  readonly catalog: RepositoryCatalog;
  readonly sources: ReadonlyMap<string, SourceRecord>;
  readonly edges: readonly IncludeEdge[];
  readonly resources: readonly ResourceRecord[];
  readonly resourcesByType: ReadonlyMap<
    ConfigResourceType,
    readonly RepositoryResourceSummary[]
  >;
  readonly resourceByKey: ReadonlyMap<string, ResourceRecord>;
  readonly snapshotSha256: string;
}

interface ResolvedEntry {
  readonly keyType: ProjectedYamlMapEntry["keyType"];
  readonly key?: string | undefined;
  readonly value: ResolvedNode | null;
  readonly sourcePath: string;
}

type ResolvedNode =
  | Readonly<{
      kind: "map";
      entries: readonly ResolvedEntry[];
      sourcePath: string;
      projected: Extract<ProjectedYamlNode, { kind: "map" }>;
    }>
  | Readonly<{
      kind: "sequence";
      items: readonly ResolvedNode[];
      sourcePath: string;
      projected: Extract<ProjectedYamlNode, { kind: "sequence" }>;
    }>
  | Readonly<{
      kind: "leaf";
      sourcePath: string;
      projected: Exclude<ProjectedYamlNode, { kind: "map" | "sequence" }>;
    }>;

const NULL_NODE = Object.freeze({
  kind: "scalar" as const,
  scalarType: "null" as const,
  anchored: false,
});
const HELPER_DOMAINS = new Set([
  "counter",
  "input_boolean",
  "input_button",
  "input_datetime",
  "input_number",
  "input_select",
  "input_text",
  "timer",
]);
const BLUEPRINT_DOMAINS = ["automation", "script", "template"] as const;
const RESOURCE_TYPES: readonly ConfigResourceType[] = [
  "automation",
  "script",
  "helper",
  "scene",
  "blueprint",
];
const SNAPSHOT_DOMAIN = Buffer.from("HA_RESOURCE_PROJECTION_V1\0", "ascii");

export class RepositoryResourceService {
  constructor(
    private readonly catalogs: RepositoryCatalogProvider,
    private readonly reader: SecureFileReader,
    private readonly protectedRegistry: ProtectedIdentityRegistry,
    private readonly cursors: RepositoryCursorCodec,
  ) {}

  async list(
    input: {
      readonly resourceType: ConfigResourceType;
      readonly cursor?: string;
      readonly limit: number;
    },
    context: Phase2OperationContext,
  ): Promise<RepositoryPage<RepositoryResourceSummary>> {
    return this.sanitize(async () => {
      assertResourceType(input.resourceType);
      assertResourceLimit(input.limit);
      const typeDigest = resourceTypeDigest(input.resourceType);
      const decoded = input.cursor
        ? this.cursors.decode(input.cursor, "resource-list", typeDigest)
        : undefined;
      const graph = await this.project(input.resourceType, context);
      const resources = graph.resourcesByType.get(input.resourceType) ?? [];
      if (
        decoded &&
        (decoded.snapshotSha256 !== graph.snapshotSha256 ||
          decoded.offset > resources.length)
      )
        throw boundary("stale_source", "Resource cursor is stale");
      const offset = decoded?.offset ?? 0;
      const items = Object.freeze(
        resources.slice(offset, offset + input.limit),
      );
      await this.protectedRegistry.assertFresh(context);
      return Object.freeze({
        items: Object.freeze(items),
        nextCursor:
          offset + items.length < resources.length
            ? this.cursors.encode(
                "resource-list",
                offset + items.length,
                typeDigest,
                graph.snapshotSha256,
              )
            : null,
        snapshotSha256: graph.snapshotSha256,
      });
    });
  }

  async get(
    resourceType: ConfigResourceType,
    resourceId: string,
    context: Phase2OperationContext,
  ): Promise<RepositoryResourceContent> {
    return this.sanitize(async () => {
      assertResourceType(resourceType);
      if (!resourceIdSchema.safeParse(resourceId).success)
        throw boundary("invalid_input", "Resource ID is invalid");
      const graph = await this.project(resourceType, context);
      const resource = graph.resourceByKey.get(
        resourceKey(resourceType, resourceId),
      );
      if (!resource)
        throw boundary("resource_not_found", "Resource was not found");
      const source = graph.sources.get(resource.path);
      if (!source) throw unhealthy("Resource source is unavailable");
      const read = await this.reader.read(resource.path, context);
      try {
        validateSecureRead(
          graph.catalog.rootIdentity,
          source.identity,
          source.bytes,
          read.rootIdentity,
          read.identity,
          read.bytes.byteLength,
        );
        if (digest(read.bytes) !== source.sha256)
          throw unhealthy("Resource source changed after projection");
        for (const range of source.secretRanges) {
          if (
            range.startByte < 0 ||
            range.endByte < range.startByte ||
            range.endByte > read.bytes.byteLength
          )
            throw unhealthy("Secret source range is invalid");
          read.bytes.fill(0x2a, range.startByte, range.endByte);
        }
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
        } catch {
          throw boundary(
            "unsupported_encoding",
            "Resource source encoding is invalid",
          );
        }
        const content = this.protectedRegistry.redactWholeText(text, context);
        await this.protectedRegistry.assertFresh(context);
        return Object.freeze({
          ...publicSummary(resource),
          content,
        });
      } finally {
        read.bytes.fill(0);
      }
    });
  }

  private async project(
    resourceType: ConfigResourceType,
    context: Phase2OperationContext,
  ): Promise<ProjectionGraph> {
    await this.protectedRegistry.assertFresh(context);
    const catalog = await this.catalogs.catalog(context);
    const operation = new ProjectionOperation(
      catalog,
      this.reader,
      this.protectedRegistry,
      context,
    );
    const graph =
      resourceType === "blueprint"
        ? await operation.projectBlueprints()
        : await operation.projectOrdinary();
    await this.protectedRegistry.assertFresh(context);
    return graph;
  }

  private async sanitize<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof RepositoryBoundaryError) throw error;
      if (
        error instanceof YamlGateError &&
        (error.code === "operation_cancelled" ||
          error.code === "deadline_exceeded")
      )
        throw boundary(error.code, "Resource projection was interrupted");
      if (error instanceof YamlGateError)
        throw unhealthy("Reachable YAML failed strict projection");
      throw unhealthy("Resource projection failed safely");
    }
  }
}

class ProjectionOperation {
  private readonly files = new Map<string, CatalogFile>();
  private readonly directories = new Set<string>();
  private readonly directoryFiles = new Map<string, readonly string[]>();
  private readonly sources = new Map<string, SourceRecord>();
  private readonly edges: IncludeEdge[] = [];
  private readonly resources: ResourceRecord[] = [];
  private readonly resourceKeys = new Set<string>();
  private work = 0;
  private retainedNodes = 0;
  private retainedStrings = 0;
  private resourceCandidates = 0;
  private totalSourceBytes = 0;

  constructor(
    private readonly catalog: RepositoryCatalog,
    private readonly reader: SecureFileReader,
    private readonly protectedRegistry: ProtectedIdentityRegistry,
    private readonly context: Phase2OperationContext,
  ) {
    for (const file of catalog.files) {
      this.charge();
      this.files.set(file.path, file);
    }
    const indexed = new Map<string, string[]>();
    for (const directory of catalog.directories) {
      this.charge();
      this.directories.add(directory.path);
      indexed.set(directory.path, []);
    }
    const yamlPaths = [...this.files.keys()].filter((path) => {
      this.charge();
      return path.endsWith(".yaml");
    });
    yamlPaths.sort((left, right) => {
      this.charge();
      return compareUtf8(left, right);
    });
    for (const path of yamlPaths) {
      let directory = posix.dirname(path);
      while (directory !== ".") {
        this.charge();
        indexed.get(directory)?.push(path);
        const parent = posix.dirname(directory);
        if (parent === directory) break;
        directory = parent;
      }
    }
    for (const [directory, paths] of indexed) {
      this.charge();
      this.directoryFiles.set(directory, Object.freeze(paths));
    }
  }

  async projectOrdinary(): Promise<ProjectionGraph> {
    const root = await this.loadAndExpand(
      "configuration.yaml",
      ["configuration.yaml"],
      0,
    );
    if (root.kind !== "map")
      throw unhealthy("configuration.yaml must project to a map");
    this.extractDomainMap(root, "configuration.yaml");
    this.extractPackages(root);
    return this.finish();
  }

  async projectBlueprints(): Promise<ProjectionGraph> {
    for (const domain of BLUEPRINT_DOMAINS) {
      this.charge();
      const paths = this.directoryFiles.get(`blueprints/${domain}`) ?? [];
      for (const path of paths) {
        this.charge();
        const source = await this.parseFile(path);
        const root = await this.expandProjection(
          source.projection.root ?? leaf(NULL_NODE, path),
          path,
          [path],
          0,
        );
        this.extractBlueprint(root, path, domain);
      }
    }
    return this.finish();
  }

  private async loadAndExpand(
    path: string,
    stack: readonly string[],
    depth: number,
  ): Promise<ResolvedNode> {
    const source = await this.parseFile(path);
    return this.expandProjection(
      source.projection.root ?? leaf(NULL_NODE, path),
      path,
      stack,
      depth,
    );
  }

  private async expandProjection(
    projectedOrResolved: ProjectedYamlNode | ResolvedNode,
    sourcePath: string,
    stack: readonly string[],
    depth: number,
    parentKey?: string,
  ): Promise<ResolvedNode> {
    this.charge();
    const projected =
      "sourcePath" in projectedOrResolved
        ? projectedOrResolved.projected
        : projectedOrResolved;
    if (projected.kind === "include" && parentKey !== "id")
      return this.expandInclude(projected, sourcePath, stack, depth);
    if (projected.kind === "map") {
      const entries: ResolvedEntry[] = [];
      for (const entry of projected.entries) {
        this.charge();
        const value = entry.value
          ? await this.expandProjection(
              entry.value,
              sourcePath,
              stack,
              depth,
              entry.key,
            )
          : null;
        entries.push(
          Object.freeze({
            keyType: entry.keyType,
            key: entry.key,
            value,
            sourcePath: value?.sourcePath ?? sourcePath,
          }),
        );
      }
      return Object.freeze({
        kind: "map",
        entries: Object.freeze(entries),
        sourcePath,
        projected,
      });
    }
    if (projected.kind === "sequence") {
      const items: ResolvedNode[] = [];
      for (const item of projected.items)
        items.push(await this.expandProjection(item, sourcePath, stack, depth));
      return Object.freeze({
        kind: "sequence",
        items: Object.freeze(items),
        sourcePath,
        projected,
      });
    }
    return leaf(projected, sourcePath);
  }

  private async expandInclude(
    include: Extract<ProjectedYamlNode, { kind: "include" }>,
    sourcePath: string,
    stack: readonly string[],
    depth: number,
  ): Promise<ResolvedNode> {
    if (depth >= RESOURCE_MAX_INCLUDE_DEPTH)
      throw unhealthy("Include depth exceeded");
    const target = resolveRelative(sourcePath, include.value);
    if (include.tag === "!include") {
      const file = this.requireFile(target, true);
      return this.followInclude(
        include.tag,
        sourcePath,
        file.path,
        stack,
        depth,
      );
    }
    if (!this.directories.has(target))
      throw unhealthy("Include directory is unavailable");
    const paths = this.directoryFiles.get(target) ?? [];
    if (include.tag === "!include_dir_list") {
      const items: ResolvedNode[] = [];
      for (const path of paths)
        items.push(
          await this.followInclude(include.tag, sourcePath, path, stack, depth),
        );
      return sequence(items, sourcePath);
    }
    if (include.tag === "!include_dir_named") {
      const entries: ResolvedEntry[] = [];
      const names = new Set<string>();
      for (const path of paths) {
        const name = posix.basename(path, ".yaml");
        if (names.has(name))
          throw unhealthy("Named include contains duplicate basenames");
        names.add(name);
        const value = await this.followInclude(
          include.tag,
          sourcePath,
          path,
          stack,
          depth,
        );
        entries.push(
          Object.freeze({
            keyType: "string",
            key: name,
            value,
            sourcePath: path,
          }),
        );
      }
      return map(entries, sourcePath);
    }
    if (include.tag === "!include_dir_merge_list") {
      const items: ResolvedNode[] = [];
      for (const path of paths) {
        const value = await this.followInclude(
          include.tag,
          sourcePath,
          path,
          stack,
          depth,
        );
        if (value.kind !== "sequence")
          throw unhealthy("Merged list include requires sequences");
        for (const item of value.items) {
          this.charge();
          items.push(item);
        }
      }
      return sequence(items, sourcePath);
    }
    const entries: ResolvedEntry[] = [];
    const keys = new Set<string>();
    for (const path of paths) {
      const value = await this.followInclude(
        include.tag,
        sourcePath,
        path,
        stack,
        depth,
      );
      if (value.kind !== "map")
        throw unhealthy("Merged named include requires maps");
      for (const entry of value.entries) {
        this.charge();
        const identity = `${entry.keyType}:${entry.key ?? ""}`;
        if (keys.has(identity))
          throw unhealthy("Merged named include contains duplicate keys");
        keys.add(identity);
        entries.push(entry);
      }
    }
    return map(entries, sourcePath);
  }

  private async followInclude(
    tag: string,
    source: string,
    target: string,
    stack: readonly string[],
    depth: number,
  ): Promise<ResolvedNode> {
    for (const ancestor of stack) {
      this.charge();
      if (ancestor === target) throw unhealthy("Include cycle detected");
    }
    this.edges.push(
      Object.freeze({
        tag,
        source,
        target,
        order: this.edges.length,
      }),
    );
    if (this.edges.length > RESOURCE_MAX_EDGES)
      throw unhealthy("Include edge limit exceeded");
    this.charge();
    return this.loadAndExpand(target, [...stack, target], depth + 1);
  }

  private async parseFile(path: string): Promise<SourceRecord> {
    const cached = this.sources.get(path);
    if (cached) return cached;
    if (this.sources.size >= RESOURCE_MAX_UNIQUE_FILES)
      throw unhealthy("Unique YAML file limit exceeded");
    const entry = this.requireFile(path, false);
    if (this.protectedRegistry.isProtected(entry.path, entry.identity))
      throw boundary("protected_resource", "Included source is protected");
    if (this.totalSourceBytes + entry.size > REPOSITORY_MAX_TOTAL_BYTES)
      throw unhealthy("Total projected source bytes exceeded the boundary");
    assertOperationActive(this.context);
    const read = await this.reader.read(path, this.context);
    try {
      validateSecureRead(
        this.catalog.rootIdentity,
        entry.identity,
        entry.size,
        read.rootIdentity,
        read.identity,
        read.bytes.byteLength,
      );
      this.totalSourceBytes += read.bytes.byteLength;
      const sha256 = digest(read.bytes);
      const projection = await validateAndProjectYaml(read.bytes, this.context);
      if (projection.metadata.sha256 !== sha256)
        throw unhealthy("Projected source digest is inconsistent");
      this.retainedNodes += projection.retainedNodeCount;
      this.retainedStrings += projection.retainedStringBytes;
      if (this.retainedNodes > RESOURCE_MAX_RETAINED_NODES)
        throw unhealthy("Retained projection node limit exceeded");
      if (this.retainedStrings > RESOURCE_MAX_STRING_BYTES)
        throw unhealthy("Retained projection string limit exceeded");
      const record = Object.freeze({
        path,
        identity: entry.identity,
        sha256,
        bytes: read.bytes.byteLength,
        projection,
        secretRanges: Object.freeze(
          collectSecretRanges(projection.root, () => this.charge()),
        ),
      });
      this.sources.set(path, record);
      assertOperationActive(this.context);
      return record;
    } finally {
      read.bytes.fill(0);
    }
  }

  private requireFile(path: string, includeExtension: boolean): CatalogFile {
    const entry = this.files.get(path);
    if (
      !entry ||
      (includeExtension && !/\.ya?ml$/u.test(path)) ||
      this.protectedRegistry.isProtected(path, entry.identity)
    )
      throw unhealthy("Included YAML source is unavailable");
    return entry;
  }

  private extractPackages(root: Extract<ResolvedNode, { kind: "map" }>): void {
    for (const home of root.entries) {
      this.charge();
      if (home.key !== "homeassistant" || !home.value) continue;
      if (home.value.kind !== "map")
        throw unhealthy("homeassistant must be a map");
      for (const packages of home.value.entries) {
        this.charge();
        if (packages.key !== "packages" || !packages.value) continue;
        if (packages.value.kind === "map") {
          for (const item of packages.value.entries) {
            this.charge();
            if (item.keyType !== "string" || item.value?.kind !== "map")
              throw unhealthy("Each package value must be a map");
            this.extractDomainMap(item.value, item.sourcePath);
          }
        } else if (packages.value.kind === "sequence") {
          for (const item of packages.value.items) {
            this.charge();
            if (item.kind !== "map")
              throw unhealthy("Each included package must be a map");
            this.extractDomainMap(item, item.sourcePath);
          }
        } else throw unhealthy("Packages must project to a map or sequence");
      }
    }
  }

  private extractDomainMap(
    root: Extract<ResolvedNode, { kind: "map" }>,
    provenance: string,
  ): void {
    for (const entry of root.entries) {
      this.charge();
      if (entry.keyType !== "string" || !entry.key || !entry.value) continue;
      const domain = recognizedDomain(entry.key);
      if (!domain) continue;
      if (domain === "automation" || domain === "scene")
        this.extractSequenceResources(domain, entry.value, entry.key);
      else if (domain === "script")
        this.extractKeyedResources("script", entry.value, entry.key, false);
      else this.extractKeyedResources("helper", entry.value, domain, true);
    }
    void provenance;
  }

  private extractSequenceResources(
    resourceType: "automation" | "scene",
    value: ResolvedNode,
    provenance: string,
  ): void {
    if (value.kind !== "sequence")
      throw unhealthy(`${resourceType} resources must be a sequence`);
    for (const item of value.items) {
      this.charge();
      this.resourceCandidates += 1;
      if (this.resourceCandidates > RESOURCE_MAX_RESOURCES)
        throw unhealthy("Resource candidate limit exceeded");
      if (item.kind !== "map")
        throw unhealthy(`${resourceType} entries must be maps`);
      let idNode: ResolvedNode | null | undefined;
      for (const entry of item.entries) {
        this.charge();
        if (entry.key !== "id") continue;
        if (idNode !== undefined)
          throw unhealthy("Resource contains duplicate id");
        idNode = entry.value;
      }
      if (!idNode) continue;
      const projected = idNode.projected;
      if (
        idNode.kind !== "leaf" ||
        projected.kind !== "scalar" ||
        projected.scalarType !== "string" ||
        projected.anchored ||
        projected.identity === undefined
      )
        throw unhealthy("Resource id has an invalid YAML shape");
      if (projected.identity === "") continue;
      this.addResource(
        resourceType,
        projected.identity,
        item.sourcePath,
        `${item.sourcePath}#${provenance}`,
      );
    }
  }

  private extractKeyedResources(
    resourceType: "script" | "helper",
    value: ResolvedNode,
    domain: string,
    prefixDomain: boolean,
  ): void {
    if (value.kind !== "map")
      throw unhealthy(`${domain} resources must be a map`);
    for (const entry of value.entries) {
      this.charge();
      this.resourceCandidates += 1;
      if (this.resourceCandidates > RESOURCE_MAX_RESOURCES)
        throw unhealthy("Resource candidate limit exceeded");
      if (entry.keyType !== "string" || entry.key === undefined)
        throw unhealthy("Resource map key must be a string");
      const id = prefixDomain ? `${domain}.${entry.key}` : entry.key;
      this.addResource(
        resourceType,
        id,
        entry.sourcePath,
        `${entry.sourcePath}#${domain}`,
      );
    }
  }

  private extractBlueprint(
    root: ResolvedNode,
    path: string,
    domain: (typeof BLUEPRINT_DOMAINS)[number],
  ): void {
    if (root.kind !== "map") throw unhealthy("Blueprint root must be a map");
    let blueprint: ResolvedEntry | undefined;
    for (const entry of root.entries) {
      this.charge();
      if (entry.key !== "blueprint") continue;
      if (blueprint) throw unhealthy("Blueprint metadata is duplicated");
      blueprint = entry;
    }
    if (!blueprint?.value || blueprint.value.kind !== "map")
      throw unhealthy("Blueprint metadata must be a map");
    const name = requiredIdentity(blueprint.value, "name", () => this.charge());
    const declaredDomain = requiredIdentity(blueprint.value, "domain", () =>
      this.charge(),
    );
    if (declaredDomain !== domain || name.length === 0)
      throw unhealthy("Blueprint metadata is invalid");
    const prefix = `blueprints/${domain}/`;
    if (!path.startsWith(prefix)) throw unhealthy("Blueprint path is invalid");
    const id = `${domain}/${path.slice(prefix.length)}`;
    this.addResource("blueprint", id, path, `${path}#blueprint:${name}`);
  }

  private addResource(
    resourceType: ConfigResourceType,
    resourceId: string,
    path: string,
    provenance: string,
  ): void {
    if (!resourceIdSchema.safeParse(resourceId).success)
      throw unhealthy("Projected resource ID is outside bounds");
    const source = this.sources.get(path);
    if (!source) throw unhealthy("Resource provenance source is unavailable");
    const key = resourceKey(resourceType, resourceId);
    if (this.resourceKeys.has(key))
      throw unhealthy("Projected resource ID is duplicated");
    this.resourceKeys.add(key);
    this.resources.push(
      Object.freeze({
        resourceType,
        resourceId,
        path,
        sha256: source.sha256,
        provenance,
      }),
    );
    if (this.resources.length > RESOURCE_MAX_RESOURCES)
      throw unhealthy("Resource limit exceeded");
  }

  private finish(): ProjectionGraph {
    const resources = this.resources;
    resources.sort((left, right) => {
      this.charge();
      const type = compareUtf8(left.resourceType, right.resourceType);
      return type || compareUtf8(left.resourceId, right.resourceId);
    });
    const sources: SourceRecord[] = [];
    for (const source of this.sources.values()) {
      this.charge();
      sources.push(source);
    }
    sources.sort((left, right) => {
      this.charge();
      return compareUtf8(left.path, right.path);
    });
    const mutableByType = new Map<
      ConfigResourceType,
      RepositoryResourceSummary[]
    >();
    for (const resourceType of RESOURCE_TYPES)
      mutableByType.set(resourceType, []);
    const resourceByKey = new Map<string, ResourceRecord>();
    const snapshotSha256 = projectionSnapshot(
      this.catalog.rootIdentity,
      sources,
      this.edges,
      resources,
      () => this.charge(),
      (resource) => {
        mutableByType.get(resource.resourceType)!.push(publicSummary(resource));
        resourceByKey.set(
          resourceKey(resource.resourceType, resource.resourceId),
          resource,
        );
      },
    );
    const resourcesByType = new Map<
      ConfigResourceType,
      readonly RepositoryResourceSummary[]
    >();
    for (const resourceType of RESOURCE_TYPES) {
      this.charge();
      resourcesByType.set(
        resourceType,
        Object.freeze(mutableByType.get(resourceType)!),
      );
    }
    return Object.freeze({
      catalog: this.catalog,
      sources: this.sources,
      edges: Object.freeze(this.edges),
      resources: Object.freeze(resources),
      resourcesByType,
      resourceByKey,
      snapshotSha256,
    });
  }

  private charge(): void {
    if ((this.work & 255) === 0) assertOperationActive(this.context);
    this.work += 1;
    if (this.work > RESOURCE_MAX_WORK)
      throw unhealthy("Projection work limit exceeded");
  }
}

function requiredIdentity(
  mapNode: Extract<ResolvedNode, { kind: "map" }>,
  key: string,
  charge: () => void,
): string {
  let value: ResolvedNode | null | undefined;
  for (const entry of mapNode.entries) {
    charge();
    if (entry.key !== key) continue;
    if (value !== undefined) throw unhealthy("Required identity is duplicated");
    value = entry.value;
  }
  if (value === undefined) throw unhealthy("Required identity is missing");
  if (
    value?.kind !== "leaf" ||
    value.projected.kind !== "scalar" ||
    value.projected.scalarType !== "string" ||
    value.projected.anchored ||
    value.projected.identity === undefined ||
    !resourceIdSchema.safeParse(value.projected.identity).success
  )
    throw unhealthy("Required identity is invalid");
  return value.projected.identity;
}

function recognizedDomain(key: string): string | undefined {
  const domains = ["automation", "scene", "script", ...HELPER_DOMAINS];
  for (const domain of domains)
    if (
      key === domain ||
      (key.startsWith(`${domain} `) && key.length > domain.length + 1)
    )
      return domain;
  return undefined;
}

function resolveRelative(containingPath: string, raw: string): string {
  if (
    raw !== raw.normalize("NFC") ||
    raw.startsWith("/") ||
    raw.includes("\\") ||
    raw.includes(":") ||
    /\p{Cc}/u.test(raw)
  )
    throw unhealthy("Include reference is invalid");
  const normalized = posix.normalize(
    posix.join(posix.dirname(containingPath), raw),
  );
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    !relativeConfigPathSchema.safeParse(normalized).success
  )
    throw unhealthy("Include reference escapes the repository root");
  return normalized;
}

function validateSecureRead(
  catalogRoot: FileIdentity,
  expectedIdentity: FileIdentity,
  expectedSize: number,
  readRoot: FileIdentity,
  readIdentity: FileIdentity,
  readSize: number,
): void {
  if (
    catalogRoot.device !== readRoot.device ||
    catalogRoot.inode !== readRoot.inode ||
    expectedIdentity.device !== readIdentity.device ||
    expectedIdentity.inode !== readIdentity.inode ||
    expectedSize !== readSize
  )
    throw unhealthy("Repository source changed during projection");
}

function collectSecretRanges(
  root: ProjectedYamlNode | null,
  charge: () => void,
): YamlSourceRange[] {
  const ranges: YamlSourceRange[] = [];
  const visit = (node: ProjectedYamlNode | null): void => {
    charge();
    if (!node) return;
    if (node.kind === "secret") ranges.push(node.sourceRange);
    else if (node.kind === "map")
      for (const entry of node.entries) visit(entry.value);
    else if (node.kind === "sequence")
      for (const item of node.items) visit(item);
  };
  visit(root);
  return ranges.sort((left, right) => {
    charge();
    return left.startByte - right.startByte;
  });
}

function projectionSnapshot(
  root: FileIdentity,
  sources: readonly SourceRecord[],
  edges: readonly IncludeEdge[],
  resources: readonly ResourceRecord[],
  charge: () => void,
  indexResource: (resource: ResourceRecord) => void,
): string {
  const hash = createHash("sha256");
  hash.update(SNAPSHOT_DOMAIN);
  updateField(hash, String(RESOURCE_PROJECTION_RULES_VERSION));
  updateField(hash, root.device);
  updateField(hash, root.inode);
  for (const source of sources) {
    charge();
    hash.update(Buffer.from([1]));
    updateField(hash, source.path);
    updateField(hash, source.identity.device);
    updateField(hash, source.identity.inode);
    updateDigest(hash, source.sha256);
  }
  for (const edge of edges) {
    charge();
    hash.update(Buffer.from([2]));
    updateField(hash, edge.tag);
    updateField(hash, edge.source);
    updateField(hash, edge.target);
    updateField(hash, String(edge.order));
  }
  for (const resource of resources) {
    charge();
    indexResource(resource);
    hash.update(Buffer.from([3]));
    updateField(hash, resource.resourceType);
    updateField(hash, resource.resourceId);
    updateField(hash, resource.provenance);
  }
  return hash.digest("hex");
}

function updateField(hash: Hash, value: string): void {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  try {
    length.writeUInt32BE(bytes.byteLength);
    hash.update(length);
    hash.update(bytes);
  } finally {
    length.fill(0);
    bytes.fill(0);
  }
}

function updateDigest(hash: Hash, value: string): void {
  const bytes = Buffer.from(value, "hex");
  try {
    if (bytes.byteLength !== 32) throw unhealthy("Digest is invalid");
    hash.update(bytes);
  } finally {
    bytes.fill(0);
  }
}

function resourceKey(
  resourceType: ConfigResourceType,
  resourceId: string,
): string {
  return resourceType + "\0" + resourceId;
}
function resourceTypeDigest(resourceType: ConfigResourceType): string {
  const bytes = Buffer.from(`HA_RESOURCE_TYPE_V1\0${resourceType}`, "utf8");
  try {
    return digest(bytes);
  } finally {
    bytes.fill(0);
  }
}

function publicSummary(resource: ResourceRecord): RepositoryResourceSummary {
  return Object.freeze({
    resourceType: resource.resourceType,
    resourceId: resource.resourceId,
    path: resource.path,
    sha256: resource.sha256,
  });
}

function leaf(
  projected: Exclude<ProjectedYamlNode, { kind: "map" | "sequence" }>,
  sourcePath: string,
): ResolvedNode {
  return Object.freeze({ kind: "leaf", projected, sourcePath });
}

function map(
  entries: readonly ResolvedEntry[],
  sourcePath: string,
): ResolvedNode {
  return Object.freeze({
    kind: "map",
    entries: Object.freeze([...entries]),
    sourcePath,
    projected: Object.freeze({
      kind: "map",
      entries: Object.freeze([]),
      anchored: false,
    }),
  });
}

function sequence(
  items: readonly ResolvedNode[],
  sourcePath: string,
): ResolvedNode {
  return Object.freeze({
    kind: "sequence",
    items: Object.freeze([...items]),
    sourcePath,
    projected: Object.freeze({
      kind: "sequence",
      items: Object.freeze([]),
      anchored: false,
    }),
  });
}

function assertResourceType(
  value: string,
): asserts value is ConfigResourceType {
  if (!configResourceTypeSchema.safeParse(value).success)
    throw boundary("invalid_input", "Resource type is invalid");
}

function assertResourceLimit(limit: number): void {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500)
    throw boundary("invalid_input", "Resource page limit is invalid");
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function boundary(
  code: ConstructorParameters<typeof RepositoryBoundaryError>[0],
  message: string,
): RepositoryBoundaryError {
  return new RepositoryBoundaryError(code, message);
}

function unhealthy(message: string): RepositoryBoundaryError {
  return boundary("service_unhealthy", message);
}
