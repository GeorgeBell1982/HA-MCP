import { createHash, randomUUID } from "node:crypto";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import type {
  CatalogFile,
  RepositoryCatalog,
  RepositoryCatalogProvider,
} from "../repository/repositoryReads.js";
import {
  RepositoryBoundaryError,
  type FileIdentity,
  type SecureFileRead,
} from "../security/repositoryBoundary.js";
import type {
  Phase3OperationContext,
  Phase3SourcePort,
} from "./applyCoordinator.js";
import { canonicalPhase3Path } from "./resourceLocks.js";

export interface Phase3SourceBoundary {
  assertFresh(context: Phase2OperationContext): Promise<void>;
  isProtected(path: string, identity: FileIdentity): boolean;
  readContent(
    path: string,
    context: Phase2OperationContext,
  ): Promise<SecureFileRead>;
}

export class ProtectedPhase3SourceAdapter implements Phase3SourcePort {
  constructor(
    private readonly catalogs: RepositoryCatalogProvider,
    private readonly boundary: Phase3SourceBoundary,
  ) {}

  async read(
    path: string,
    context: Phase3OperationContext,
  ): Promise<Readonly<{ bytes: Uint8Array; sha256: string }>> {
    const canonical = canonicalSourcePath(path);
    return await this.withSanitizedErrors(async () => {
      const source = await this.readSource(canonical, phase2Context(context));
      if (source === null)
        throw new RepositoryBoundaryError(
          "resource_not_found",
          "Repository source resource was not found",
        );
      return source;
    });
  }

  async readDigest(path: string): Promise<string | null> {
    const canonical = canonicalSourcePath(path);
    return await this.withSanitizedErrors(async () => {
      const source = await this.readSource(
        canonical,
        internalPhase2Context(),
        false,
      );
      return source?.sha256 ?? null;
    });
  }

  private async readSource(
    path: string,
    context: Phase2OperationContext,
    includeBytes = true,
  ): Promise<Readonly<{ bytes: Uint8Array; sha256: string }> | null> {
    await this.boundary.assertFresh(context);
    const catalog = await this.catalogs.catalog(context);
    const entry = exactEntry(catalog, path);
    if (!entry) return null;
    if (this.boundary.isProtected(entry.path, entry.identity))
      throw new RepositoryBoundaryError(
        "protected_resource",
        "Repository source resource is protected",
      );
    let read: SecureFileRead | undefined;
    try {
      read = await this.readAcceptedContent(path, context);
      validateRead(catalog, entry, read);
      const sha256 = digest(read.bytes);
      await this.boundary.assertFresh(context);
      return Object.freeze({
        bytes: includeBytes ? Uint8Array.from(read.bytes) : new Uint8Array(0),
        sha256,
      });
    } finally {
      read?.bytes.fill(0);
    }
  }

  private async readAcceptedContent(
    path: string,
    context: Phase2OperationContext,
  ): Promise<SecureFileRead> {
    try {
      return await this.boundary.readContent(path, context);
    } catch (error) {
      if (
        error instanceof RepositoryBoundaryError &&
        (error.code === "resource_not_found" ||
          error.code === "protected_resource")
      )
        throw unhealthy();
      throw error;
    }
  }

  private async withSanitizedErrors<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof RepositoryBoundaryError)
        throw new RepositoryBoundaryError(
          error.code,
          safeBoundaryMessage(error.code),
        );
      throw unhealthy();
    }
  }
}

function canonicalSourcePath(path: string): string {
  try {
    return canonicalPhase3Path(path);
  } catch {
    throw new RepositoryBoundaryError(
      "invalid_input",
      "Repository source path is invalid",
    );
  }
}

function phase2Context(
  context: Phase3OperationContext,
): Phase2OperationContext {
  return Object.freeze({
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt: context.deadlineAt,
    signal: context.signal,
  });
}

function internalPhase2Context(): Phase2OperationContext {
  return Object.freeze({
    requestId: randomUUID(),
    operationId: randomUUID(),
    deadlineAt: Date.now() + 60_000,
    signal: new AbortController().signal,
  });
}

function exactEntry(
  catalog: RepositoryCatalog,
  path: string,
): CatalogFile | undefined {
  return catalog.files.find((file) => file.path === path);
}

function validateRead(
  catalog: RepositoryCatalog,
  entry: CatalogFile,
  read: SecureFileRead,
): void {
  if (
    catalog.rootIdentity.device !== read.rootIdentity.device ||
    catalog.rootIdentity.inode !== read.rootIdentity.inode ||
    entry.identity.device !== read.identity.device ||
    entry.identity.inode !== read.identity.inode ||
    read.bytes.byteLength !== entry.size ||
    read.bytes.byteLength > PHASE2_MAX_TEXT_BYTES
  )
    throw unhealthy();
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function unhealthy(): RepositoryBoundaryError {
  return new RepositoryBoundaryError(
    "service_unhealthy",
    "Repository source boundary failed safely",
  );
}

function safeBoundaryMessage(code: RepositoryBoundaryError["code"]): string {
  switch (code) {
    case "capability_unavailable":
      return "Repository source capability is unavailable";
    case "deadline_exceeded":
      return "Repository source deadline expired";
    case "operation_cancelled":
      return "Repository source operation was cancelled";
    case "resource_not_found":
      return "Repository source resource was not found";
    case "protected_resource":
      return "Repository source resource is protected";
    case "file_too_large":
      return "Repository source resource exceeded its byte boundary";
    case "unsupported_encoding":
      return "Repository source encoding is unsupported";
    case "invalid_input":
      return "Repository source input is invalid";
    case "stale_source":
      return "Repository source is stale";
    case "path_denied":
      return "Repository source path is denied";
    case "service_unhealthy":
      return "Repository source boundary failed safely";
  }
}
