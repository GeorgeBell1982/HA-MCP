import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  phase2SourceEvidence,
  phase2ToolInputSchemas,
  phase2ToolNames,
  phase2ToolOutputSchemas,
  type Phase2OperationContext,
  type Phase2ToolName,
} from "../src/phase2Contracts.js";
import { Phase2Tools, type Phase2ToolsServices } from "../src/phase2Tools.js";
import { ProposalServiceError } from "../src/proposals/proposalService.js";
import { RepositoryBoundaryError } from "../src/security/repositoryBoundary.js";
import type { ToolResult } from "../src/toolRegistry.js";
import { YamlGateError } from "../src/yaml/strictYamlGate.js";

const now = Date.parse("2026-07-20T08:00:00.000Z");
const observedAt = new Date(now).toISOString();
const cursor = Buffer.alloc(102).toString("base64url");
const sha = "a".repeat(64);
const proposalId = "4c43818c-ddfe-47ea-ad13-35fe796b13ce";
const idempotencyKey = "1c43818c-ddfe-47ea-ad13-35fe796b13ce";
const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");

type SuccessToolResult = ToolResult & {
  readonly ok: true;
  readonly evidence: readonly {
    readonly source: string;
    readonly observedAt: string;
  }[];
};

function uuidFactory() {
  let index = 0;
  return () => {
    index += 1;
    return `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  };
}

const proposal = Object.freeze({
  proposalId,
  idempotencyKey,
  state: "pending" as const,
  path: "automations.yaml",
  expectedSha256: sha,
  candidateSha256: digest("candidate"),
  diffSha256: digest("diff"),
  redactedDiff: "@@ -1 +1 @@\n",
  createdAt: "2026-07-20T08:00:00.000Z",
  expiresAt: "2026-07-21T08:00:00.000Z",
  risk: "high" as const,
  validationPlan: ["Validate Home Assistant configuration"],
  reloadImpact: "restart_required" as const,
  sourceEvidence: phase2SourceEvidence.proposalStore,
});

function services(
  overrides: Partial<Phase2ToolsServices> = {},
): Phase2ToolsServices {
  return {
    repositoryReadService: {
      list: vi.fn(async () => ({
        items: [{ path: "configuration.yaml", sha256: sha, bytes: 42 }],
        nextCursor: cursor,
        snapshotSha256: "snapshot",
      })),
      read: vi.fn(async () => ({
        path: "configuration.yaml",
        sha256: sha,
        bytes: 42,
        content: "default_config:\n",
      })),
      search: vi.fn(async () => ({
        items: [
          {
            path: "configuration.yaml",
            line: 1,
            snippet: "default_config:",
          },
        ],
        nextCursor: null,
        snapshotSha256: "snapshot",
      })),
    },
    repositoryResourceService: {
      list: vi.fn(async () => ({
        items: [
          {
            resourceType: "automation" as const,
            resourceId: "automation.morning",
            path: "automations.yaml",
            sha256: sha,
          },
        ],
        nextCursor: null,
        snapshotSha256: "snapshot",
      })),
      get: vi.fn(async () => ({
        resourceType: "automation" as const,
        resourceId: "automation.morning",
        path: "automations.yaml",
        sha256: sha,
        content: "- id: morning\n",
      })),
    },
    gitReadService: {
      status: vi.fn(async () => ({
        branch: "main",
        unborn: false,
        entries: [{ path: "configuration.yaml", index: "M", worktree: " " }],
      })),
      diff: vi.fn(async () => ({
        patch: "@@ redacted @@\n",
        diffSha256: digest("@@ redacted @@\n"),
        truncated: false,
        warnings: ["Unsupported repository changes were omitted"],
        snapshotSha256: "snapshot",
      })),
    },
    proposalService: {
      list: vi.fn(async () => ({ items: [proposal], nextCursor: null })),
      get: vi.fn(async () => proposal),
      propose: vi.fn(async () => proposal),
      discard: vi.fn(async () => ({
        ...proposal,
        state: "discarded" as const,
      })),
    },
    ...overrides,
  };
}

function tools(phase2Services = services()) {
  return new Phase2Tools(phase2Services, {
    clock: { now: () => now },
    timeoutMs: 1_000,
    createUuid: uuidFactory(),
  });
}

describe("Phase2Tools", () => {
  it("exposes the exact Phase 2 inventory and descriptors", () => {
    const registry = tools();
    expect(registry.names()).toEqual(phase2ToolNames);
    expect(registry.descriptors().map((descriptor) => descriptor.name)).toEqual(
      phase2ToolNames,
    );
    for (const name of phase2ToolNames) {
      const descriptor = registry.descriptor(name);
      expect(descriptor?.inputSchema).toBe(phase2ToolInputSchemas[name]);
      expect(descriptor?.outputSchema).toBe(phase2ToolOutputSchemas[name]);
      if (
        name === "ha_propose_config_change" ||
        name === "ha_discard_proposed_change"
      )
        expect(descriptor?.description).toMatch(/^Proposal-only\./u);
      else expect(descriptor?.description).toMatch(/^Read-only\./u);
    }
    expect(registry.descriptor("ha_nope")).toBeUndefined();
  });

  it("dispatches every tool to its service and returns schema-valid output envelopes", async () => {
    const phase2Services = services();
    const registry = tools(phase2Services);
    const validInputs = {
      ha_list_config_files: {},
      ha_read_config_file: { path: "configuration.yaml" },
      ha_search_config: { query: "default" },
      ha_list_config_resources: { resourceType: "automation" },
      ha_get_config_resource: {
        resourceType: "automation" as const,
        resourceId: "automation.morning",
      },
      ha_get_git_status: {},
      ha_get_git_diff: { paths: ["configuration.yaml"] },
      ha_list_proposals: {},
      ha_get_pending_diff: { proposalId },
      ha_propose_config_change: {
        idempotencyKey,
        path: "automations.yaml",
        expectedSha256: sha,
        proposedContent: "- id: morning\n",
      },
      ha_discard_proposed_change: { proposalId },
    } satisfies Record<Phase2ToolName, unknown>;

    const outputs = new Map<Phase2ToolName, ToolResult>();
    for (const name of phase2ToolNames) {
      const output = await registry.call(name, validInputs[name]);
      outputs.set(name, output);
      expect(phase2ToolOutputSchemas[name].safeParse(output).success).toBe(
        true,
      );
      expect(output.ok).toBe(true);
      if (output.ok) {
        const success = output as SuccessToolResult;
        expect(success.evidence).toEqual([
          {
            source:
              name.startsWith("ha_get_git") || name === "ha_get_git_status"
                ? phase2SourceEvidence.gitRepository
                : name.includes("proposal") ||
                    name === "ha_get_pending_diff" ||
                    name === "ha_propose_config_change" ||
                    name === "ha_discard_proposed_change"
                  ? phase2SourceEvidence.proposalStore
                  : phase2SourceEvidence.configRepository,
            observedAt,
          },
        ]);
      }
    }

    expect(phase2Services.repositoryReadService.list).toHaveBeenCalledWith(
      { limit: 100 },
      expect.objectContaining({ deadlineAt: now + 1_000 }),
    );
    expect(phase2Services.repositoryReadService.read).toHaveBeenCalledWith(
      "configuration.yaml",
      expect.any(Object),
    );
    expect(phase2Services.repositoryReadService.search).toHaveBeenCalledWith(
      { query: "default", limit: 100 },
      expect.any(Object),
    );
    expect(phase2Services.repositoryResourceService.list).toHaveBeenCalledWith(
      { resourceType: "automation", limit: 100 },
      expect.any(Object),
    );
    expect(phase2Services.repositoryResourceService.get).toHaveBeenCalledWith(
      "automation",
      "automation.morning",
      expect.any(Object),
    );
    expect(phase2Services.gitReadService.status).toHaveBeenCalledWith(
      expect.any(Object),
    );
    expect(phase2Services.gitReadService.diff).toHaveBeenCalledWith(
      { scope: "both", paths: ["configuration.yaml"] },
      expect.any(Object),
    );
    expect(phase2Services.proposalService.list).toHaveBeenCalledWith(
      { limit: 100 },
      expect.any(Object),
    );
    expect(phase2Services.proposalService.get).toHaveBeenCalledWith(
      { proposalId },
      expect.any(Object),
    );
    expect(phase2Services.proposalService.propose).toHaveBeenCalledWith(
      validInputs.ha_propose_config_change,
      expect.any(Object),
    );
    expect(phase2Services.proposalService.discard).toHaveBeenCalledWith(
      { proposalId },
      expect.any(Object),
    );

    expect(outputs.get("ha_get_git_status")).toMatchObject({
      ok: true,
      data: {
        clean: false,
        branch: "main",
        changes: [{ path: "configuration.yaml", index: "M", worktree: " " }],
        sourceEvidence: phase2SourceEvidence.gitRepository,
      },
    });
    expect(outputs.get("ha_get_git_diff")).toMatchObject({
      ok: true,
      warnings: ["Unsupported repository changes were omitted"],
      data: {
        redactedDiff: "@@ redacted @@\n",
        sourceEvidence: phase2SourceEvidence.gitRepository,
      },
    });
    expect(outputs.get("ha_get_config_resource")).toMatchObject({
      ok: true,
      data: {
        redactedContent: "- id: morning\n",
        sourceEvidence: phase2SourceEvidence.configRepository,
      },
    });
  });

  it("rejects strict invalid input without dispatching", async () => {
    const phase2Services = services();
    const output = await tools(phase2Services).call("ha_read_config_file", {
      path: "configuration.yaml",
      extra: true,
    });
    expect(output).toMatchObject({
      ok: false,
      error: {
        code: "invalid_input",
        message: "Tool input failed schema validation",
      },
      warnings: [],
      evidence: [],
    });
    expect(phase2Services.repositoryReadService.read).not.toHaveBeenCalled();
    expect(JSON.stringify(output)).not.toContain("extra");
  });

  it("sanitizes known and unknown errors to fixed Phase 2 failure envelopes", async () => {
    const cases = [
      {
        error: new RepositoryBoundaryError(
          "capability_unavailable",
          "secret repository path",
        ),
        code: "repository_unavailable",
        message: "Repository is unavailable",
      },
      {
        error: new ProposalServiceError(
          "proposal_conflict",
          "idempotency secret",
        ),
        code: "proposal_conflict",
        message: "Proposal conflict",
      },
      {
        error: new YamlGateError("file_too_large"),
        code: "file_too_large",
        message: "Content exceeds Phase 2 size limits",
      },
      {
        error: new Error("password=secret"),
        code: "service_unhealthy",
        message: "Service is temporarily unhealthy",
      },
    ] as const;

    for (const item of cases) {
      const phase2Services = services({
        repositoryReadService: {
          ...services().repositoryReadService,
          read: vi.fn(async () => {
            throw item.error;
          }),
        },
      });
      const output = await tools(phase2Services).call("ha_read_config_file", {
        path: "configuration.yaml",
      });
      expect(output).toMatchObject({
        ok: false,
        error: { code: item.code, message: item.message },
        warnings: [],
        evidence: [],
      });
      expect(JSON.stringify(output)).not.toContain("secret");
      expect(JSON.stringify(output)).not.toContain("password");
    }
  });

  it("returns a fixed service_unhealthy envelope when output shaping fails", async () => {
    const phase2Services = services({
      repositoryReadService: {
        ...services().repositoryReadService,
        read: vi.fn(async () => ({
          path: "configuration.yaml",
          sha256: "not-a-sha",
          bytes: 1,
          content: "x",
        })),
      },
    });
    const output = await tools(phase2Services).call("ha_read_config_file", {
      path: "configuration.yaml",
    });
    expect(output).toMatchObject({
      ok: false,
      error: {
        code: "service_unhealthy",
        message: "Service is temporarily unhealthy",
      },
      warnings: [],
      evidence: [],
    });
  });

  it("combines caller cancellation with the operation signal", async () => {
    const phase2Services = services({
      repositoryReadService: {
        ...services().repositoryReadService,
        read: vi.fn(
          (_path: string, context: Phase2OperationContext) =>
            new Promise<{
              readonly path: string;
              readonly sha256: string;
              readonly bytes: number;
              readonly content: string;
            }>((resolve) => {
              context.signal.addEventListener(
                "abort",
                () =>
                  resolve({
                    path: "configuration.yaml",
                    sha256: sha,
                    bytes: 42,
                    content: "default_config:\n",
                  }),
                { once: true },
              );
            }),
        ),
      },
    });
    const controller = new AbortController();
    const pending = tools(phase2Services).call(
      "ha_read_config_file",
      { path: "configuration.yaml" },
      { signal: controller.signal },
    );
    controller.abort();
    const output = await pending;
    expect(output).toMatchObject({
      ok: false,
      error: {
        code: "operation_cancelled",
        message: "Operation was cancelled",
      },
    });
  });

  it("returns deadline_exceeded when the bounded timeout fires", async () => {
    let timeout: (() => void) | undefined;
    const clock = {
      now: () => now,
      setTimeout: vi.fn((callback: () => void) => {
        timeout = callback;
        return setTimeout(() => undefined, 10_000);
      }),
      clearTimeout: vi.fn((timer: ReturnType<typeof setTimeout>) =>
        clearTimeout(timer),
      ),
    };
    const phase2Services = services({
      repositoryReadService: {
        ...services().repositoryReadService,
        read: vi.fn(() => new Promise<never>(() => undefined)),
      },
    });
    const pending = new Phase2Tools(phase2Services, {
      clock,
      timeoutMs: 50,
      createUuid: uuidFactory(),
    }).call("ha_read_config_file", { path: "configuration.yaml" });
    await Promise.resolve();
    timeout?.();
    const output = await pending;
    expect(output).toMatchObject({
      ok: false,
      error: {
        code: "deadline_exceeded",
        message: "Operation deadline expired",
      },
    });
    expect(clock.clearTimeout).toHaveBeenCalled();
  });
});
