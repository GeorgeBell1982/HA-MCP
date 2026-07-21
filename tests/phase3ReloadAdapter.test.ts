import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { Phase3OperationContext } from "../src/phase3/applyCoordinator.js";
import {
  NarrowPhase3ReloadAdapter,
  Phase3ReloadError,
  phase3ReloadDispatchOutcomes,
  phase3ReloadErrorCodes,
  phase3ReloadResolutionStatuses,
  phase3ReloadStages,
  phase3ReloadTargets,
  type Phase3ReloadCatalogPort,
  type Phase3ReloadDispatchOutcome,
  type Phase3ReloadResolution,
  type Phase3ReloadServicePort,
  type Phase3ReloadTarget,
} from "../src/phase3/reloadAdapter.js";

const activeContext = (): Phase3OperationContext => ({
  signal: new AbortController().signal,
  deadlineAt: Date.now() + 60_000,
});
const resolved = (target: Phase3ReloadTarget): Phase3ReloadResolution =>
  Object.freeze({ status: "resolved", target });
const outcome = (status: Phase3ReloadDispatchOutcome) =>
  Object.freeze({ status });

function adapter(
  resolution: Phase3ReloadResolution,
  dispatch: Phase3ReloadDispatchOutcome = "completed",
  calls: string[] = [],
): NarrowPhase3ReloadAdapter {
  return new NarrowPhase3ReloadAdapter(
    {
      async resolve(path, context) {
        calls.push(
          `resolve:${path}:${Object.isFrozen(resolution)}:${context.deadlineAt}`,
        );
        return resolution;
      },
    },
    {
      async reload(target, context) {
        calls.push(`reload:${target}:${context.deadlineAt}`);
        return outcome(dispatch);
      },
    },
  );
}

describe("Phase 3H narrow reload adapter", () => {
  it("exports immutable closed contracts", () => {
    expect(phase3ReloadTargets).toEqual([
      "automation.reload",
      "script.reload",
      "scene.reload",
    ]);
    expect(phase3ReloadResolutionStatuses).toEqual([
      "resolved",
      "unavailable",
      "ambiguous",
      "unhealthy",
    ]);
    expect(phase3ReloadDispatchOutcomes).toEqual([
      "completed",
      "not_dispatched",
      "outcome_unknown",
    ]);
    expect(phase3ReloadStages).toEqual(["input", "resolution", "dispatch"]);
    expect(phase3ReloadErrorCodes).toHaveLength(9);
    for (const value of [
      phase3ReloadTargets,
      phase3ReloadResolutionStatuses,
      phase3ReloadDispatchOutcomes,
      phase3ReloadStages,
      phase3ReloadErrorCodes,
    ])
      expect(Object.isFrozen(value)).toBe(true);
    expect(() =>
      (phase3ReloadTargets as unknown as string[]).push("homeassistant.reload"),
    ).toThrow();
  });

  it.each(
    phase3ReloadTargets.flatMap((target) =>
      phase3ReloadDispatchOutcomes.map((dispatch) => ({ target, dispatch })),
    ),
  )(
    "classifies $target x $dispatch without retry",
    async ({ target, dispatch }) => {
      const calls: string[] = [];
      const context = activeContext();
      const run = adapter(resolved(target), dispatch, calls).reloadDomain(
        "packages/mixed-name.yaml",
        context,
      );
      if (dispatch === "completed") await expect(run).resolves.toBeUndefined();
      else {
        const expected =
          dispatch === "not_dispatched"
            ? "reload_not_dispatched"
            : "reload_outcome_unknown";
        await expect(run).rejects.toMatchObject({
          code: expected,
          stage: "dispatch",
          resolution: "resolved",
          dispatch,
          target,
        });
      }
      expect(calls.filter((call) => call.startsWith("resolve:"))).toHaveLength(
        1,
      );
      expect(calls.filter((call) => call.startsWith("reload:"))).toEqual([
        `reload:${target}:${context.deadlineAt}`,
      ]);
    },
  );

  it.each([
    ["unavailable", "reload_unavailable"],
    ["ambiguous", "reload_ambiguous"],
    ["unhealthy", "reload_catalog_unhealthy"],
  ] as const)("fails closed for %s resolution", async (status, code) => {
    let dispatched = false;
    const run = new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          return Object.freeze({ status });
        },
      },
      {
        async reload() {
          dispatched = true;
          return outcome("completed");
        },
      },
    ).reloadDomain("not-a-domain-name.yaml", activeContext());
    await expect(run).rejects.toMatchObject({
      code,
      stage: "resolution",
      resolution: status,
      dispatch: "not_attempted",
    });
    expect(dispatched).toBe(false);
  });

  it("uses only the catalog result and passes the exact context", async () => {
    const context = activeContext();
    let catalogContext: Phase3OperationContext | undefined;
    let serviceContext: Phase3OperationContext | undefined;
    let observedPath = "";
    await new NarrowPhase3ReloadAdapter(
      {
        async resolve(path, received) {
          observedPath = path;
          catalogContext = received;
          return resolved("scene.reload");
        },
      },
      {
        async reload(_target, received) {
          serviceContext = received;
          return outcome("completed");
        },
      },
    ).reloadDomain("automations/deceptive-name.yaml", context);
    expect(observedPath).toBe("automations/deceptive-name.yaml");
    expect(catalogContext).toBe(context);
    expect(serviceContext).toBe(context);
  });

  it.each([
    "",
    "../configuration.yaml",
    "/configuration.yaml",
    "a\\b.yaml",
    "a/../b.yaml",
  ])("rejects invalid path %j before catalog effects", async (path) => {
    let resolvedCount = 0;
    const run = new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          resolvedCount += 1;
          return resolved("automation.reload");
        },
      },
      {
        async reload() {
          return outcome("completed");
        },
      },
    ).reloadDomain(path, activeContext());
    await expect(run).rejects.toMatchObject({
      code: "invalid_path",
      stage: "input",
    });
    expect(resolvedCount).toBe(0);
  });

  it.each(["cancelled", "expired", "nonfinite"] as const)(
    "rejects %s context before catalog effects",
    async (kind) => {
      const controller = new AbortController();
      if (kind === "cancelled") controller.abort();
      const context = {
        signal: controller.signal,
        deadlineAt:
          kind === "expired"
            ? Date.now() - 1
            : kind === "nonfinite"
              ? Number.NaN
              : Date.now() + 60_000,
      };
      let resolvedCount = 0;
      const run = new NarrowPhase3ReloadAdapter(
        {
          async resolve() {
            resolvedCount += 1;
            return resolved("automation.reload");
          },
        },
        {
          async reload() {
            return outcome("completed");
          },
        },
      ).reloadDomain("configuration.yaml", context);
      await expect(run).rejects.toMatchObject({
        code:
          kind === "cancelled" ? "operation_cancelled" : "deadline_exceeded",
        stage: "input",
      });
      expect(resolvedCount).toBe(0);
    },
  );

  it("rechecks cancellation after catalog resolution", async () => {
    const controller = new AbortController();
    const context = {
      signal: controller.signal,
      deadlineAt: Date.now() + 60_000,
    };
    let dispatched = false;
    const run = new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          controller.abort();
          return resolved("script.reload");
        },
      },
      {
        async reload() {
          dispatched = true;
          return outcome("completed");
        },
      },
    ).reloadDomain("arbitrary/location.yaml", context);
    await expect(run).rejects.toMatchObject({
      code: "operation_cancelled",
      stage: "dispatch",
      resolution: "resolved",
      target: "script.reload",
    });
    expect(dispatched).toBe(false);
  });

  it("rechecks the deadline after catalog resolution", async () => {
    const clock = vi.spyOn(Date, "now");
    clock.mockReturnValueOnce(10).mockReturnValue(100);
    let dispatched = false;
    try {
      const run = new NarrowPhase3ReloadAdapter(
        {
          async resolve() {
            return resolved("scene.reload");
          },
        },
        {
          async reload() {
            dispatched = true;
            return outcome("completed");
          },
        },
      ).reloadDomain("x.yaml", {
        signal: new AbortController().signal,
        deadlineAt: 50,
      });
      await expect(run).rejects.toMatchObject({
        code: "deadline_exceeded",
        stage: "dispatch",
      });
      expect(dispatched).toBe(false);
    } finally {
      clock.mockRestore();
    }
  });

  it.each([
    { status: "resolved", target: "automation.reload" },
    Object.freeze({
      status: "resolved",
      target: "automation.reload",
      extra: true,
    }),
    Object.freeze({ status: "resolved", target: "homeassistant.reload" }),
    Object.freeze({ status: "unavailable", extra: true }),
    Object.freeze({ status: "stale" }),
  ])("rejects malformed catalog result %# before dispatch", async (bad) => {
    let dispatched = false;
    const catalog: Phase3ReloadCatalogPort = {
      async resolve() {
        return bad as unknown as Phase3ReloadResolution;
      },
    };
    const run = new NarrowPhase3ReloadAdapter(catalog, {
      async reload() {
        dispatched = true;
        return outcome("completed");
      },
    }).reloadDomain("x.yaml", activeContext());
    await expect(run).rejects.toMatchObject({
      code: "internal_failure",
      stage: "resolution",
    });
    expect(dispatched).toBe(false);
  });

  it.each([
    { status: "completed" },
    Object.freeze({ status: "completed", extra: true }),
    Object.freeze({ status: "unknown" }),
  ])("treats malformed dispatch result %# as outcome unknown", async (bad) => {
    const service: Phase3ReloadServicePort = {
      async reload() {
        return bad as unknown as ReturnType<typeof outcome>;
      },
    };
    await expect(
      new NarrowPhase3ReloadAdapter(
        {
          async resolve() {
            return resolved("automation.reload");
          },
        },
        service,
      ).reloadDomain("x.yaml", activeContext()),
    ).rejects.toMatchObject({
      code: "reload_outcome_unknown",
      stage: "dispatch",
      dispatch: "outcome_unknown",
    });
  });

  it("sanitizes resolver and dispatch exceptions without retry", async () => {
    const canary = "SECRET_TOKEN_AND_PATH";
    const resolverError = await new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          throw new Error(canary);
        },
      },
      {
        async reload() {
          return outcome("completed");
        },
      },
    )
      .reloadDomain("private/path.yaml", activeContext())
      .catch((error: unknown) => error);
    expect(resolverError).toBeInstanceOf(Phase3ReloadError);
    expect(String(resolverError)).not.toContain(canary);
    expect(String(resolverError)).not.toContain("private/path.yaml");
    expect(resolverError).toMatchObject({
      code: "internal_failure",
      stage: "resolution",
    });

    let dispatches = 0;
    const dispatchError = await new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          return resolved("script.reload");
        },
      },
      {
        async reload() {
          dispatches += 1;
          throw new Error(canary);
        },
      },
    )
      .reloadDomain("private/path.yaml", activeContext())
      .catch((error: unknown) => error);
    expect(dispatchError).toMatchObject({
      code: "reload_outcome_unknown",
      dispatch: "outcome_unknown",
    });
    expect(String(dispatchError)).not.toContain(canary);
    expect(String(dispatchError)).not.toContain("private/path.yaml");
    expect(dispatches).toBe(1);
  });

  it("never rereads a validated foreign catalog object", async () => {
    const foreign = new Proxy(
      Object.freeze({
        status: "resolved" as const,
        target: "automation.reload" as const,
      }),
      {
        get(target, key, receiver) {
          if (key === "status" || key === "target")
            throw new Error("SECRET_RESOLUTION_PROXY");
          return undefined;
        },
      },
    );
    let dispatched = false;
    await expect(
      new NarrowPhase3ReloadAdapter(
        {
          async resolve() {
            return foreign;
          },
        },
        {
          async reload() {
            dispatched = true;
            return outcome("completed");
          },
        },
      ).reloadDomain("x.yaml", activeContext()),
    ).resolves.toBeUndefined();
    expect(dispatched).toBe(true);
  });

  it("never rereads a validated foreign dispatch object", async () => {
    const foreign = new Proxy(Object.freeze({ status: "completed" as const }), {
      get(target, key, receiver) {
        if (key === "status") throw new Error("SECRET_DISPATCH_PROXY");
        return undefined;
      },
    });
    await expect(
      new NarrowPhase3ReloadAdapter(
        {
          async resolve() {
            return resolved("scene.reload");
          },
        },
        {
          async reload() {
            return foreign;
          },
        },
      ).reloadDomain("x.yaml", activeContext()),
    ).resolves.toBeUndefined();
  });
  it("sanitizes a hostile catalog proxy during descriptor parsing", async () => {
    const foreign = new Proxy(
      Object.freeze({
        status: "resolved" as const,
        target: "automation.reload" as const,
      }),
      {
        getOwnPropertyDescriptor() {
          throw new Error("SECRET_RESOLUTION_DESCRIPTOR_PROXY");
        },
      },
    );
    let dispatched = false;
    const error = await new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          return foreign;
        },
      },
      {
        async reload() {
          dispatched = true;
          return outcome("completed");
        },
      },
    )
      .reloadDomain("x.yaml", activeContext())
      .catch((failure: unknown) => failure);
    expect(error).toMatchObject({
      code: "internal_failure",
      stage: "resolution",
    });
    expect(String(error)).not.toContain("SECRET_RESOLUTION_DESCRIPTOR_PROXY");
    expect(dispatched).toBe(false);
  });

  it("sanitizes a hostile dispatch proxy during descriptor parsing", async () => {
    const foreign = new Proxy(Object.freeze({ status: "completed" as const }), {
      getOwnPropertyDescriptor() {
        throw new Error("SECRET_DISPATCH_DESCRIPTOR_PROXY");
      },
    });
    const error = await new NarrowPhase3ReloadAdapter(
      {
        async resolve() {
          return resolved("script.reload");
        },
      },
      {
        async reload() {
          return foreign;
        },
      },
    )
      .reloadDomain("x.yaml", activeContext())
      .catch((failure: unknown) => failure);
    expect(error).toMatchObject({
      code: "reload_outcome_unknown",
      stage: "dispatch",
      dispatch: "outcome_unknown",
    });
    expect(String(error)).not.toContain("SECRET_DISPATCH_DESCRIPTOR_PROXY");
  });
  it("has no dependency on generic HA clients or broad operations", () => {
    const source = readFileSync("src/phase3/reloadAdapter.ts", "utf8");
    for (const forbidden of [
      "../ha/rest",
      "../ha/websocket",
      "call_service",
      "homeassistant.reload",
      "homeassistant.restart",
      "restart",
    ])
      expect(source).not.toContain(forbidden);
  });
});
