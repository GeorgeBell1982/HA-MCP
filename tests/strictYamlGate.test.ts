import { createHash } from "node:crypto";
import { setImmediate as scheduleImmediate } from "node:timers";
import { describe, expect, it, vi } from "vitest";
import {
  PHASE2_MAX_TEXT_BYTES,
  type Phase2OperationContext,
} from "../src/phase2Contracts.js";
import {
  YamlGateError,
  validateAndProjectYaml,
  validateStrictYaml,
  yamlGateErrorCodes,
} from "../src/yaml/strictYamlGate.js";

const context = (
  signal: AbortSignal = new AbortController().signal,
  deadlineAt = Date.now() + 30_000,
): Phase2OperationContext => ({
  requestId: "2c43818c-ddfe-47ea-ad13-35fe796b13ce",
  operationId: "3c43818c-ddfe-47ea-ad13-35fe796b13ce",
  deadlineAt,
  signal,
});

const bytes = (value: string) => Buffer.from(value, "utf8");
const digest = (value: Uint8Array) =>
  createHash("sha256").update(value).digest("hex");

async function expectGateError(
  input: Uint8Array,
  code: string | readonly string[],
  operation = context(),
): Promise<YamlGateError> {
  try {
    await validateStrictYaml(input, operation);
    throw new Error("expected YAML gate rejection");
  } catch (error) {
    expect(error).toBeInstanceOf(YamlGateError);
    const gateError = error as YamlGateError;
    expect(yamlGateErrorCodes).toContain(gateError.code);
    expect(typeof code === "string" ? [code] : code).toContain(gateError.code);
    expect(gateError.message).toBe(gateError.code);
    expect(gateError.line).toBeGreaterThan(0);
    expect(gateError.column).toBeGreaterThan(0);
    expect(Object.keys(gateError).sort()).toEqual([
      "code",
      "column",
      "line",
      "name",
    ]);
    return gateError;
  }
}

describe("strict Phase 2 YAML gate", () => {
  it("projects only fixed frozen shape, identity, include, and secret-range IR after unchanged validation", async () => {
    const source = [
      "automation: !include automations.yaml",
      "blueprint:",
      "  name: Example",
      "  domain: automation",
      "token: !secret 'SECRET_NAME_CANARY'",
      "arbitrary: should_not_be_retained",
    ].join("\n");
    const projection = await validateAndProjectYaml(bytes(source), context());
    const metadata = await validateStrictYaml(bytes(source), context());
    expect(projection.metadata).toEqual(metadata);
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.root)).toBe(true);
    const serialized = JSON.stringify(projection);
    expect(serialized).toContain("automations.yaml");
    expect(serialized).toContain("Example");
    expect(serialized).not.toContain("SECRET_NAME_CANARY");
    expect(serialized).not.toContain("should_not_be_retained");
    expect(serialized).not.toMatch(/Document|contents|cstNode|srcToken/u);
    expect(serialized).toMatch(/startByte.*endByte/u);
  });
  it("accepts implicit and explicit empty streams without inventing a document", async () => {
    for (const source of ["", "  \n# comment\n", "\r\n# comment\r\n"]) {
      const result = await validateStrictYaml(bytes(source), context());
      expect(result.empty).toBe(true);
      expect(result.explicitEmpty).toBe(false);
      expect(result.documentCount).toBe(0);
    }
    for (const source of ["---\n", "--- # empty\n...\n"]) {
      const result = await validateStrictYaml(bytes(source), context());
      expect(result.empty).toBe(true);
      expect(result.explicitEmpty).toBe(true);
      expect(result.documentCount).toBe(1);
      expect(result.nodeCount).toBe(2);
    }
  });

  it("preserves caller bytes and reports their exact digest and line-ending mode", async () => {
    for (const [source, ending] of [
      ["a: 'quoted'\n# comment\nb: 2\n", "lf"],
      ["a: 'quoted'\r\n# comment\r\nb: 2\r\n", "crlf"],
      ["a: 1", "none"],
    ] as const) {
      const input = bytes(source);
      const original = Buffer.from(input);
      const result = await validateStrictYaml(input, context());
      expect(input).toEqual(original);
      expect(result.sha256).toBe(digest(original));
      expect(result.lineEndings).toBe(ending);
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen(result.references)).toBe(true);
    }
  });

  it("returns bounded references for every allowed tag and hashes secret names", async () => {
    const source = [
      "a: !include packages/a.yaml",
      "b: !include_dir_list packages/list",
      "c: !include_dir_merge_list packages/merge-list",
      "d: !include_dir_named packages/named",
      "e: !include_dir_merge_named packages/merge-named",
      "f: !secret top_secret_name",
      "g: !input user_input",
    ].join("\n");
    const result = await validateStrictYaml(bytes(source), context());
    expect(result.references.map((reference) => reference.tag)).toEqual([
      "!include",
      "!include_dir_list",
      "!include_dir_merge_list",
      "!include_dir_named",
      "!include_dir_merge_named",
      "!secret",
      "!input",
    ]);
    const secret = result.references[5];
    expect(secret).toEqual({
      tag: "!secret",
      path: [5, 1],
      valueSha256: createHash("sha256").update("top_secret_name").digest("hex"),
      byteLength: 15,
    });
    expect(JSON.stringify(result)).not.toContain("top_secret_name");
    expect(
      Buffer.byteLength(JSON.stringify(result), "utf8"),
    ).toBeLessThanOrEqual(32 * 1024);
  });

  it("accepts comments, ordering, flow collections, quotes and bounded acyclic aliases", async () => {
    const result = await validateStrictYaml(
      bytes(
        "# before\ndefaults: &defaults { enabled: true, name: '1' }\ncopy: *defaults\n",
      ),
      context(),
    );
    expect(result.aliasReferences).toBe(1);
    expect(result.expandedNodeCount).toBeGreaterThan(result.nodeCount);
  });

  it("rejects invalid encodings, forbidden bytes and inconsistent line endings", async () => {
    await expectGateError(Buffer.from([0xff]), "unsupported_encoding");
    await expectGateError(
      Buffer.from([0xef, 0xbb, 0xbf, 0x61]),
      "unsupported_encoding",
    );
    await expectGateError(Buffer.from("a:\0b", "utf8"), "unsupported_encoding");
    await expectGateError(
      bytes("a: before\ufeffafter\n"),
      "unsupported_encoding",
    );
    await expectGateError(bytes("a: 1\rb: 2"), "invalid_line_endings");
    await expectGateError(bytes("a: 1\r\nb: 2\n"), "invalid_line_endings");
  });

  it("rejects directives, multiple documents, parser errors and warnings", async () => {
    await expectGateError(
      bytes("%YAML 1.1\n---\na: yes\n"),
      "invalid_directive",
    );
    await expectGateError(
      bytes("%TAG !e! tag:example.com,2026:\n---\na: !e!thing x\n"),
      "invalid_directive",
    );
    await expectGateError(
      bytes("---\na: 1\n---\nb: 2\n"),
      "multiple_documents",
    );
    await expectGateError(bytes("a: [1, 2\n"), "yaml_syntax");
    await expectGateError(bytes("a: !unknown value\n"), [
      "yaml_syntax",
      "yaml_warning",
    ]);
  });

  it("rejects denied tags and non-scalar values for allowed tags", async () => {
    await expectGateError(bytes("a: !!binary SGVsbG8=\n"), [
      "yaml_syntax",
      "yaml_warning",
      "tag_denied",
    ]);
    await expectGateError(bytes("a: !!timestamp 2026-07-16\n"), [
      "yaml_syntax",
      "yaml_warning",
      "tag_denied",
    ]);
    await expectGateError(bytes("a: !include [one, two]\n"), [
      "yaml_syntax",
      "yaml_warning",
      "tagged_value_invalid",
    ]);
    await expectGateError(
      bytes(`a: !include ${"x".repeat(513)}\n`),
      "reference_limit_exceeded",
    );
  });

  it("enforces scalar primitive key identity and rejects merge syntax", async () => {
    await validateStrictYaml(bytes("1: numeric\n'1': string\n"), context());
    for (const source of [
      "a: 1\na: 2\n",
      "1: a\n1.0: b\n",
      "0: a\n-0: b\n",
      "true: a\nTRUE: b\n",
    ])
      await expectGateError(bytes(source), ["yaml_syntax", "duplicate_key"]);
    for (const source of [
      "? [a, b]\n: value\n",
      "!!str key: value\n",
      "&key anchored: value\n",
      ".inf: value\n",
      "<<: { a: 1 }\n",
      "base: &base { a: 1 }\nmap:\n  <<: *base\n",
    ])
      await expectGateError(bytes(source), [
        "yaml_syntax",
        "yaml_warning",
        "key_invalid",
        "merge_key_denied",
      ]);
  });

  it("rejects duplicate, unresolved and cyclic anchors", async () => {
    await expectGateError(bytes("a: &x 1\nb: &x 2\n"), "duplicate_anchor");
    await expectGateError(bytes("a: *missing\n"), [
      "yaml_syntax",
      "unresolved_alias",
    ]);
    await expectGateError(bytes("a: &loop [*loop]\n"), "alias_cycle");
  });

  it("accepts inclusive reference and depth limits and rejects N+1", async () => {
    const aliases = (count: number) =>
      `base: &base 1\nrefs: [${Array.from({ length: count }, () => "*base").join(",")}]\n`;
    expect(
      (await validateStrictYaml(bytes(aliases(100)), context()))
        .aliasReferences,
    ).toBe(100);
    await expectGateError(bytes(aliases(101)), "alias_limit_exceeded");

    const tagged = (count: number) =>
      Array.from({ length: count }, (_, index) => `r${index}: !include x`).join(
        "\n",
      );
    expect(
      (await validateStrictYaml(bytes(tagged(100)), context())).references,
    ).toHaveLength(100);
    await expectGateError(bytes(tagged(101)), "reference_limit_exceeded");

    const aggregateReferences = (count: number) =>
      Array.from(
        { length: count },
        (_, index) => `r${index}: !secret ${"x".repeat(512)}`,
      ).join("\n");
    expect(
      (await validateStrictYaml(bytes(aggregateReferences(64)), context()))
        .references,
    ).toHaveLength(64);
    await expectGateError(
      bytes(aggregateReferences(65)),
      "reference_limit_exceeded",
    );

    const returnedReferenceBytes = Array.from(
      { length: 64 },
      (_, index) => `r${index}: !include ${"x".repeat(512)}`,
    ).join("\n");
    await expectGateError(bytes(returnedReferenceBytes), "metadata_too_large");

    const nested = (collections: number) =>
      `${"[".repeat(collections)}0${"]".repeat(collections)}`;
    expect(
      (await validateStrictYaml(bytes(nested(63)), context())).maximumDepth,
    ).toBe(64);
    await expectGateError(bytes(nested(64)), "depth_limit_exceeded");
  });

  it("counts the inclusive structural node limit once and expanded aliases per reach", async () => {
    const sequence = (items: number) => `[${"0,".repeat(items - 1)}0]`;
    const accepted = await validateStrictYaml(
      bytes(sequence(99_998)),
      context(),
    );
    expect(accepted.nodeCount).toBe(100_000);
    await expectGateError(bytes(sequence(99_999)), "node_limit_exceeded");

    const bomb = `base: &base [${"0,".repeat(1_100)}0]\nrefs: [${Array.from(
      { length: 100 },
      () => "*base",
    ).join(",")}]\n`;
    await expectGateError(bytes(bomb), "node_limit_exceeded");
  }, 30_000);

  it("accepts the exact byte ceiling, rejects N+1 and counts multibyte input as bytes", async () => {
    const prefix = "value: |\n  ";
    const exact = bytes(
      prefix + "x".repeat(PHASE2_MAX_TEXT_BYTES - bytes(prefix).byteLength),
    );
    expect(exact.byteLength).toBe(PHASE2_MAX_TEXT_BYTES);
    await validateStrictYaml(exact, context());
    await expectGateError(
      Buffer.concat([exact, Buffer.from("x")]),
      "file_too_large",
    );
    const multibyte = bytes(
      `value: ${"é".repeat(PHASE2_MAX_TEXT_BYTES / 2)}\n`,
    );
    expect(multibyte.byteLength).toBeGreaterThan(PHASE2_MAX_TEXT_BYTES);
    await expectGateError(multibyte, "file_too_large");

    const multibytePrefix = "value: |\n  ";
    const remaining = PHASE2_MAX_TEXT_BYTES - bytes(multibytePrefix).byteLength;
    const exactMultibyte = bytes(
      multibytePrefix +
        "é".repeat(Math.floor(remaining / 2)) +
        (remaining % 2 ? "x" : ""),
    );
    expect(exactMultibyte.byteLength).toBe(PHASE2_MAX_TEXT_BYTES);
    await validateStrictYaml(exactMultibyte, context());

    const splitSurrogate = `value: "${"x".repeat(4087)}😀"\n`;
    await validateStrictYaml(bytes(splitSurrogate), context());
  });

  it("honours pre-parse and actual mid-parse cancellation", async () => {
    const pre = new AbortController();
    pre.abort();
    await expectGateError(
      bytes("a: 1\n"),
      "operation_cancelled",
      context(pre.signal),
    );

    const mid = new AbortController();
    scheduleImmediate(() => mid.abort());
    await expectGateError(
      bytes(`value: |\n  ${"x".repeat(100_000)}`),
      "operation_cancelled",
      context(mid.signal),
    );
  });

  it("checks the monotonic deadline before and after an incremental yield", async () => {
    const now = vi.spyOn(performance, "now");
    now
      .mockReturnValueOnce(0)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce(0)
      .mockReturnValue(20);
    try {
      await expectGateError(
        bytes(`value: |\n  ${"x".repeat(10_000)}`),
        "deadline_exceeded",
        context(new AbortController().signal, Date.now() + 10),
      );
    } finally {
      now.mockRestore();
    }
  });

  it("cancels during bounded structural validation after parsing finishes", async () => {
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks >= 6;
      },
    } as AbortSignal;
    await expectGateError(
      bytes(`[${"0,".repeat(299)}0]`),
      "operation_cancelled",
      context(signal),
    );
    expect(checks).toBe(6);
  });

  it("expires during bounded expanded traversal after structural validation", async () => {
    let readings = 0;
    const now = vi.spyOn(performance, "now").mockImplementation(() => {
      readings += 1;
      return readings >= 9 ? 20 : 0;
    });
    try {
      await expectGateError(
        bytes(`[${"0,".repeat(299)}0]`),
        "deadline_exceeded",
        context(new AbortController().signal, Date.now() + 10),
      );
      expect(readings).toBe(9);
    } finally {
      now.mockRestore();
    }
  });

  it("replaces unexpected internal exceptions with a stable safe error", async () => {
    const signal = {
      get aborted(): boolean {
        throw new Error("THIRD_PARTY_CANARY_SOURCE_CONTEXT");
      },
    } as AbortSignal;
    const error = await expectGateError(
      bytes("a: 1\n"),
      "internal_failure",
      context(signal),
    );
    expect(String(error)).not.toContain("THIRD_PARTY_CANARY_SOURCE_CONTEXT");
    expect(JSON.stringify(error)).not.toContain(
      "THIRD_PARTY_CANARY_SOURCE_CONTEXT",
    );
  });
  it("polls cancellation during byte-offset construction", async () => {
    let offsetChecks = 0;
    const offsetSignal = {
      get aborted() {
        offsetChecks += 1;
        return offsetChecks >= 100;
      },
    } as AbortSignal;
    const offsetHeavy = "value: |\n  " + "x".repeat(200_000);
    await expectGateError(
      bytes(offsetHeavy),
      "operation_cancelled",
      context(offsetSignal),
    );
  });
  it("cancels during bounded map-key canonicalization", async () => {
    let checks = 0;
    const signal = {
      get aborted() {
        checks += 1;
        return checks >= 6;
      },
    } as AbortSignal;
    const map = Array.from(
      { length: 300 },
      (_, index) => `key${index}: ${index}`,
    ).join("\n");
    await expectGateError(bytes(map), "operation_cancelled", context(signal));
    expect(checks).toBe(6);
  });

  it("expires during bounded map-key canonicalization", async () => {
    let readings = 0;
    const now = vi.spyOn(performance, "now").mockImplementation(() => {
      readings += 1;
      return readings >= 7 ? 20 : 0;
    });
    const map = Array.from(
      { length: 300 },
      (_, index) => `key${index}: ${index}`,
    ).join("\n");
    try {
      await expectGateError(
        bytes(map),
        "deadline_exceeded",
        context(new AbortController().signal, Date.now() + 10),
      );
      expect(readings).toBe(7);
    } finally {
      now.mockRestore();
    }
  });
});
