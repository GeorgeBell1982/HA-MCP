import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);

it("requires explicit native acknowledgement, an immutable builder, and matching image/daemon architectures", async () => {
  const moduleUrl = new URL(
    "../scripts/linux/phase3-ha-evidence.mjs",
    import.meta.url,
  ).href;
  await execute(process.execPath, [
    "--input-type=module",
    "-e",
    `
import assert from "node:assert/strict";
import { parseHaFixtureArguments as parse, assertFixtureArchitecture as check } from ${JSON.stringify(moduleUrl)};
const ack = "--ack-disposable-ha-boundary-smoke";
const digest = "sha256:" + "a".repeat(64);
assert.equal(parse([ack]).fullWorkflow, false);
assert.equal(parse([ack, "--full-workflow"]).architecture, "amd64");
assert.deepEqual(parse([ack, "--full-workflow", "--native-arm64-builder", digest]), { fullWorkflow: true, architecture: "arm64", builder: digest });
for (const args of [[], [ack, "--native-arm64-builder", digest], [ack, "--full-workflow", "--native-arm64-builder", "latest"], [ack, "--full-workflow", "--native-arm64-builder", digest, "extra"]]) assert.throws(() => parse(args));
const arm = {Os: "linux", Architecture: "arm64"};
check([arm, arm], "aarch64", "arm64");
check([{Os: "linux", Architecture: "amd64"}], "x86_64", "amd64");
for (const images of [[arm, {Os: "linux", Architecture: "amd64"}], [undefined], [{Os: "windows", Architecture: "arm64"}]]) assert.throws(() => check(images, "arm64", "arm64"));
assert.throws(() => check([arm], "amd64", "arm64"));
`,
  ]);
});

it("requires every exact acceptance row and rejects missing, duplicate, extra or failed evidence", async () => {
  const moduleUrl = new URL(
    "../scripts/linux/phase3-ha-evidence.mjs",
    import.meta.url,
  ).href;
  const result = await execute(process.execPath, [
    "--input-type=module",
    "-e",
    `
import assert from "node:assert/strict";
import { mainWorkerRows, readonlyWorkerRows, boundaryRows, assertExactRows, parseWorkerRows } from ${JSON.stringify(moduleUrl)};
const all = [...boundaryRows, ...mainWorkerRows, ...readonlyWorkerRows];
assert.equal(all.length, 27);
assertExactRows(all, all);
for (const expected of [mainWorkerRows, readonlyWorkerRows]) {
  const output = expected.map(row => "PASSED " + row).join("\\n");
  assert.deepEqual(parseWorkerRows(output, expected), expected);
  for (const invalid of [
    expected.slice(1).map(row => "PASSED " + row).join("\\n"),
    output + "\\nPASSED " + expected[0],
    output + "\\nPASSED unexpected",
    output.replace("PASSED", "FAILED"),
    "",
  ]) assert.throws(() => parseWorkerRows(invalid, expected));
}
assert.throws(() => assertExactRows(all.slice(1), all));
`,
  ]);
  expect(result.stderr).toBe("");
});

it("cleans ambiguous Docker creates and requires affirmative daemon absence", async () => {
  for (const mode of ["removed", "retained", "daemon-failure"]) {
    // Intercept only this child process's built-in spawnSync. No Docker command
    // reaches the host, and the fake create changes state before returning failure.
    const preload = `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
const present = new Set();
childProcess.spawnSync = (_command, args) => {
  process.stdout.write("FAKE " + JSON.stringify(args) + "\\n");
  const result = (status, stdout = "") => ({status, stdout, stderr: "", signal: null});
  if (args[0] === "image") return result(0, JSON.stringify([{Os: "linux", Architecture: "amd64"}]));
  if (args[0] === "info") return result(0, "x86_64");
  if (args[0] === "volume" && args[1] === "create") {
    present.add(args[2]);
    return result(1);
  }
  if (args[0] === "rm" || (args[0] === "volume" && args[1] === "rm")) {
    if (${JSON.stringify(mode)} !== "retained") present.delete(args.at(-1));
    return result(1);
  }
  if (args[1] === "ls") {
    if (${JSON.stringify(mode)} === "daemon-failure") return result(1);
    return result(0, args[0] === "volume" ? [...present].join("\\n") : "");
  }
  throw new Error("unexpected fake Docker operation");
};
syncBuiltinESMExports();`;
    const result = await execute(
      process.execPath,
      [
        "--import",
        `data:text/javascript,${encodeURIComponent(preload)}`,
        fileURLToPath(
          new URL(
            "../scripts/linux/phase3-ha-boundary-smoke.mjs",
            import.meta.url,
          ),
        ),
        "--ack-disposable-ha-boundary-smoke",
        "--full-workflow",
      ],
      { timeout: 10_000 },
    ).then(
      (value) => ({ ...value, code: 0 }),
      (error: { stdout: string; stderr: string; code: number }) => error,
    );
    expect(result.code).toBe(1);
    const calls = result.stdout
      .split("\n")
      .filter((line) => line.startsWith("FAKE "))
      .map((line) => JSON.parse(line.slice(5)) as string[]);
    const created = calls.find((args) => args[1] === "create")?.[2];
    expect(created).toMatch(/^codex-ha-boundary-[a-f0-9-]+-config$/u);
    const removals = calls.filter(
      (args) => args[0] === "rm" || args[1] === "rm",
    );
    expect(removals).toHaveLength(5);
    expect(removals.map((args) => args.at(-1))).toContain(created);
    expect(new Set(removals.map((args) => args.at(-1))).size).toBe(5);
    expect(
      result.stdout.includes("PASSED owned-container-and-volume-removed"),
    ).toBe(mode === "removed");
    expect(result.stderr.includes("FAILED fixture_cleanup")).toBe(
      mode !== "removed",
    );
  }
});
