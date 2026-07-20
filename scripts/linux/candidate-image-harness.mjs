#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const helperPaths = Object.freeze([
  "/app/native/git-broker",
  "/app/native/openat2-list",
  "/app/native/openat2-read",
]);
const requiredRows = Object.freeze([
  "image:metadata",
  "image:native-paths",
  "image:native-artifacts",
  "image:linkage",
  "image:git-protocol-matrix",
  "image:setuid-setgid",
  "image:writable-dirs",
  "image:offline-startup",
]);

function emit(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}
function fail(message) {
  throw new Error(message);
}
function expect(value, message) {
  if (!value) fail(message);
}
function sha(value) {
  return createHash("sha256").update(value).digest("hex");
}
function parsePathHash(value) {
  const separator = value.indexOf("=");
  expect(separator > 0, `invalid path=sha256 value: ${value}`);
  const path = value.slice(0, separator);
  const digest = value.slice(separator + 1);
  expect(/^sha256:[a-f0-9]{64}$/u.test(digest), `invalid sha256 for ${path}`);
  return [path, digest.slice("sha256:".length)];
}

function parseArguments(argv) {
  const result = {
    broker: "/app/native/git-broker",
    git: "/usr/bin/git",
    runtimeInputs: [],
    startupTimeoutMs: 5000,
    expectedSha256: new Map(),
    expectedLabels: null,
    expectedSetidPaths: [],
  };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index],
      value = argv[index + 1];
    if (!value) fail(`missing value for ${flag}`);
    if (flag === "--image") result.image = value;
    else if (flag === "--broker") result.broker = value;
    else if (flag === "--git") result.git = value;
    else if (flag === "--runtime-loader") result.runtimeLoader = value;
    else if (flag === "--runtime-input") result.runtimeInputs.push(value);
    else if (flag === "--output") result.output = resolve(value);
    else if (flag === "--expected-image-id") result.expectedImageId = value;
    else if (flag === "--expected-architecture")
      result.expectedArchitecture = value;
    else if (flag === "--expect-no-labels") result.expectNoLabels = value;
    else if (flag === "--expected-labels-base64") {
      const labels = JSON.parse(Buffer.from(value, "base64").toString("utf8"));
      expect(
        labels !== null &&
          typeof labels === "object" &&
          !Array.isArray(labels) &&
          Object.values(labels).every((entry) => typeof entry === "string"),
        "invalid --expected-labels-base64",
      );
      result.expectedLabels = labels;
    } else if (flag === "--expected-setid-path")
      result.expectedSetidPaths.push(value);
    else if (flag === "--expected-sha256")
      result.expectedSha256.set(...parsePathHash(value));
    else if (flag === "--expected-startup-status")
      result.expectedStartupStatus = value === "null" ? null : Number(value);
    else if (flag === "--expected-startup-signal")
      result.expectedStartupSignal = value === "null" ? null : value;
    else if (flag === "--expected-startup-timed-out")
      result.expectedStartupTimedOut = value === "true";
    else if (flag === "--startup-timeout-ms")
      result.startupTimeoutMs = Number(value);
    else fail(`unknown argument ${flag}`);
  }
  expect(result.image, "missing --image");
  expect(result.runtimeLoader, "missing --runtime-loader");
  expect(result.expectedImageId, "missing --expected-image-id");
  expect(result.expectedArchitecture, "missing --expected-architecture");
  expect(
    (result.expectNoLabels === "true") !== (result.expectedLabels !== null),
    "provide exactly one label expectation",
  );
  expect(
    result.expectedStartupStatus === null ||
      Number.isInteger(result.expectedStartupStatus),
    "missing --expected-startup-status",
  );
  expect(
    Object.hasOwn(result, "expectedStartupSignal"),
    "missing --expected-startup-signal",
  );
  expect(
    Object.hasOwn(result, "expectedStartupTimedOut"),
    "missing --expected-startup-timed-out",
  );
  expect(result.runtimeInputs.length <= 16, "more than 16 runtime inputs");
  expect(
    Number.isInteger(result.startupTimeoutMs) && result.startupTimeoutMs > 0,
    "invalid --startup-timeout-ms",
  );
  for (const path of [
    ...helperPaths,
    result.git,
    result.runtimeLoader,
    ...result.runtimeInputs,
  ])
    expect(
      result.expectedSha256.has(path),
      `missing --expected-sha256 ${path}`,
    );
  return result;
}

function docker(args, options = {}) {
  const command = process.env.HA_CANDIDATE_IMAGE_HARNESS_DOCKER ?? "docker";
  const prefix = process.env.HA_CANDIDATE_IMAGE_HARNESS_DOCKER_ARGV
    ? JSON.parse(process.env.HA_CANDIDATE_IMAGE_HARNESS_DOCKER_ARGV)
    : [];
  const result = spawnSync(command, [...prefix, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: options.timeoutMs ?? 120_000,
  });
  if (result.error && result.error.code !== "ETIMEDOUT") throw result.error;
  return result;
}

function requireDocker(args, options) {
  const result = docker(args, options);
  expect(
    result.status === 0,
    `docker ${args.join(" ")} failed (${result.status}): ${result.stderr}`,
  );
  return result.stdout;
}

function runInImage(config, command, timeoutMs = 120_000) {
  return requireDocker(
    [
      "run",
      "--rm",
      "--network",
      "none",
      "--platform",
      `linux/${config.expectedArchitecture}`,
      "--entrypoint",
      "/bin/sh",
      config.image,
      "-lc",
      command,
    ],
    { timeoutMs },
  );
}

const rowHandlers = new Map();
function row(id, handler) {
  expect(!rowHandlers.has(id), `duplicate row ${id}`);
  rowHandlers.set(id, handler);
}

row("image:metadata", (config) => {
  const inspect = JSON.parse(
    requireDocker(["image", "inspect", config.image]),
  )[0];
  expect(inspect?.Id === config.expectedImageId, "image ID mismatch");
  expect(
    inspect?.Architecture === config.expectedArchitecture,
    "image architecture mismatch",
  );
  expect(inspect?.Os === "linux", "image OS is not linux");
  expect(
    JSON.stringify(inspect?.Config?.Cmd ?? []) === JSON.stringify(["/run.sh"]),
    "image command is not /run.sh",
  );
  const labels = inspect.Config?.Labels ?? null;
  if (config.expectNoLabels === "true")
    expect(labels === null, "image labels are not empty");
  else
    expect(
      JSON.stringify(Object.entries(labels ?? {}).sort()) ===
        JSON.stringify(Object.entries(config.expectedLabels).sort()),
      "image labels mismatch",
    );
  return {
    id: inspect.Id,
    repoDigests: inspect.RepoDigests ?? [],
    architecture: inspect.Architecture,
    os: inspect.Os,
    command: inspect.Config.Cmd,
    labels,
  };
});

row("image:native-paths", (config) => {
  const output = runInImage(
    config,
    'for path in /app/native/*; do [ -e "$path" ] || continue; if [ -L "$path" ]; then kind=link; elif [ -f "$path" ]; then kind=file; elif [ -d "$path" ]; then kind=dir; else kind=other; fi; printf \'%s %s\\n\' "$kind" "$path"; done | sort',
  );
  const entries = output.trim() ? output.trim().split("\n") : [];
  const expected = helperPaths.map((path) => `file ${path}`);
  expect(
    JSON.stringify(entries) === JSON.stringify(expected),
    `unexpected native helper entries: ${entries.join(",")}`,
  );
  return { entries };
});

row("image:native-artifacts", (config) => {
  const output = runInImage(
    config,
    `stat -c '%U:%G %a %F %n' ${helperPaths.join(" ")}; sha256sum ${[
      ...helperPaths,
      config.git,
      config.runtimeLoader,
      ...config.runtimeInputs,
    ].join(" ")}`,
  );
  const lines = output.trim().split("\n");
  for (const path of helperPaths) {
    expect(
      lines.some((line) => line === `root:root 555 regular file ${path}`),
      `${path} is not root:root 0555 regular file`,
    );
  }
  const hashes = new Map(
    lines
      .filter((line) => /^[a-f0-9]{64} {2}/u.test(line))
      .map((line) => {
        const [digest, path] = line.split(/ {2}/u);
        return [path, digest];
      }),
  );
  for (const [path, expected] of config.expectedSha256)
    expect(hashes.get(path) === expected, `SHA-256 mismatch for ${path}`);
  return { sha256: [...hashes].map(([path, digest]) => `${digest}  ${path}`) };
});

function normalizeLinkage(output) {
  const targets = new Set();
  for (const raw of output.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const direct = /^(\/\S+)\s+\(/u.exec(line);
    if (direct) targets.add(direct[1]);
    const mapped = /^\S+\s+=>\s+(\/\S+)\s+\(/u.exec(line);
    if (mapped) targets.add(mapped[1]);
  }
  return [...targets].sort();
}
function expectedLinkageTargets(config) {
  return [
    config.runtimeLoader,
    ...config.runtimeInputs.map(
      (input) => /^(.*?\.so\.\d+)/u.exec(input)?.[1] ?? input,
    ),
  ].sort();
}

row("image:linkage", (config) => {
  const output = runInImage(
    config,
    `for path in ${[...helperPaths, config.git].join(" ")}; do ldd "$path"; done`,
  );
  const targets = normalizeLinkage(output);
  const expected = expectedLinkageTargets(config);
  expect(
    JSON.stringify(targets) === JSON.stringify(expected),
    `unexpected linkage targets: ${targets.join(",")}`,
  );
  const resolutionOutput = runInImage(
    config,
    `for path in ${targets.join(" ")}; do resolved=$(readlink -f "$path"); printf '%s -> %s\\n' "$path" "$resolved"; sha256sum "$resolved"; done`,
  );
  const resolutionLines = resolutionOutput.trim()
    ? resolutionOutput.trim().split("\n")
    : [];
  const resolved = resolutionLines
    .filter((line) => line.includes(" -> "))
    .map((line) => line.slice(line.indexOf(" -> ") + " -> ".length))
    .sort();
  const expectedResolved = [
    config.runtimeLoader,
    ...config.runtimeInputs,
  ].sort();
  expect(
    JSON.stringify(resolved) === JSON.stringify(expectedResolved),
    `linkage realpath mismatch: ${resolved.join(",")}`,
  );
  const hashes = new Map(
    resolutionLines
      .filter((line) => /^[a-f0-9]{64} {2}/u.test(line))
      .map((line) => {
        const [digest, path] = line.split(/ {2}/u);
        return [path, digest];
      }),
  );
  for (const path of expectedResolved)
    expect(
      hashes.get(path) === config.expectedSha256.get(path),
      `linkage SHA-256 mismatch for ${path}`,
    );
  return {
    targets,
    resolved,
    sha256: [...hashes].map(([path, digest]) => `${digest}  ${path}`),
    rawSha256: sha(output),
    bytes: Buffer.byteLength(output),
  };
});

row("image:git-protocol-matrix", (config) => {
  const args = [
    "run",
    "--rm",
    "--network",
    "none",
    "--platform",
    `linux/${config.expectedArchitecture}`,
    "-v",
    `${process.cwd()}:/work:ro`,
    "-w",
    "/work",
    "--entrypoint",
    "node",
    config.image,
    "scripts/linux/git-candidate-harness.mjs",
    "--broker",
    config.broker,
    "--git",
    config.git,
    "--runtime-loader",
    config.runtimeLoader,
  ];
  for (const input of config.runtimeInputs) args.push("--runtime-input", input);
  const result = docker(args, { timeoutMs: 600_000 });
  expect(
    result.status === 0,
    `Git matrix failed (${result.status}): ${result.stderr}`,
  );
  const summary = result.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line))
    .findLast((value) => value.type === "summary");
  expect(summary?.status === "PASSED", "Git matrix summary did not pass");
  expect(summary.required === summary.executed, "Git matrix missed rows");
  return summary;
});

row("image:setuid-setgid", (config) => {
  const output = runInImage(
    config,
    "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -print | sort",
  );
  const paths = output.trim() ? output.trim().split("\n") : [];
  expect(
    JSON.stringify(paths) === JSON.stringify(config.expectedSetidPaths),
    `unexpected setuid/setgid paths: ${paths}`,
  );
  return { paths };
});

row("image:writable-dirs", (config) => {
  const output = runInImage(
    config,
    "find / -xdev -type d -perm -0002 -print | sort",
  );
  const paths = output.trim() ? output.trim().split("\n") : [];
  const unexpected = paths.filter(
    (path) => path !== "/tmp" && path !== "/var/tmp",
  );
  expect(
    unexpected.length === 0,
    `unexpected world-writable directories: ${unexpected.join(",")}`,
  );
  return { paths };
});

row("image:offline-startup", (config) => {
  const result = docker(
    [
      "run",
      "--rm",
      "--network",
      "none",
      "--platform",
      `linux/${config.expectedArchitecture}`,
      config.image,
    ],
    { timeoutMs: config.startupTimeoutMs },
  );
  const stderr = result.stderr ?? "";
  const stdout = result.stdout ?? "";
  expect(
    !/apk add|fetch https?:\/\//iu.test(`${stdout}\n${stderr}`),
    "startup attempted runtime install/network",
  );
  expect(
    result.status === config.expectedStartupStatus,
    "startup status mismatch",
  );
  expect(
    result.signal === config.expectedStartupSignal,
    "startup signal mismatch",
  );
  expect(
    (result.error?.code === "ETIMEDOUT") === config.expectedStartupTimedOut,
    "startup timeout mismatch",
  );
  return {
    status: result.status,
    signal: result.signal,
    timedOut: result.error?.code === "ETIMEDOUT",
    stdoutSha256: sha(stdout),
    stderrSha256: sha(stderr),
  };
});

const requestedRows = process.env.HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS;
if (requestedRows && process.env.NODE_ENV !== "test")
  fail("HA_CANDIDATE_IMAGE_HARNESS_ONLY_ROWS is test-only");
const rowsToRun = requestedRows
  ? requestedRows.split(",").filter(Boolean)
  : requiredRows;
for (const id of rowsToRun) expect(rowHandlers.has(id), `unknown row ${id}`);
const config = parseArguments(process.argv.slice(2));
const actualRows = [...rowHandlers.keys()].sort(),
  expectedRows = [...requiredRows].sort();
expect(
  JSON.stringify(actualRows) === JSON.stringify(expectedRows),
  `mandatory candidate-image row registry mismatch: expected ${expectedRows.length}, got ${actualRows.length}`,
);
const results = [];
emit({
  type: "manifest",
  version: 1,
  requiredRows,
  image: config.image,
  expectedImageId: config.expectedImageId,
  expectedArchitecture: config.expectedArchitecture,
  broker: config.broker,
  git: config.git,
  runtimeLoader: config.runtimeLoader,
  runtimeInputs: config.runtimeInputs,
});
for (const id of rowsToRun) {
  const started = Date.now();
  try {
    const evidence = rowHandlers.get(id)(config);
    const record = {
      type: "row",
      id,
      status: "PASSED",
      durationMs: Date.now() - started,
      evidence,
    };
    results.push(record);
    emit(record);
  } catch (error) {
    const record = {
      type: "row",
      id,
      status: "FAILED",
      durationMs: Date.now() - started,
      error: String(error?.message ?? error),
    };
    results.push(record);
    emit(record);
  }
}
const failed = results.filter((result) => result.status !== "PASSED");
const summary = {
  type: "summary",
  status: failed.length ? "FAILED" : "PASSED",
  required: rowsToRun.length,
  executed: results.length,
  passed: results.length - failed.length,
  failed: failed.map((result) => result.id),
};
emit(summary);
if (config.output)
  writeFileSync(
    config.output,
    `${results.map((value) => JSON.stringify(value)).join("\n")}\n${JSON.stringify(summary)}\n`,
    { mode: 0o600 },
  );
if (failed.length || results.length !== rowsToRun.length) process.exitCode = 1;
