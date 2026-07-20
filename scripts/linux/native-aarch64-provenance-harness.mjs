#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

const CAPTURE_LIMIT_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 30_000;
const FIXTURE_ENV = "HA_NATIVE_AARCH64_PROVENANCE_FIXTURE";
const BINFMT_ROOT = "/proc/sys/fs/binfmt_misc";
const CPUINFO_PATH = "/proc/cpuinfo";
const requiredRows = Object.freeze([
  "host:os-architecture",
  "host:cpu-provenance",
  "host:binfmt",
  "docker:server",
  "host:runner-provenance",
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
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function captureEvidence(value) {
  return { bytes: value.length, sha256: sha256(value) };
}
function boundedBuffer(value, label) {
  const buffer = Buffer.isBuffer(value)
    ? value
    : Buffer.from(value ?? "", "utf8");
  expect(
    buffer.length <= CAPTURE_LIMIT_BYTES,
    `${label} exceeded ${CAPTURE_LIMIT_BYTES} bytes`,
  );
  return buffer;
}
function decodeUtf8(value, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
}
function boundedString(value, label, limit = 256) {
  expect(typeof value === "string", `${label} is not a string`);
  expect(Buffer.byteLength(value, "utf8") <= limit, `${label} is oversized`);
  return value;
}

const fixtureSource = process.env[FIXTURE_ENV];
if (fixtureSource !== undefined && process.env.NODE_ENV !== "test")
  fail(`${FIXTURE_ENV} is test-only`);
let fixture;
if (fixtureSource !== undefined) {
  try {
    fixture = JSON.parse(fixtureSource);
  } catch {
    fail(`${FIXTURE_ENV} is not valid JSON`);
  }
  expect(
    fixture && typeof fixture === "object" && !Array.isArray(fixture),
    `${FIXTURE_ENV} must be an object`,
  );
}

function fixtureCommand(id) {
  const result = fixture?.commands?.[id];
  expect(result && typeof result === "object", `fixture missing command ${id}`);
  expect(Number.isInteger(result.status), `fixture ${id} status is invalid`);
  expect(
    result.signal === undefined || typeof result.signal === "string",
    `fixture ${id} signal is invalid`,
  );
  expect(typeof result.stdout === "string", `fixture ${id} stdout is invalid`);
  expect(typeof result.stderr === "string", `fixture ${id} stderr is invalid`);
  expect(
    result.errorCode === undefined || typeof result.errorCode === "string",
    `fixture ${id} errorCode is invalid`,
  );
  return {
    status: result.status,
    signal: result.signal ?? null,
    stdout: Buffer.from(result.stdout, "utf8"),
    stderr: Buffer.from(result.stderr, "utf8"),
    error: result.errorCode ? { code: result.errorCode } : undefined,
  };
}

function requireCommand(id, command, args) {
  const result = fixture
    ? fixtureCommand(id)
    : spawnSync(command, args, {
        encoding: "buffer",
        maxBuffer: CAPTURE_LIMIT_BYTES,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        timeout: COMMAND_TIMEOUT_MS,
      });
  const stdout = boundedBuffer(result.stdout, `${id} stdout`);
  const stderr = boundedBuffer(result.stderr, `${id} stderr`);
  if (result.error || result.status !== 0 || result.signal !== null) {
    const details = {
      errorCode: result.error?.code ?? null,
      status: result.status ?? null,
      signal: result.signal ?? null,
      stdout: captureEvidence(stdout),
      stderr: captureEvidence(stderr),
    };
    fail(`${id} failed: ${JSON.stringify(details)}`);
  }
  return {
    buffer: stdout,
    text: decodeUtf8(stdout, `${id} stdout`),
    evidence: captureEvidence(stdout),
    stderr: captureEvidence(stderr),
  };
}

function requireFile(path) {
  let value;
  if (fixture) {
    value = fixture.files?.[path];
    expect(typeof value === "string", `fixture missing file ${path}`);
    value = Buffer.from(value, "utf8");
  } else {
    try {
      value = readFileSync(path);
    } catch (error) {
      fail(`cannot read ${path}: ${error?.code ?? "UNKNOWN"}`);
    }
  }
  const buffer = boundedBuffer(value, path);
  return {
    buffer,
    text: decodeUtf8(buffer, path),
    evidence: captureEvidence(buffer),
  };
}

function requireDirectory(path) {
  let entries;
  if (fixture) {
    entries = fixture.directories?.[path];
    expect(Array.isArray(entries), `fixture missing directory ${path}`);
  } else {
    try {
      entries = readdirSync(path, { encoding: "utf8" });
    } catch (error) {
      fail(`cannot read ${path}: ${error?.code ?? "UNKNOWN"}`);
    }
  }
  expect(entries.length <= 256, `${path} contains too many entries`);
  const normalized = entries.map((entry) => {
    boundedString(entry, `${path} entry`, 255);
    expect(
      entry !== "." && entry !== ".." && !entry.includes("/"),
      `${path} contains an invalid entry`,
    );
    return entry;
  });
  expect(
    new Set(normalized).size === normalized.length,
    `${path} has duplicates`,
  );
  return normalized.sort();
}

function normalizeArchitecture(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase().replaceAll("_", "-");
  if (normalized === "aarch64" || normalized === "arm64") return "aarch64";
  return null;
}

function parseArguments(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    expect(value !== undefined, `missing value for ${flag}`);
    if (flag === "--runner-identity") {
      expect(
        !Object.hasOwn(result, "runnerIdentity"),
        "duplicate --runner-identity",
      );
      result.runnerIdentity = value;
    } else if (flag === "--output") {
      expect(!Object.hasOwn(result, "output"), "duplicate --output");
      expect(value.trim().length > 0, "empty --output");
      result.output = resolve(value);
    } else fail(`unknown argument ${boundedString(flag, "argument", 128)}`);
  }
  return result;
}

function parseLscpu(capture) {
  let document;
  try {
    document = JSON.parse(capture.text);
  } catch {
    fail("lscpu output is not valid JSON");
  }
  expect(Array.isArray(document?.lscpu), "lscpu JSON is missing lscpu rows");
  expect(document.lscpu.length <= 256, "lscpu JSON has too many rows");
  const architectures = [];
  for (const entry of document.lscpu) {
    expect(entry && typeof entry === "object", "lscpu row is invalid");
    const field = boundedString(entry.field, "lscpu field");
    const data = boundedString(entry.data, `lscpu ${field}`);
    if (field.trim().replace(/:$/u, "").toLowerCase() === "architecture")
      architectures.push(data);
  }
  expect(architectures.length > 0, "lscpu architecture evidence is missing");
  expect(
    architectures.every((value) => normalizeArchitecture(value) === "aarch64"),
    "lscpu architecture is not aarch64",
  );
  return architectures;
}

function collectCpuInfoValues(text, allowedFields) {
  const values = new Map(allowedFields.map((field) => [field, new Set()]));
  for (const line of text.split("\n")) {
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const field = line.slice(0, separator).trim().toLowerCase();
    const target = values.get(field);
    if (!target) continue;
    const value = line.slice(separator + 1).trim();
    boundedString(value, `cpuinfo ${field}`);
    if (value.length === 0) continue;
    target.add(value);
    expect(target.size <= 16, `cpuinfo ${field} has too many values`);
  }
  return Object.fromEntries(
    [...values].map(([field, entries]) => [field, [...entries].sort()]),
  );
}

const rowHandlers = new Map();
function row(id, handler) {
  expect(!rowHandlers.has(id), `duplicate row ${id}`);
  rowHandlers.set(id, handler);
}

row("host:os-architecture", () => {
  const platform = fixture?.platform ?? process.platform;
  const architecture = fixture?.arch ?? process.arch;
  expect(platform === "linux", "process.platform is not linux");
  expect(architecture === "arm64", "process.arch is not arm64");
  const unameSystem = requireCommand("unameSystem", "uname", ["-s"]);
  const unameMachine = requireCommand("unameMachine", "uname", ["-m"]);
  expect(unameSystem.text.trim() === "Linux", "uname -s is not Linux");
  expect(unameMachine.text.trim() === "aarch64", "uname -m is not aarch64");
  return {
    process: { platform, architecture },
    uname: {
      system: unameSystem.text.trim(),
      machine: unameMachine.text.trim(),
      systemCapture: unameSystem.evidence,
      machineCapture: unameMachine.evidence,
    },
  };
});

row("host:cpu-provenance", () => {
  const lscpu = requireCommand("lscpu", "lscpu", ["--json"]);
  const cpuinfo = requireFile(CPUINFO_PATH);
  expect(cpuinfo.buffer.length > 0, `${CPUINFO_PATH} is empty`);
  const architectures = parseLscpu(lscpu);
  const combined = `${lscpu.text}\n${cpuinfo.text}`;
  const indicators = [
    ...new Set(
      [
        ...combined.matchAll(
          /\b(?:qemu|tcg|hypervisor|emulat(?:ed|ing|ion|or))\b/giu,
        ),
      ].map((match) => match[0].toLowerCase()),
    ),
  ].sort();
  expect(
    indicators.length === 0,
    "CPU provenance contains emulation indicators",
  );
  const fields = collectCpuInfoValues(cpuinfo.text, [
    "cpu architecture",
    "hardware",
    "model",
    "model name",
  ]);
  const processorCount = [...cpuinfo.text.matchAll(/^processor\s*:/gimu)]
    .length;
  expect(processorCount > 0, "cpuinfo processor evidence is missing");
  expect(
    ["hardware", "model", "model name"].some(
      (field) => fields[field].length > 0,
    ),
    "cpuinfo identity evidence is missing",
  );
  return {
    architecture: {
      exact: architectures,
      normalized: "aarch64",
    },
    lscpu: lscpu.evidence,
    cpuinfo: {
      ...cpuinfo.evidence,
      processorCount,
      fields,
    },
    rejectedIndicators: indicators,
  };
});

row("host:binfmt", () => {
  const entries = requireDirectory(BINFMT_ROOT);
  expect(entries.includes("status"), "binfmt_misc status is missing");
  const registryStatusCapture = requireFile(`${BINFMT_ROOT}/status`);
  const registryStatus = registryStatusCapture.text.trim();
  expect(
    registryStatus === "enabled" || registryStatus === "disabled",
    "binfmt_misc status is malformed",
  );
  const handlers = [];
  for (const name of entries.filter(
    (entry) => entry !== "register" && entry !== "status",
  )) {
    const capture = requireFile(`${BINFMT_ROOT}/${name}`);
    const status = capture.text.split(/\r?\n/u, 1)[0]?.trim();
    expect(
      status === "enabled" || status === "disabled",
      "binfmt_misc handler status is malformed",
    );
    const translationEvidence = /qemu[-_]?aarch64|aarch64|arm64/iu.test(
      `${name}\n${capture.text}`,
    );
    expect(
      !(status === "enabled" && translationEvidence),
      "enabled arm64/aarch64 binfmt translation handler detected",
    );
    handlers.push({
      name,
      status,
      translationEvidence,
      ...capture.evidence,
    });
  }
  return {
    registry: { status: registryStatus, ...registryStatusCapture.evidence },
    handlers,
  };
});

row("docker:server", () => {
  const capture = requireCommand("dockerServer", "docker", [
    "version",
    "--format",
    "{{json .}}",
  ]);
  let document;
  try {
    document = JSON.parse(capture.text);
  } catch {
    fail("Docker server inspection is not valid JSON");
  }
  const server = document?.Server;
  expect(
    server && typeof server === "object",
    "Docker Server evidence is missing",
  );
  const os = Object.fromEntries(
    ["Os", "OSType"]
      .filter((field) => server[field] !== undefined)
      .map((field) => [
        field,
        boundedString(server[field], `Server.${field}`, 64),
      ]),
  );
  const architectures = Object.fromEntries(
    ["Arch", "Architecture"]
      .filter((field) => server[field] !== undefined)
      .map((field) => [
        field,
        boundedString(server[field], `Server.${field}`, 64),
      ]),
  );
  expect(Object.keys(os).length > 0, "Docker Server OS evidence is missing");
  expect(
    Object.values(os).every((value) => value.trim().toLowerCase() === "linux"),
    "Docker Server OS is not linux",
  );
  expect(
    Object.keys(architectures).length > 0,
    "Docker Server architecture evidence is missing",
  );
  expect(
    Object.values(architectures).every(
      (value) => normalizeArchitecture(value) === "aarch64",
    ),
    "Docker Server architecture is not arm64/aarch64",
  );
  return {
    os,
    architecture: architectures,
    normalized: { os: "linux", architecture: "aarch64" },
    capture: capture.evidence,
  };
});

row("host:runner-provenance", (config) => {
  const identity = config.runnerIdentity;
  expect(typeof identity === "string", "missing --runner-identity");
  expect(identity.trim().length > 0, "runner identity is empty or whitespace");
  expect(
    [...identity].every((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint !== undefined && codePoint > 0x1f && codePoint !== 0x7f;
    }),
    "runner identity has controls",
  );
  const bytes = Buffer.byteLength(identity, "utf8");
  expect(bytes <= 512, "runner identity exceeds 512 UTF-8 bytes");
  return {
    identity,
    bytes,
    sha256: sha256(identity),
    selfAttested: true,
    claimLimit:
      "This self-attested value does not establish runner provenance; external immutable runner provenance is still required.",
  };
});

const config = parseArguments(process.argv.slice(2));
const actualRows = [...rowHandlers.keys()].sort();
const expectedRows = [...requiredRows].sort();
expect(
  JSON.stringify(actualRows) === JSON.stringify(expectedRows),
  `mandatory native-aarch64 row registry mismatch: expected ${expectedRows.length}, got ${actualRows.length}`,
);
const manifest = {
  type: "manifest",
  version: 1,
  requiredRows,
  commandTimeoutMs: COMMAND_TIMEOUT_MS,
  captureLimitBytes: CAPTURE_LIMIT_BYTES,
};
const records = [manifest];
emit(manifest);
const results = [];
for (const id of requiredRows) {
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
    records.push(record);
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
    records.push(record);
    emit(record);
  }
}
const failed = results.filter((result) => result.status !== "PASSED");
const summary = {
  type: "summary",
  status: failed.length === 0 ? "PASSED" : "FAILED",
  required: requiredRows.length,
  executed: results.length,
  passed: results.length - failed.length,
  failed: failed.map((result) => result.id),
};
records.push(summary);
emit(summary);
if (config.output) {
  const flags =
    constants.O_WRONLY |
    constants.O_CREAT |
    constants.O_TRUNC |
    (constants.O_NOFOLLOW ?? 0);
  const descriptor = openSync(config.output, flags, 0o600);
  try {
    fchmodSync(descriptor, 0o600);
    writeFileSync(
      descriptor,
      `${records.map((value) => JSON.stringify(value)).join("\n")}\n`,
      "utf8",
    );
  } finally {
    closeSync(descriptor);
  }
}
if (failed.length > 0 || results.length !== requiredRows.length)
  process.exitCode = 1;
