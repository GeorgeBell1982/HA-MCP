#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const MAGIC = Buffer.from("HAGIT1\0", "ascii");
const RESPONSE_MAGIC = Buffer.from("HAGITR1\0", "ascii");
const HEADER_BYTES = 128;
const CANARY = `G2-CANARY-${randomUUID()}`;
const operations = Object.freeze({
  status: 1,
  "object-format": 2,
  index: 3,
  tree: 4,
  objects: 5,
});
const states = Object.freeze([
  "clean",
  "staged",
  "unstaged",
  "staged+unstaged",
  "untracked",
]);
const refs = Object.freeze(["born", "unborn", "detached"]);
const formats = Object.freeze(["sha1", "sha256"]);
const hostileVectors = Object.freeze([
  "local",
  "global",
  "system",
  "include",
  "includeIf",
  "hooksPath",
  "filter.process",
  "filter.clean",
  "filter.smudge",
  "diff.external",
  "fsmonitor",
  "attributes",
  "excludes",
  "mailmap",
  "alias",
  "credential",
  "proxy",
  "SSH",
  "askpass",
  "pager",
  "editor",
  "replacements",
  "lazy-fetch-promisor",
  "alternates",
]);
const topologies = Object.freeze([
  "linked",
  "bare",
  "common-dir",
  "worktree",
  "submodule",
]);
const protocolRows = Object.freeze([
  "bad-magic",
  "truncated",
  "trailing",
  "oversized",
  "unknown-operation",
]);
const lifecycleRows = Object.freeze(["partial-request-kill", "timeout-kill"]);
const closureRows = Object.freeze([
  "missing-loader",
  "relative-loader",
  "duplicate",
  "directory",
  "symlink",
  "nonregular",
  "over-limit",
]);

const requiredRows = Object.freeze([
  ...formats.flatMap((format) =>
    refs.flatMap((ref) =>
      states.map((state) => `matrix:${format}:${ref}:${state}`),
    ),
  ),
  ...hostileVectors.map((name) => `hostile:${name}`),
  ...topologies.map((name) => `topology:${name}`),
  ...protocolRows.map((name) => `protocol:${name}`),
  ...lifecycleRows.map((name) => `lifecycle:${name}`),
  "rlimits:all",
  ...closureRows.map((name) => `closure:${name}`),
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
function sha(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseArguments(argv) {
  const result = { runtimeInputs: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index],
      value = argv[index + 1];
    if (!value) fail(`missing value for ${flag}`);
    if (flag === "--broker") result.broker = resolve(value);
    else if (flag === "--git") result.git = resolve(value);
    else if (flag === "--runtime-loader") result.runtimeLoader = resolve(value);
    else if (flag === "--runtime-input")
      result.runtimeInputs.push(resolve(value));
    else if (flag === "--output") result.output = resolve(value);
    else fail(`unknown argument ${flag}`);
  }
  for (const key of ["broker", "git", "runtimeLoader"])
    expect(
      result[key],
      `missing --${key.replace(/[A-Z]/g, (x) => `-${x.toLowerCase()}`)}`,
    );
  expect(result.runtimeInputs.length <= 16, "more than 16 runtime inputs");
  return result;
}

function command(file, args, options = {}) {
  const result = spawnSync(file, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.status !== 0)
    fail(
      `${basename(file)} ${args.join(" ")} failed (${result.status}): ${result.stderr}`,
    );
  return result.stdout.trim();
}

function request(operation, objectIds = []) {
  const payload = Buffer.from(objectIds.join("\n"), "ascii");
  const frame = Buffer.alloc(16 + payload.length);
  MAGIC.copy(frame);
  frame[7] = operations[operation];
  frame.writeUInt32BE(payload.length, 8);
  payload.copy(frame, 16);
  return frame;
}

function treeDigest(root) {
  const hash = createHash("sha256");
  function walk(directory, relative = "") {
    for (const name of readdirSync(directory).sort()) {
      if (name === ".git" && relative === "") {
        const git = join(directory, name);
        for (const tracked of ["HEAD", "index", "config", "packed-refs"]) {
          const path = join(git, tracked);
          if (existsSync(path))
            hash.update(`git:${tracked}\0`).update(readFileSync(path));
        }
        continue;
      }
      const path = join(directory, name),
        child = relative ? `${relative}/${name}` : name,
        metadata = lstatSync(path);
      hash.update(`${child}\0${metadata.mode}\0${metadata.size}\0`);
      if (metadata.isDirectory()) walk(path, child);
      else if (metadata.isFile()) hash.update(readFileSync(path));
      else if (metadata.isSymbolicLink()) hash.update("link");
    }
  }
  walk(root);
  return hash.digest("hex");
}

function assertNoProcessGroup(pid) {
  try {
    process.kill(-pid, 0);
    fail(`descendant process group ${pid} survived`);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function invoke(config, root, operation, objectIds = [], overrides = {}) {
  const loader =
    overrides.runtimeLoader === undefined
      ? config.runtimeLoader
      : overrides.runtimeLoader;
  const inputs = overrides.runtimeInputs ?? config.runtimeInputs;
  const args = [
    "--protocol-v1",
    "--git",
    overrides.git ?? config.git,
    "--root",
    root,
  ];
  if (loader !== null) args.push("--runtime-loader", loader);
  for (const input of inputs) args.push("--runtime-input", input);
  return invokeRaw(
    config.broker,
    args,
    overrides.frame ?? request(operation, objectIds),
    overrides.env,
  );
}

function invokeRaw(broker, args, frame, env = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(broker, args, {
      detached: true,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [],
      stderr = [];
    let stdoutBytes = 0,
      stderrBytes = 0,
      settled = false;
    const timer = setTimeout(() => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }, 12_000);
    child.stdout.on("data", (part) => {
      stdoutBytes += part.length;
      if (stdoutBytes <= 5 * 1024 * 1024) stdout.push(part);
    });
    child.stderr.on("data", (part) => {
      stderrBytes += part.length;
      if (stderrBytes <= 8192) stderr.push(part);
    });
    child.on("error", reject);
    child.stdin.on("error", (error) => {
      if (error.code === "EPIPE" || error.code === "ERR_STREAM_DESTROYED")
        return;
      if (!settled) reject(error);
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      setTimeout(() => {
        try {
          assertNoProcessGroup(child.pid);
          resolvePromise({
            code,
            signal,
            pid: child.pid,
            stdout: Buffer.concat(stdout),
            stderr: Buffer.concat(stderr),
            stdoutBytes,
            stderrBytes,
          });
        } catch (error) {
          reject(error);
        }
      }, 20);
    });
    child.stdin.end(frame);
  });
}

function decode(result) {
  expect(
    result.code === 0 && result.signal === null,
    `broker exit ${result.code}/${result.signal}`,
  );
  expect(result.stderrBytes === 0, "broker wrote diagnostics");
  const bytes = result.stdout;
  expect(
    bytes.length >= HEADER_BYTES && bytes.subarray(0, 8).equals(RESPONSE_MAGIC),
    "invalid response frame",
  );
  expect(
    bytes.readUInt32BE(8) === 1 &&
      bytes.readUInt32BE(16) === 0 &&
      bytes.readUInt32BE(20) === 0 &&
      bytes.readUInt32BE(124) === 0,
    "noncanonical response header",
  );
  const status = bytes.readUInt32BE(12),
    length = bytes.readUInt32BE(120);
  expect(
    length === bytes.length - HEADER_BYTES && length <= 4 * 1024 * 1024,
    "response length violation",
  );
  return { status, output: bytes.subarray(HEADER_BYTES), digest: sha(bytes) };
}

function initRepository(base, format, ref, state) {
  const root = join(
    base,
    `repo-${format}-${ref}-${state.replaceAll("+", "-")}-${randomUUID()}`,
  );
  mkdirSync(root);
  command(config.git, ["init", "-q", `--object-format=${format}`, root]);
  command(config.git, [
    "-C",
    root,
    "config",
    "user.email",
    "candidate@example.invalid",
  ]);
  command(config.git, ["-C", root, "config", "user.name", "Candidate Harness"]);
  if (ref !== "unborn") {
    writeFileSync(join(root, "automation.yaml"), "value: one\n");
    command(config.git, ["-C", root, "add", "automation.yaml"]);
    command(config.git, ["-C", root, "commit", "-qm", "fixture"]);
    if (ref === "detached")
      command(config.git, ["-C", root, "checkout", "-q", "--detach"]);
  }
  if (state === "staged") {
    writeFileSync(join(root, "automation.yaml"), "value: staged\n");
    command(config.git, ["-C", root, "add", "automation.yaml"]);
  }
  if (state === "unstaged" && ref !== "unborn")
    writeFileSync(join(root, "automation.yaml"), "value: unstaged\n");
  if (state === "staged+unstaged") {
    writeFileSync(join(root, "automation.yaml"), "value: staged\n");
    command(config.git, ["-C", root, "add", "automation.yaml"]);
    writeFileSync(join(root, "automation.yaml"), "value: both\n");
  }
  if (state === "untracked")
    writeFileSync(join(root, "untracked.yaml"), "value: untracked\n");
  return root;
}

function validateStatus(bytes, format, ref, state) {
  expect(bytes.length > 0 && bytes.at(-1) === 0, "status is not NUL framed");
  const records = bytes.toString("utf8").slice(0, -1).split("\0");
  expect(
    records.every(
      (record) => record.startsWith("# branch.") || /^(1|\?) /u.test(record),
    ),
    "unexpected status record",
  );
  const joined = records.join("\n");
  if (ref === "unborn")
    expect(joined.includes("# branch.oid (initial)"), "unborn marker missing");
  else
    expect(
      joined.includes(`# branch.oid ${"[0-9a-f]"}`) ||
        /# branch\.oid [0-9a-f]+/u.test(joined),
      "born oid missing",
    );
  if (state === "clean" || (ref === "unborn" && state === "unstaged"))
    expect(!/^(1|\?) /mu.test(joined), "clean repository reported changes");
  if (state === "untracked")
    expect(joined.includes("? untracked.yaml"), "untracked file missing");
  return { records: records.length, format };
}

function parseIndex(bytes, format) {
  if (bytes.length === 0) return { records: 0, objectIds: [] };
  expect(bytes.at(-1) === 0, "index is not NUL framed");
  const records = bytes.toString("utf8").slice(0, -1).split("\0"),
    width = format === "sha1" ? 40 : 64,
    objectIds = [];
  for (const record of records) {
    const match = new RegExp(
      `^100644 ([0-9a-f]{${width}}) 0\\t(.+)$`,
      "u",
    ).exec(record);
    expect(match, "invalid index record");
    objectIds.push(match[1]);
  }
  return { records: records.length, objectIds };
}

function parseTree(bytes, format) {
  if (bytes.length === 0) return { records: 0, objectIds: [] };
  expect(bytes.at(-1) === 0, "tree is not NUL framed");
  const records = bytes.toString("utf8").slice(0, -1).split("\0"),
    width = format === "sha1" ? 40 : 64,
    objectIds = [];
  for (const record of records) {
    const match = new RegExp(
      `^100644 blob ([0-9a-f]{${width}})\\t(.+)$`,
      "u",
    ).exec(record);
    expect(match, "invalid tree record");
    objectIds.push(match[1]);
  }
  return { records: records.length, objectIds };
}

function parseObjects(bytes, ids) {
  let cursor = 0,
    records = 0;
  while (cursor < bytes.length) {
    const newline = bytes.indexOf(10, cursor);
    expect(newline > cursor, "object header missing");
    const match = /^([0-9a-f]+) ([0-9]+)$/u.exec(
      bytes.toString("ascii", cursor, newline),
    );
    expect(match, "object header invalid");
    const size = Number(match[2]);
    cursor = newline + 1 + size;
    expect(cursor <= bytes.length, "object body truncated");
    records += 1;
  }
  expect(records === ids.length, "object record count mismatch");
  return { records };
}

const runners = new Map();
function row(id, runner) {
  expect(!runners.has(id), `duplicate row ${id}`);
  runners.set(id, runner);
}

for (const format of formats)
  for (const ref of refs)
    for (const state of states)
      row(`matrix:${format}:${ref}:${state}`, async (base) => {
        const root = initRepository(base, format, ref, state),
          before = treeDigest(root),
          evidence = {};
        const status = decode(await invoke(config, root, "status"));
        expect(status.status === 0, "status denied");
        evidence.status = validateStatus(status.output, format, ref, state);
        if (ref === "unborn" && state === "unstaged")
          evidence.status.requestedState =
            "not-applicable-without-HEAD-or-index";
        const objectFormat = decode(
          await invoke(config, root, "object-format"),
        );
        expect(
          objectFormat.status === 0 &&
            objectFormat.output.toString("ascii") === `${format}\n`,
          "object format mismatch",
        );
        evidence.objectFormat = format;
        const indexResponse = decode(await invoke(config, root, "index"));
        expect(indexResponse.status === 0, "index denied");
        const index = parseIndex(indexResponse.output, format);
        evidence.index = index.records;
        const treeResponse = decode(await invoke(config, root, "tree"));
        if (ref === "unborn") {
          expect(
            treeResponse.status !== 0,
            "unborn tree unexpectedly succeeded",
          );
          evidence.tree = "not-applicable-denied";
        } else {
          expect(treeResponse.status === 0, "tree denied");
          const tree = parseTree(treeResponse.output, format);
          evidence.tree = tree.records;
          const ids = [...new Set([...index.objectIds, ...tree.objectIds])];
          const objects = decode(await invoke(config, root, "objects", ids));
          expect(objects.status === 0, "objects denied");
          evidence.objects = parseObjects(objects.output, ids).records;
        }
        if (ref === "unborn" && index.objectIds.length) {
          const objects = decode(
            await invoke(config, root, "objects", [
              ...new Set(index.objectIds),
            ]),
          );
          expect(objects.status === 0, "unborn staged objects denied");
          evidence.objects = parseObjects(objects.output, [
            ...new Set(index.objectIds),
          ]).records;
        } else if (ref === "unborn")
          evidence.objects = "not-applicable-no-object";
        expect(treeDigest(root) === before, "broker mutated repository");
        return evidence;
      });

function hostileRoot(base, name) {
  const parent = join(base, `hostile-${name.replaceAll(".", "-")}`);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  return initRepository(parent, "sha1", "born", "clean");
}
function appendConfig(root, text) {
  writeFileSync(
    join(root, ".git", "config"),
    `${readFileSync(join(root, ".git", "config"), "utf8")}\n${text}\n`,
  );
}
function canaryCommand(base) {
  const path = join(base, "canary-output");
  return { path, command: `sh -c 'printf %s ${CANARY} > ${path}'` };
}

for (const name of hostileVectors)
  row(`hostile:${name}`, async (base) => {
    const root = hostileRoot(base, name),
      canary = canaryCommand(base),
      env = {},
      external = join(base, `${name}.config`);
    const configs = {
      local: `[include]\npath=${external}`,
      include: `[include]\npath=${external}`,
      includeIf: `[includeIf "gitdir:/**"]\npath=${external}`,
      hooksPath: `[core]\nhooksPath=${base}`,
      "filter.process": `[filter "x"]\nprocess=${canary.command}`,
      "filter.clean": `[filter "x"]\nclean=${canary.command}`,
      "filter.smudge": `[filter "x"]\nsmudge=${canary.command}`,
      "diff.external": `[diff "x"]\ncommand=${canary.command}`,
      fsmonitor: `[core]\nfsmonitor=${canary.command}`,
      attributes: `[core]\nattributesFile=${external}`,
      excludes: `[core]\nexcludesFile=${external}`,
      mailmap: `[mailmap]\nfile=${external}`,
      alias: `[alias]\nx=!${canary.command}`,
      credential: `[credential]\nhelper=!${canary.command}`,
      proxy: `[core]\ngitproxy=${canary.command}`,
      SSH: `[core]\nsshCommand=${canary.command}`,
      pager: `[core]\npager=${canary.command}`,
      editor: `[core]\neditor=${canary.command}`,
      "lazy-fetch-promisor": `[extensions]\npartialClone=origin`,
    };
    writeFileSync(external, `[alias]\nx=!${canary.command}\n`);
    if (name === "global") {
      env.HOME = base;
      env.GIT_CONFIG_GLOBAL = external;
    } else if (name === "system") env.GIT_CONFIG_SYSTEM = external;
    else if (name === "askpass") {
      env.GIT_ASKPASS = canary.command;
      env.SSH_ASKPASS = canary.command;
    } else if (name === "replacements") {
      const head = command(config.git, ["-C", root, "rev-parse", "HEAD"]);
      mkdirSync(join(root, ".git", "refs", "replace"), { recursive: true });
      writeFileSync(join(root, ".git", "refs", "replace", head), `${head}\n`);
    } else if (name === "alternates") {
      mkdirSync(join(root, ".git", "objects", "info"), { recursive: true });
      writeFileSync(
        join(root, ".git", "objects", "info", "alternates"),
        `${base}\n`,
      );
    } else appendConfig(root, configs[name]);
    const before = treeDigest(root),
      result = await invoke(config, root, "status", [], { env }),
      decoded = decode(result);
    const sanitizedSuccess =
      name === "global" || name === "system" || name === "askpass";
    expect(
      sanitizedSuccess ? decoded.status === 0 : decoded.status !== 0,
      `${name} outcome was not fail-closed/sanitized`,
    );
    expect(
      !decoded.output.includes(CANARY) && !result.stderr.includes(CANARY),
      `${name} disclosed canary`,
    );
    expect(!existsSync(canary.path), `${name} executed canary`);
    expect(treeDigest(root) === before, `${name} mutated repository`);
    return {
      outcome: sanitizedSuccess ? "sanitized-success" : "denied",
      canary: "absent",
      descendants: "none",
    };
  });

for (const name of topologies)
  row(`topology:${name}`, async (base) => {
    const root = join(base, `topology-${name}`);
    mkdirSync(root);
    if (name === "bare") command(config.git, ["init", "-q", "--bare", root]);
    else {
      const ordinary = initRepository(base, "sha1", "born", "clean");
      if (name === "linked") {
        writeFileSync(
          join(root, ".git"),
          `gitdir: ${join(ordinary, ".git")}\n`,
        );
      } else {
        cpSync(ordinary, root, { recursive: true });
        if (name === "common-dir")
          writeFileSync(join(root, ".git", "commondir"), "..\n");
        if (name === "worktree")
          writeFileSync(join(root, ".git", "gitdir"), `${root}\n`);
        if (name === "submodule") mkdirSync(join(root, ".git", "modules"));
      }
    }
    const decoded = decode(await invoke(config, root, "status"));
    expect(decoded.status !== 0, `${name} topology accepted`);
    return { outcome: "denied" };
  });

for (const name of protocolRows)
  row(`protocol:${name}`, async (base) => {
    const root = initRepository(base, "sha1", "born", "clean");
    let frame = request("status");
    if (name === "bad-magic") {
      frame = Buffer.from(frame);
      frame[0] ^= 1;
    }
    if (name === "truncated") frame = frame.subarray(0, 8);
    if (name === "trailing") frame = Buffer.concat([frame, Buffer.from("x")]);
    if (name === "oversized") {
      frame = Buffer.from(frame);
      frame.writeUInt32BE(16385, 8);
    }
    if (name === "unknown-operation") {
      frame = Buffer.from(frame);
      frame[7] = 9;
    }
    const result = await invoke(config, root, "status", [], { frame });
    expect(
      result.code === 125 &&
        result.stdout.length === 0 &&
        result.stderr.length === 0,
      `${name} protocol accepted`,
    );
    return { outcome: "rejected", descendants: "none" };
  });

for (const name of lifecycleRows)
  row(`lifecycle:${name}`, async (base) => {
    const root = initRepository(base, "sha1", "born", "clean"),
      args = [
        "--protocol-v1",
        "--git",
        config.git,
        "--root",
        root,
        "--runtime-loader",
        config.runtimeLoader,
        ...config.runtimeInputs.flatMap((x) => ["--runtime-input", x]),
      ];
    const child = spawn(config.broker, args, {
      detached: true,
      env: {},
      stdio: ["pipe", "pipe", "pipe"],
    });
    const peerCloseErrors = [];
    child.stdin.on("error", (error) => {
      if (peerCloseErrors.length < 2) peerCloseErrors.push(error.code);
    });
    const closed = new Promise((resolvePromise) =>
      child.once("close", resolvePromise),
    );
    child.stdin.write(
      request("status").subarray(0, name === "partial-request-kill" ? 8 : 15),
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 30));
    process.kill(-child.pid, "SIGKILL");
    await closed;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
    assertNoProcessGroup(child.pid);
    expect(
      peerCloseErrors.length <= 1 &&
        peerCloseErrors.every(
          (code) => code === "EPIPE" || code === "ERR_STREAM_DESTROYED",
        ),
      `unexpected lifecycle stdin error ${peerCloseErrors.join(",")}`,
    );
    return {
      outcome: "killed",
      descendants: "none",
      peerClose: peerCloseErrors[0] ?? "clean-close",
    };
  });

row("rlimits:all", async (base) => {
  const root = initRepository(base, "sha1", "born", "untracked");
  for (let i = 0; i < 6000; i += 1)
    writeFileSync(join(root, `u-${String(i).padStart(5, "0")}.yaml`), "x: y\n");
  const args = [
    "--protocol-v1",
    "--git",
    config.git,
    "--root",
    root,
    "--runtime-loader",
    config.runtimeLoader,
    ...config.runtimeInputs.flatMap((x) => ["--runtime-input", x]),
  ];
  const child = spawn(config.broker, args, {
    detached: true,
    env: {},
    stdio: ["pipe", "pipe", "pipe"],
  });
  const output = [],
    errors = [];
  child.stdout.on("data", (x) => output.push(x));
  child.stderr.on("data", (x) => errors.push(x));
  const closed = new Promise((resolvePromise) =>
    child.once("close", resolvePromise),
  );
  child.stdin.end(request("status"));
  let limits = "";
  for (let attempt = 0; attempt < 500 && !limits; attempt += 1) {
    try {
      const candidate = readFileSync(`/proc/${child.pid}/limits`, "utf8");
      if (/Max cpu time\s+5\s+5/u.test(candidate)) limits = candidate;
    } catch {}
    if (!limits)
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 2));
  }
  await closed;
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  assertNoProcessGroup(child.pid);
  for (const pattern of [
    /Max cpu time\s+5\s+5/u,
    /Max address space\s+268435456\s+268435456/u,
    /Max file size\s+4194304\s+4194304/u,
    /Max open files\s+32\s+32/u,
    /Max processes\s+8\s+8/u,
  ])
    expect(pattern.test(limits), `missing rlimit ${pattern}`);
  const decoded = decode({
    code: 0,
    signal: null,
    stdout: Buffer.concat(output),
    stderr: Buffer.concat(errors),
    stdoutBytes: Buffer.concat(output).length,
    stderrBytes: Buffer.concat(errors).length,
  });
  expect(decoded.status === 0, "rlimit probe operation denied");
  return { limits: "observed-in-proc", descendants: "none" };
});

for (const name of closureRows)
  row(`closure:${name}`, async (base) => {
    const root = initRepository(base, "sha1", "born", "clean"),
      directory = join(base, "closure-dir"),
      link = join(base, "closure-link"),
      fifo = join(base, "closure-fifo");
    mkdirSync(directory, { recursive: true });
    if (!existsSync(link)) symlinkSync(config.runtimeLoader, link);
    if (name === "nonregular") command("mkfifo", [fifo]);
    const overrides = {};
    if (name === "missing-loader") overrides.runtimeLoader = null;
    if (name === "relative-loader") overrides.runtimeLoader = "relative";
    if (name === "duplicate") overrides.runtimeInputs = [config.runtimeLoader];
    if (name === "directory") overrides.runtimeInputs = [directory];
    if (name === "symlink") overrides.runtimeInputs = [link];
    if (name === "nonregular") overrides.runtimeInputs = [fifo];
    if (name === "over-limit")
      overrides.runtimeInputs = Array.from(
        { length: 17 },
        () => config.runtimeInputs[0] ?? config.runtimeLoader,
      );
    const result = await invoke(config, root, "status", [], overrides);
    const acceptedFrame =
      result.code === 0 && result.stdout.length >= HEADER_BYTES;
    if (acceptedFrame)
      expect(decode(result).status !== 0, `${name} closure accepted`);
    else expect(result.code === 125, `${name} unexpected exit`);
    return { outcome: "rejected", descendants: "none" };
  });

const config = parseArguments(process.argv.slice(2));
for (const path of [
  config.broker,
  config.git,
  config.runtimeLoader,
  ...config.runtimeInputs,
])
  expect(
    existsSync(path) && statSync(path).isFile(),
    `missing regular input ${path}`,
  );
const actualRows = [...runners.keys()].sort(),
  expectedRows = [...requiredRows].sort();
expect(
  JSON.stringify(actualRows) === JSON.stringify(expectedRows),
  `mandatory row registry mismatch: expected ${expectedRows.length}, got ${actualRows.length}`,
);
const base = mkdtempSync(join(tmpdir(), "ha-g2-git-"));
chmodSync(base, 0o700);
const results = [];
emit({
  type: "manifest",
  version: 1,
  requiredRows,
  canarySha256: sha(Buffer.from(CANARY)),
  platform: process.platform,
  arch: process.arch,
});
try {
  for (const id of requiredRows) {
    const started = Date.now();
    try {
      const evidence = await runners.get(id)(base);
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
} finally {
  rmSync(base, { recursive: true, force: true });
}
const failed = results.filter((rowResult) => rowResult.status !== "PASSED");
const summary = {
  type: "summary",
  status: failed.length ? "FAILED" : "PASSED",
  required: requiredRows.length,
  executed: results.length,
  passed: results.length - failed.length,
  failed: failed.map((rowResult) => rowResult.id),
};
emit(summary);
if (config.output)
  writeFileSync(
    config.output,
    `${results.map((value) => JSON.stringify(value)).join("\n")}\n${JSON.stringify(summary)}\n`,
    { mode: 0o600 },
  );
if (failed.length || results.length !== requiredRows.length)
  process.exitCode = 1;
