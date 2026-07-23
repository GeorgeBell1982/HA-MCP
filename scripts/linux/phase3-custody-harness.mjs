#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statfsSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CUSTODY_EVIDENCE_IDS = Object.freeze([
  "N001 env_linux",
  "N002 env_arch",
  "N003 env_libc",
  "N004 env_compiler",
  "N005 env_uid0",
  "N006 env_filesystem_recorded_supported",
  "N007 uid0_acquire",
  "N008 nonroot_acquire_via_uid_drop",
  "N009 same_root_contention",
  "N010 different_root_independence",
  "N011 clean_release_handoff",
  "N012 helper_sigkill_reacquire",
  "N013 holder_parent_death",
  "N014 waiter_parent_death",
  "N015 root_replaced_while_waiting_rejected",
  "N016 symlink_root_rejected",
  "N017 nondirectory_root_rejected",
  "N018 unsafe_mode_rejected",
  "N019 wrong_owner_rejected",
  "N020 unsupported_filesystem_rejected",
  "N021 zero_eof_abandonment",
  "N022 malformed_control",
  "N023 duplicate_control",
  "N024 trailing_control",
  "N025 phase3n_remediation_api_mechanics",
]);

const MANIFEST = Object.freeze({
  type: "manifest",
  version: 1,
  requiredRows: CUSTODY_EVIDENCE_IDS,
  prerequisites: Object.freeze(["linux", "uid0", "compiler"]),
  claim: "conditional-advisory-custody-evidence-only",
});
const SUPPORTED_FILESYSTEMS = new Map([
  [0x01021994, "tmpfs"],
  [0xef53, "ext2_ext3_ext4"],
  [0x58465342, "xfs"],
  [0x9123683e, "btrfs"],
  [0x794c7630, "overlayfs"],
]);
const FRAME_PREFIX = "phase3-approval-custody-v1";
const READY_PATTERN =
  /^phase3-approval-custody-v1\tready\tdev=(?:0|[1-9][0-9]{0,19})\tino=(?:0|[1-9][0-9]{0,19})\tmode=(?:0|[1-9][0-9]{0,19})\tuid=(?:0|[1-9][0-9]{0,19})\tgid=(?:0|[1-9][0-9]{0,19})\tnlink=(?:0|[1-9][0-9]{0,19})\tctime_sec=(?:0|[1-9][0-9]{0,19})\tctime_nsec=(?:0|[1-9][0-9]{0,8})\tfs_type=(?:0|[1-9][0-9]{0,19})\n$/u;
const STARTUP_TIMEOUT_MS = 5_000;
const CLOSE_TIMEOUT_MS = 5_000;
const CONTENTION_PROBE_MS = 150;
const PARENT_DEATH_TIMEOUT_MS = 5_000;
const MAX_STDOUT_BYTES = 512;
const MAX_STDERR_BYTES = 1024;
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..", "..");
const moduleRoot = process.env.HA_PHASE3_CUSTODY_MODULE_ROOT
  ? resolve(process.env.HA_PHASE3_CUSTODY_MODULE_ROOT)
  : repositoryRoot;
const sourcePath = join(
  repositoryRoot,
  "src",
  "phase3",
  "native",
  "approval-custody.c",
);
let workRoot;
let helperPath;
let evidenceRoot;
let rows;
let environment;
let prerequisitesReady = true;
let testedFilesystem;

async function main() {
  workRoot = mkdtempSync(join(tmpdir(), "phase3-custody-native-"));
  chmodSync(workRoot, 0o755);
  helperPath = join(workRoot, "approval-custody");
  evidenceRoot = join(workRoot, "evidence");
  rows = [];
  environment = {
    kernel: "",
    arch: process.arch,
    libc: "",
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    filesystemMagic: "",
    mount: "",
    compiler: "",
    helperSha256: "",
  };
  prerequisitesReady = true;
  testedFilesystem = undefined;

  process.stdout.write(`${JSON.stringify(MANIFEST)}\n`);

  try {
    await evidence("N001 env_linux", async () => {
      if (process.platform !== "linux") throw new Error("linux required");
      environment.kernel = readFileSync(
        "/proc/sys/kernel/osrelease",
        "utf8",
      ).trim();
      return { kernel: environment.kernel };
    });
    await evidence("N002 env_arch", async () => {
      if (!["x64", "arm64"].includes(process.arch))
        throw new Error("unsupported architecture");
      return { arch: process.arch };
    });
    await evidence("N003 env_libc", async () => {
      environment.libc = detectLibc();
      if (!environment.libc) throw new Error("libc unavailable");
      return { libc: environment.libc };
    });
    await evidence("N004 env_compiler", async () => {
      const compiled = compileHelper();
      environment.compiler = compiled.compiler;
      environment.helperSha256 = hashFile(helperPath);
      return {
        compiler: environment.compiler,
        helperSha256: environment.helperSha256,
        hardening: compiled.hardening,
      };
    });
    await evidence("N005 env_uid0", async () => {
      if (process.getuid?.() !== 0) throw new Error("UID 0 required");
      return { uid: 0 };
    });
    await evidence("N006 env_filesystem_recorded_supported", async () => {
      mkdirPrivate(evidenceRoot);
      chmodSync(evidenceRoot, 0o755);
      const stats = statfsSync(evidenceRoot);
      const magic = Number(stats.type) >>> 0;
      testedFilesystem = SUPPORTED_FILESYSTEMS.get(magic);
      environment.filesystemMagic = `0x${magic.toString(16)}`;
      environment.mount = mountFor(evidenceRoot);
      if (!testedFilesystem) throw new Error("unsupported evidence filesystem");
      return {
        magic: environment.filesystemMagic,
        family: testedFilesystem,
        mount: environment.mount,
      };
    });

    prerequisitesReady = rows
      .slice(0, 6)
      .every((row) => row.status === "PASSED");
    await nativeEvidence("N007 uid0_acquire", async () => {
      const root = privateRoot("uid0");
      const holder = await startHelper(root);
      assertReady(holder.frame);
      await releaseHelper(holder, Buffer.from([0x52]), 0);
      return { frame: "ready", release: 0 };
    });
    await nativeEvidence("N008 nonroot_acquire_via_uid_drop", async () => {
      const root = privateRoot("nonroot");
      chownSync(root, 65534, 65534);
      const holder = await startHelper(root, { uid: 65534 });
      assertReady(holder.frame);
      await releaseHelper(holder, Buffer.from([0x52]), 0);
      return { uid: 65534, frame: "ready" };
    });
    await nativeEvidence("N009 same_root_contention", async () => {
      const root = privateRoot("contention");
      const first = await startHelper(root);
      const secondStart = startHelper(root);
      const premature = await settlesWithin(secondStart, CONTENTION_PROBE_MS);
      if (premature) throw new Error("same-root waiter did not block");
      await releaseHelper(first, Buffer.from([0x52]), 0);
      const second = await secondStart;
      assertReady(second.frame);
      await releaseHelper(second, Buffer.from([0x52]), 0);
      return { blockedMs: CONTENTION_PROBE_MS };
    });
    await nativeEvidence("N010 different_root_independence", async () => {
      const left = await startHelper(privateRoot("left"));
      const right = await startHelper(privateRoot("right"));
      assertReady(left.frame);
      assertReady(right.frame);
      await Promise.all([
        releaseHelper(left, Buffer.from([0x52]), 0),
        releaseHelper(right, Buffer.from([0x52]), 0),
      ]);
      return { concurrent: true };
    });
    await nativeEvidence("N011 clean_release_handoff", async () => {
      const root = privateRoot("handoff");
      const first = await startHelper(root);
      await releaseHelper(first, Buffer.from([0x52]), 0);
      const second = await startHelper(root);
      await releaseHelper(second, Buffer.from([0x52]), 0);
      return { acquisitions: 2 };
    });
    await nativeEvidence("N012 helper_sigkill_reacquire", async () => {
      const root = privateRoot("sigkill");
      const first = await startHelper(root);
      first.child.kill("SIGKILL");
      const killed = await waitClose(first.child);
      if (killed.signal !== "SIGKILL") throw new Error("SIGKILL not observed");
      const second = await startHelper(root);
      await releaseHelper(second, Buffer.from([0x52]), 0);
      return { reacquired: true };
    });
    await nativeEvidence("N013 holder_parent_death", async () => {
      const root = privateRoot("holder-parent");
      const parent = await startParentedHelper(root);
      parent.parent.kill("SIGKILL");
      await waitClose(parent.parent);
      await waitForProcAbsence(parent.helperPid);
      const replacement = await startHelper(root);
      await releaseHelper(replacement, Buffer.from([0x52]), 0);
      return { helperTerminated: true, reacquired: true };
    });
    await nativeEvidence("N014 waiter_parent_death", async () => {
      const root = privateRoot("waiter-parent");
      const holder = await startHelper(root);
      const waiter = await startParentedHelper(root, { expectReady: false });
      await delay(CONTENTION_PROBE_MS);
      waiter.parent.kill("SIGKILL");
      await waitClose(waiter.parent);
      await waitForProcAbsence(waiter.helperPid);
      await releaseHelper(holder, Buffer.from([0x52]), 0);
      return { waiterTerminated: true };
    });
    await nativeEvidence(
      "N015 root_replaced_while_waiting_rejected",
      async () => {
        const root = privateRoot("replace-root");
        const oldRoot = `${root}.old`;
        const holder = await startHelper(root);
        const module = await import(
          pathToFileURL(
            join(moduleRoot, "dist", "phase3", "approvalCustody.js"),
          ).href
        );
        const provider = module.createLinuxPhase3ApprovalCustodyProvider({
          helperPath,
          operationTimeoutMs: 2_000,
          terminationGraceMs: 500,
        });
        const pending = provider(root);
        await delay(CONTENTION_PROBE_MS);
        renameSync(root, oldRoot);
        mkdirPrivate(root);
        await releaseHelper(holder, Buffer.from([0x52]), 0);
        let rejected = false;
        try {
          await pending;
        } catch (error) {
          rejected = error?.code === "protocol";
        }
        if (!rejected) throw new Error("replacement was not rejected");
        return { classification: "protocol" };
      },
    );
    await nativeEvidence("N016 symlink_root_rejected", async () => {
      const target = privateRoot("symlink-target");
      const link = join(workRoot, "symlink-root");
      symlinkSync(target, link, "dir");
      const result = await startupFailure(link);
      assertFailure(result, "root_open_failed", 66);
      return { code: "root_open_failed", exit: 66 };
    });
    await nativeEvidence("N017 nondirectory_root_rejected", async () => {
      const path = join(workRoot, "not-directory");
      writeFileSync(path, "", { mode: 0o600 });
      const result = await startupFailure(path);
      assertFailure(result, "root_open_failed", 66);
      return { code: "root_open_failed", exit: 66 };
    });
    await nativeEvidence("N018 unsafe_mode_rejected", async () => {
      const root = privateRoot("unsafe");
      chmodSync(root, 0o755);
      const result = await startupFailure(root);
      assertFailure(result, "root_unsafe", 66);
      return { code: "root_unsafe", exit: 66 };
    });
    await nativeEvidence("N019 wrong_owner_rejected", async () => {
      const root = privateRoot("wrong-owner");
      chownSync(root, 65534, 65534);
      const result = await startupFailure(root);
      assertFailure(result, "root_unsafe", 66);
      return { code: "root_unsafe", exit: 66 };
    });
    await nativeEvidence("N020 unsupported_filesystem_rejected", async () => {
      const result = await startupFailure("/proc");
      assertFailure(result, "filesystem_unsupported", 67);
      return {
        frame: `${FRAME_PREFIX}\tfailure\tcode=filesystem_unsupported\\n`,
        exit: 67,
      };
    });
    await nativeEvidence("N021 zero_eof_abandonment", async () => {
      return await controlEvidence("zero", Buffer.alloc(0), 70);
    });
    await nativeEvidence("N022 malformed_control", async () => {
      return await controlEvidence("malformed", Buffer.from([0x51]), 71);
    });
    await nativeEvidence("N023 duplicate_control", async () => {
      return await controlEvidence("duplicate", Buffer.from([0x52, 0x52]), 71);
    });
    await nativeEvidence("N024 trailing_control", async () => {
      return await controlEvidence("trailing", Buffer.from([0x52, 0x00]), 71);
    });
    await nativeEvidence("N025 phase3n_remediation_api_mechanics", async () => {
      const root = privateRoot("phase3n");
      const custodyModule = await import(
        pathToFileURL(join(moduleRoot, "dist", "phase3", "approvalCustody.js"))
          .href
      );
      const durableModule = await import(
        pathToFileURL(join(moduleRoot, "dist", "phase3", "durableApproval.js"))
          .href
      );
      const provider = custodyModule.createLinuxPhase3ApprovalCustodyProvider({
        helperPath,
        operationTimeoutMs: 2_000,
        terminationGraceMs: 500,
      });
      const store = new durableModule.DurablePhase3ApprovalGrants(
        root,
        Buffer.alloc(32, 0x4e),
        { acquireExclusiveRootCustody: provider },
      );
      let rejected = false;
      try {
        await store.remediateStaleStages();
      } catch (error) {
        rejected =
          error instanceof Error &&
          error.message === "Approval stale-stage remediation failed";
      } finally {
        await store.close();
      }
      if (!rejected) throw new Error("Phase 3N mechanics did not reject");
      const handoff = await startHelper(root);
      await releaseHelper(handoff, Buffer.from([0x52]), 0);
      return { acquisition: true, release: true, remediationEffect: false };
    });
  } finally {
    const registryValid =
      rows.length === CUSTODY_EVIDENCE_IDS.length &&
      rows.every(
        (row, index) =>
          row.id === CUSTODY_EVIDENCE_IDS[index] &&
          CUSTODY_EVIDENCE_IDS.includes(row.id),
      ) &&
      new Set(rows.map((row) => row.id)).size === rows.length;
    const allPassed =
      registryValid && rows.every((row) => row.status === "PASSED");
    const filesystemFamilies = {};
    for (const family of SUPPORTED_FILESYSTEMS.values())
      filesystemFamilies[family] =
        family === testedFilesystem && allPassed
          ? "native_tested"
          : prerequisitesReady
            ? "permitted"
            : "UNVERIFIED";
    const summary = {
      type: "summary",
      status: allPassed ? "PASSED" : "FAILED",
      totals: {
        required: CUSTODY_EVIDENCE_IDS.length,
        passed: rows.filter((row) => row.status === "PASSED").length,
        nonpassed: rows.filter((row) => row.status !== "PASSED").length,
      },
      registryValid,
      environment,
      filesystemFamilies,
    };
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    rmSync(workRoot, { recursive: true, force: true });
    if (!allPassed) process.exitCode = 1;
  }
}

async function evidence(id, operation) {
  let status = "PASSED";
  let details;
  try {
    details = await operation();
  } catch (error) {
    status = "FAILED";
    details = { reason: safeReason(error) };
  }
  const row = { type: "evidence", id, status, evidence: details };
  rows.push(row);
  process.stdout.write(`${JSON.stringify(row)}\n`);
}

async function nativeEvidence(id, operation) {
  if (!prerequisitesReady) {
    const row = {
      type: "evidence",
      id,
      status: "BLOCKED",
      evidence: { reason: "native prerequisites failed" },
    };
    rows.push(row);
    process.stdout.write(`${JSON.stringify(row)}\n`);
    return;
  }
  await evidence(id, operation);
}

function compileHelper() {
  const compiler = process.env.CC ?? "cc";
  const hardening = [
    "-std=c17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wformat=2",
    "-Wshadow",
    "-Wstrict-prototypes",
    "-Wmissing-prototypes",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=3",
    "-fstack-protector-strong",
    "-fPIE",
    "-pie",
    "-Wl,-z,relro,-z,now",
  ];
  const version = spawnSync(compiler, ["--version"], {
    encoding: "utf8",
    timeout: 10_000,
  });
  if (version.status !== 0) throw new Error("compiler unavailable");
  const compiled = spawnSync(
    compiler,
    [...hardening, sourcePath, "-o", helperPath],
    { encoding: "utf8", timeout: 30_000 },
  );
  if (compiled.status !== 0)
    throw new Error(`strict compile failed: ${bounded(compiled.stderr)}`);
  chmodSync(helperPath, 0o755);
  const helper = lstatSync(helperPath);
  if (!helper.isFile() || helper.nlink !== 1 || helper.uid !== 0)
    throw new Error("compiled helper metadata unsafe");
  return {
    compiler: bounded(version.stdout.split(/\r?\n/u)[0] ?? ""),
    hardening,
  };
}

export function detectLibc(boundaries = {}) {
  const candidates = [];
  const record = (family, evidence) => {
    candidates.push({ family, evidence: bounded(evidence) });
  };
  const report = Object.hasOwn(boundaries, "report")
    ? boundaries.report
    : process.report?.getReport?.();
  const glibc = report?.header?.glibcVersionRuntime;
  if (typeof glibc === "string" && glibc.trim())
    record("glibc", `Node report ${glibc.trim()}`);
  const runLdd =
    boundaries.runLdd ??
    (() =>
      spawnSync("ldd", ["--version"], {
        encoding: "utf8",
        timeout: 5_000,
      }));
  let ldd;
  try {
    ldd = runLdd();
  } catch {
    ldd = undefined;
  }
  if (ldd?.status === 0) {
    const combined = `${ldd.stdout ?? ""}\n${ldd.stderr ?? ""}`;
    const first = combined
      .split(/\r?\n/u)
      .find((line) => line.trim())
      ?.trim();
    if (first) {
      if (/\bmusl\b/iu.test(combined)) record("musl", `ldd ${first}`);
      if (/\bglibc\b|GNU C Library|GNU libc/iu.test(combined))
        record("glibc", `ldd ${first}`);
    }
  }
  const loadedLibraries =
    boundaries.loadedLibraries ??
    (Array.isArray(report?.sharedObjects) ? report.sharedObjects : []);
  for (const library of loadedLibraries) {
    if (typeof library !== "string") continue;
    if (/\/(?:ld-musl|libc\.musl)[^/]*$/iu.test(library))
      record("musl", `loaded-library ${library}`);
    if (/\/(?:libc-[0-9.]+\.so|libc\.so\.6)$/iu.test(library))
      record("glibc", `loaded-library ${library}`);
  }
  const families = new Set(candidates.map((candidate) => candidate.family));
  if (families.size !== 1) return undefined;
  const selected = candidates[0];
  return selected ? `${selected.family} ${selected.evidence}` : undefined;
}

function privateRoot(name) {
  const path = join(evidenceRoot, name);
  mkdirPrivate(path);
  return path;
}

function mkdirPrivate(path) {
  mkdirSync(path, { mode: 0o700, recursive: false });
  chmodSync(path, 0o700);
}

async function startHelper(root, options = {}) {
  const child = spawn(helperPath, [root, String(process.pid)], {
    cwd: "/",
    env: {},
    shell: false,
    detached: false,
    stdio: ["pipe", "pipe", "pipe"],
    ...(options.uid === undefined ? {} : { uid: options.uid }),
  });
  const startup = await readStartup(child);
  if (startup.stderr.length !== 0) {
    child.kill("SIGKILL");
    throw new Error("helper emitted stderr");
  }
  if (!READY_PATTERN.test(startup.frame)) {
    const closed = await waitClose(child);
    throw new Error(
      `helper did not become ready: ${bounded(startup.frame)} exit=${closed.code}`,
    );
  }
  return { child, frame: startup.frame, stdout: startup.stdout };
}

async function startupFailure(root) {
  const child = spawn(helperPath, [root, String(process.pid)], {
    cwd: "/",
    env: {},
    shell: false,
    detached: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const startup = await readStartup(child);
  const closed = await waitClose(child);
  return {
    frame: startup.frame,
    stderr: startup.stderr,
    code: closed.code,
    signal: closed.signal,
  };
}

function assertFailure(result, code, exitCode) {
  const expected = `${FRAME_PREFIX}\tfailure\tcode=${code}\n`;
  if (
    result.frame !== expected ||
    result.stderr.length !== 0 ||
    result.code !== exitCode ||
    result.signal !== null
  )
    throw new Error("startup failure frame or exit mismatch");
}

function assertReady(frame) {
  if (!READY_PATTERN.test(frame)) throw new Error("ready frame mismatch");
}

async function releaseHelper(holder, control, expectedExit) {
  holder.child.stdin.end(control);
  const closed = await waitClose(holder.child);
  const trailing = holder.stdout();
  if (
    closed.code !== expectedExit ||
    closed.signal !== null ||
    trailing.stdout.length !== 0 ||
    trailing.stderr.length !== 0
  )
    throw new Error("release result mismatch");
}

async function controlEvidence(name, control, expectedExit) {
  const root = privateRoot(`control-${name}`);
  const holder = await startHelper(root);
  await releaseHelper(holder, control, expectedExit);
  return { control: name, exit: expectedExit };
}

function readStartup(child) {
  return new Promise((resolvePromise, rejectPromise) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      rejectPromise(new Error("startup timeout"));
    }, STARTUP_TIMEOUT_MS);
    const finish = (frame) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise({
        frame,
        stderr,
        stdout: () => {
          const remaining = stdout;
          const errors = stderr;
          stdout = Buffer.alloc(0);
          stderr = Buffer.alloc(0);
          return { stdout: remaining, stderr: errors };
        },
      });
    };
    const onStdout = (chunk) => {
      stdout = Buffer.concat([stdout, Buffer.from(chunk)]);
      if (stdout.length > MAX_STDOUT_BYTES) {
        finish("");
        return;
      }
      const newline = stdout.indexOf(0x0a);
      if (newline >= 0) {
        const frame = stdout.subarray(0, newline + 1).toString("ascii");
        stdout = stdout.subarray(newline + 1);
        finish(frame);
      }
    };
    child.stdout.on("data", onStdout);
    child.stderr.on("data", (chunk) => {
      stderr = Buffer.concat([stderr, Buffer.from(chunk)]);
      if (stderr.length > MAX_STDERR_BYTES) finish("");
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      const frame = stdout.toString("ascii");
      stdout = Buffer.alloc(0);
      finish(frame);
      child.__phase3EarlyClose = { code, signal };
    });
  });
}

function waitClose(child) {
  if (child.__phase3EarlyClose)
    return Promise.resolve(child.__phase3EarlyClose);
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectPromise(new Error("close timeout"));
    }, CLOSE_TIMEOUT_MS);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ code, signal });
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
  });
}

async function startParentedHelper(root, options = {}) {
  const program = [
    'import { spawn } from "node:child_process";',
    `const child = spawn(${JSON.stringify(helperPath)}, [${JSON.stringify(root)}, String(process.pid)], {cwd:"/",env:{},shell:false,detached:false,stdio:["pipe","pipe","pipe"]});`,
    "process.stdout.write(`${JSON.stringify({pid:child.pid})}\\n`);",
    "child.stdout.pipe(process.stdout);",
    "child.stderr.pipe(process.stderr);",
    "setInterval(() => {}, 1000);",
  ].join("");
  const parent = spawn(
    process.execPath,
    ["--input-type=module", "-e", program],
    {
      cwd: "/",
      env: {},
      shell: false,
      detached: false,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const lines = lineReader(parent.stdout);
  const identity = JSON.parse(await lines.next(STARTUP_TIMEOUT_MS));
  if (!Number.isSafeInteger(identity.pid) || identity.pid <= 0)
    throw new Error("parented helper PID invalid");
  if (options.expectReady !== false) {
    const frame = `${await lines.next(STARTUP_TIMEOUT_MS)}\n`;
    assertReady(frame);
  }
  return { parent, helperPid: identity.pid };
}

function lineReader(stream) {
  let buffer = "";
  const waiting = [];
  stream.on("data", (chunk) => {
    buffer += Buffer.from(chunk).toString("utf8");
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0 || waiting.length === 0) return;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      waiting.shift().resolve(line);
    }
  });
  return {
    next(timeoutMs) {
      const newline = buffer.indexOf("\n");
      if (newline >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        return Promise.resolve(line);
      }
      return new Promise((resolvePromise, rejectPromise) => {
        const waiter = {
          resolve: (line) => {
            clearTimeout(timer);
            resolvePromise(line);
          },
        };
        const timer = setTimeout(() => {
          const index = waiting.indexOf(waiter);
          if (index >= 0) waiting.splice(index, 1);
          rejectPromise(new Error("line timeout"));
        }, timeoutMs);
        waiting.push(waiter);
      });
    },
  };
}

async function waitForProcAbsence(pid) {
  const path = `/proc/${pid}`;
  const deadline = Date.now() + PARENT_DEATH_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!existsSync(path)) return;
    await delay(20);
  }
  throw new Error("helper absence unproved");
}

async function settlesWithin(promise, milliseconds) {
  return await Promise.race([
    promise.then(
      () => true,
      () => true,
    ),
    delay(milliseconds).then(() => false),
  ]);
}

function mountFor(path) {
  const normalized = resolve(path);
  const entries = readFileSync("/proc/self/mountinfo", "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const fields = line.split(" ");
      return fields[4]?.replaceAll("\\040", " ") ?? "";
    })
    .filter(
      (mount) => normalized === mount || normalized.startsWith(`${mount}/`),
    )
    .sort((left, right) => right.length - left.length);
  return entries[0] ?? "unknown";
}

function hashFile(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function safeReason(error) {
  if (!(error instanceof Error)) return "native evidence failed";
  return bounded(error.message.replaceAll(workRoot, "<work>"));
}

function bounded(value) {
  return String(value)
    .replaceAll(/[\r\n\t]+/gu, " ")
    .slice(0, 256);
}

async function delay(milliseconds) {
  await new Promise((resolvePromise) =>
    setTimeout(resolvePromise, milliseconds),
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
)
  await main();
