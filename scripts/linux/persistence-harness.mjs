#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statfsSync,
  symlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
const worker = resolve("scripts/linux/persistence-worker.mjs"),
  shimSource = resolve("scripts/linux/persistence-fault-shim.c"),
  probeSource = resolve("scripts/linux/persistence-syscall-probe.c");
const common = [
  ["open64", "fail"],
  ["write", "fail"],
  ["write", "short"],
  ["write", "enospc"],
  ["fsync", "fail"],
  ["close", "fail"],
];
const systems = {
  proposal: [...common, ["rename", "fail"]],
  journal: [...common, ["rename", "fail"]],
  audit: common,
  rotation: [...common, ["rename", "fail"]],
  quarantine: [...common, ["rename", "fail"]],
};
const probes = [
  ["open", "fail"],
  ["open64", "fail"],
  ["openat", "fail"],
  ["openat64", "fail"],
  ["write", "short"],
  ["pwrite", "short"],
  ["writev", "short"],
  ["fsync", "fail"],
  ["fdatasync", "fail"],
  ["rename", "fail"],
  ["renameat", "fail"],
  ["renameat2", "fail"],
  ["close", "fail"],
];
const stages = ["journal_prepared", "effect_committed", "outcome_committed"],
  fixtures = [
    "mode",
    "ownership",
    "symlink",
    "hardlink",
    "nonregular",
    "identity-race",
    "permissions",
    "tmpfs-enospc",
  ];
const requiredRows = [
  ...Object.entries(systems).flatMap(([s, fs]) =>
    fs.map(([c, m]) => `fault:${s}:${c}:${m}`),
  ),
  ...probes.map(([c, m]) => `shim:${c}:${m}`),
  ...stages.map((s) => `kill:${s}`),
  ...fixtures.map((f) => `fixture:${f}`),
];
const rows = new Map();
class UnverifiedError extends Error {}
const expect = (v, m) => {
    if (!v) throw Error(m);
  },
  emit = (v) => process.stdout.write(JSON.stringify(v) + "\n"),
  row = (id, f) => {
    expect(!rows.has(id), "duplicate row " + id);
    rows.set(id, f);
  };
const cfg = { node: process.execPath };
for (let i = 2; i < process.argv.length; i += 2) {
  let f = process.argv[i],
    v = process.argv[i + 1];
  expect(v, "missing " + f);
  if (f === "--node") cfg.node = resolve(v);
  else if (f === "--cc") cfg.cc = v;
  else if (f === "--tmpfs-root") cfg.tmpfsRoot = resolve(v);
  else if (f === "--output") cfg.output = resolve(v);
  else throw Error("unknown " + f);
}
expect(cfg.cc, "missing --cc");
expect(cfg.tmpfsRoot, "missing --tmpfs-root");
const base = mkdtempSync(join(tmpdir(), "ha-g2-persistence-"));
chmodSync(base, 0o700);
const shim = join(base, "fault-shim.so"),
  probe = join(base, "probe");
function compile(a, n) {
  let r = spawnSync(cfg.cc, a, { encoding: "utf8" });
  expect(r.status === 0, n + " compile failed: " + r.stderr);
}
compile(
  [
    "-shared",
    "-fPIC",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    shimSource,
    "-ldl",
    "-o",
    shim,
  ],
  "shim",
);
compile(
  ["-O2", "-Wall", "-Wextra", "-Werror", probeSource, "-o", probe],
  "probe",
);
async function assertNoProcessGroup(pid) {
  for (let i = 0; i < 25; i++) {
    try {
      process.kill(-pid, 0);
    } catch (e) {
      if (e.code === "ESRCH") return;
      throw e;
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  throw Error("worker process group survived completion");
}
function run(action, root, o = {}) {
  return new Promise((yes, no) => {
    let ms = [],
      out = [],
      err = [],
      arm = o.fault && join(root, ".fault-arm"),
      settled = false,
      timeout = false;
    let env = {
      ...process.env,
      HA_OPERATION_ID: o.operationId ?? randomUUID(),
      HA_PROPOSAL_ID: o.proposalId ?? randomUUID(),
    };
    if (o.fault)
      Object.assign(env, {
        LD_PRELOAD: shim,
        HA_FAULT_SYSCALL: o.fault.call,
        HA_FAULT_MODE: o.fault.mode,
        HA_FAULT_NTH: "1",
        HA_FAULT_PROOF: o.proof,
        HA_FAULT_ARM: arm,
        HA_FAULT_ROOT: root,
      });
    let child = spawn(cfg.node, [worker, action, root, o.checkpoint ?? ""], {
      detached: true,
      env,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      ...(o.uid === undefined ? {} : { uid: o.uid, gid: o.gid }),
    });
    let reject = (e) => {
        if (!settled) {
          settled = true;
          no(e);
        }
      },
      push = (a, v) => {
        if (a.reduce((n, b) => n + b.length, 0) < 1048576) a.push(v);
      },
      timer = setTimeout(() => {
        timeout = true;
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
      }, 30000);
    child.stdout.on("data", (v) => push(out, v));
    child.stderr.on("data", (v) => push(err, v));
    child.on("error", reject);
    child.on("message", (m) => {
      ms.push(m);
      try {
        if (m.type === "ready") {
          writeFileSync(arm, "armed", { mode: 0o600 });
          child.send({ type: "arm" });
        }
        if (m.type === "checkpoint" && o.kill)
          process.kill(-child.pid, "SIGKILL");
        o.onMessage?.(m, child);
      } catch (e) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
        reject(e);
      }
    });
    child.on("close", async (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      try {
        await assertNoProcessGroup(child.pid);
        expect(!timeout, action + " timeout");
        settled = true;
        yes({
          code,
          signal,
          messages: ms,
          stderr: Buffer.concat(err).toString(),
        });
      } catch (e) {
        reject(e);
      }
    });
  });
}
function readProof(path) {
  const raw = readFileSync(path);
  const diagnostic = raw.subarray(0, 256).toString("hex");
  expect(
    raw.length > 0 && raw.at(-1) === 0x0a,
    `fault proof is not a complete NDJSON line: bytes=${raw.length} hex=${diagnostic}`,
  );
  const lines = raw.toString("utf8").split("\n");
  expect(lines.pop() === "", "fault proof newline framing is invalid");
  return lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw Error(
        `fault proof line ${index + 1} is invalid JSON: bytes=${raw.length} hex=${diagnostic}; ${String(error?.message ?? error)}`,
      );
    }
  });
}

function durableRecovery(evidence) {
  if (!evidence || typeof evidence !== "object") return evidence;
  const durable = { ...evidence };
  delete durable.healthy;
  return durable;
}

function assertStableRecovery(first, second) {
  expect(
    JSON.stringify(durableRecovery(first)) ===
      JSON.stringify(durableRecovery(second)),
    `second recovery changed durable state: first=${JSON.stringify(first)} second=${JSON.stringify(second)}`,
  );
}

function assertScopedProof(record, root, excluded) {
  expect(
    typeof record.target === "string" &&
      record.target.length > 0 &&
      !isAbsolute(record.target),
    "fault proof target is not sanitized and relative",
  );
  const reconstructed = resolve(root, record.target);
  const fromRoot = relative(root, reconstructed);
  expect(
    fromRoot.length > 0 &&
      !isAbsolute(fromRoot) &&
      fromRoot !== ".." &&
      !fromRoot.startsWith("../"),
    "fault proof target escaped row root",
  );
  const excludedTargets = excluded.map((path) => relative(root, path));
  expect(
    !excludedTargets.includes(fromRoot),
    "fault proof targeted arm or proof plumbing",
  );
  return fromRoot;
}

const done = (r) => r.messages.find((m) => m.type === "complete")?.evidence,
  failed = (r) => r.messages.find((m) => m.type === "failure"),
  dir = (p) => (existsSync(p) ? readdirSync(p).sort() : []),
  state = (root) => ({
    proposals: dir(join(root, "store", "proposals")),
    journals: dir(join(root, "store", "journals")),
    auditBytes: existsSync(join(root, "audit", "phase2.jsonl"))
      ? readFileSync(join(root, "audit", "phase2.jsonl")).length
      : 0,
  });
for (const [s, fs] of Object.entries(systems))
  for (const [c, m] of fs)
    row(`fault:${s}:${c}:${m}`, async () => {
      let root = join(base, `f-${s}-${c}-${m}-${randomUUID()}`),
        proof = join(root, "proof");
      mkdirSync(root, { recursive: true, mode: 0o700 });
      let r = await run(s, root, { fault: { call: c, mode: m }, proof });
      expect(existsSync(proof), "fault proof missing");
      let ps = readProof(proof);
      expect(
        ps.length === 1 &&
          ps[0].syscall === c &&
          ps[0].nth === 1 &&
          ps[0].mode === m,
        "wrong nth syscall proof",
      );
      assertScopedProof(ps[0], root, [proof, join(root, ".fault-arm")]);
      let retry = m === "short" && s !== "quarantine",
        f = failed(r);
      expect(
        retry
          ? r.code === 0 && r.messages.some((x) => x.type === "complete")
          : r.code !== 0 && f,
        retry ? "short write was not retried" : "fault did not fail closed",
      );
      let immediate = state(root),
        a = await run("inspect-" + s, root),
        b = await run("inspect-" + s, root),
        x = done(a),
        y = done(b);
      expect(a.code === 0 && b.code === 0, "recovery failed");
      assertStableRecovery(x, y);
      if (s === "quarantine")
        expect(f?.latched === true, "quarantine fault did not latch unhealthy");
      if (retry && s === "proposal")
        expect(x.proposals.length === 1, "proposal missing");
      if (retry && s === "journal")
        expect(x.journals.length === 1, "journal missing");
      if (retry && s === "audit") expect(x.records === 1, "audit missing");
      if (retry && s === "rotation") expect(x.records >= 1, "rotation missing");
      return {
        proof: ps[0],
        immediate,
        first: x,
        second: y,
        latched: f?.latched ?? false,
        diagnosticsSanitized: !r.stderr.includes(root),
      };
    });
for (const [c, m] of probes)
  row(`shim:${c}:${m}`, async () => {
    let root = join(base, `p-${c}-${m}`),
      proof = join(root, "proof"),
      arm = join(root, "arm");
    mkdirSync(root, { mode: 0o700 });
    let r = spawnSync(probe, [c, join(root, "target"), arm], {
      env: {
        ...process.env,
        LD_PRELOAD: shim,
        HA_FAULT_SYSCALL: c,
        HA_FAULT_MODE: m,
        HA_FAULT_NTH: "1",
        HA_FAULT_PROOF: proof,
        HA_FAULT_ARM: arm,
        HA_FAULT_ROOT: root,
      },
    });
    expect(r.status === 0, c + " probe missed " + m);
    let ps = readProof(proof);
    expect(
      ps.length === 1 &&
        ps[0].syscall === c &&
        ps[0].nth === 1 &&
        ps[0].mode === m,
      c + " proof mismatch",
    );
    assertScopedProof(ps[0], root, [proof, arm]);
    return { proof: ps[0] };
  });
for (const stage of stages)
  row("kill:" + stage, async () => {
    let root = join(base, "k-" + stage),
      operationId = randomUUID(),
      proposalId = randomUUID(),
      k = await run("transaction", root, {
        checkpoint: stage,
        kill: true,
        operationId,
        proposalId,
      });
    expect(k.signal === "SIGKILL", "worker not killed");
    let cps = k.messages.filter((m) => m.type === "checkpoint");
    expect(
      cps.length === 1 &&
        cps[0].stage === stage &&
        cps[0].operationId === operationId,
      "checkpoint mismatch",
    );
    let immediate = state(root);
    expect(
      immediate.proposals.length === (stage === "journal_prepared" ? 0 : 1) &&
        immediate.journals.length === 1 &&
        immediate.auditBytes > 0,
      "bad immediate state",
    );
    let a = await run("recover-transaction", root, { operationId, proposalId }),
      b = await run("recover-transaction", root, { operationId, proposalId }),
      x = done(a),
      y = done(b);
    expect(
      a.code === 0 && b.code === 0 && JSON.stringify(x) === JSON.stringify(y),
      "recovery not idempotent",
    );
    let e = {
      journal_prepared: [0, "failure"],
      effect_committed: [1, "reconciled"],
      outcome_committed: [1, "success"],
    }[stage];
    expect(
      x.effects === e[0] &&
        x.outcomes === 1 &&
        x.outcomeResult === e[1] &&
        x.journals === 0,
      "not exactly one effect/outcome",
    );
    return { checkpoint: cps[0], immediate, first: x, second: y };
  });
async function denied(action, root, o = {}) {
  let r = await run(action, root, o);
  expect(r.code !== 0 && failed(r), action + " accepted");
  return { failure: failed(r), diagnosticsSanitized: !r.stderr.includes(root) };
}
for (const name of fixtures)
  row("fixture:" + name, async () => {
    if (name === "identity-race")
      throw new UnverifiedError(
        "no deterministic existing-API hook exists between protected-file identity checks",
      );
    if (name === "tmpfs-enospc") {
      let st = statfsSync(cfg.tmpfsRoot),
        total = st.blocks * st.bsize;
      expect(st.type === 0x01021994, "--tmpfs-root is not tmpfs");
      expect(total <= 134217728, "--tmpfs-root exceeds 128 MiB safety bound");
      let root = join(cfg.tmpfsRoot, "ha-g2-" + randomUUID()),
        fill = join(cfg.tmpfsRoot, ".fill-" + randomUUID()),
        enospc = false;
      mkdirSync(root, { mode: 0o700 });
      try {
        let r = await run("proposal-paused", root, {
          onMessage(m, ch) {
            if (m.type !== "fixture-ready") return;
            let fd = openSync(fill, "wx", 0o600),
              buf = Buffer.alloc(65536);
            try {
              for (let n = 0; n <= total; n += buf.length) writeSync(fd, buf);
            } catch (e) {
              if (e.code !== "ENOSPC") throw e;
              enospc = true;
            } finally {
              closeSync(fd);
            }
            ch.send({ type: "continue" });
          },
        });
        expect(
          enospc && r.code !== 0 && failed(r),
          "real ENOSPC did not fail proposal",
        );
        return {
          tmpfsType: st.type,
          totalBytes: total,
          realEnospc: true,
          failure: failed(r),
        };
      } finally {
        rmSync(fill, { force: true });
        rmSync(root, { recursive: true, force: true });
      }
    }
    let root = join(base, "fixture-" + name);
    mkdirSync(root, { mode: 0o700 });
    if (name === "mode") {
      mkdirSync(join(root, "store"), { mode: 0o755 });
      return { outcome: "denied", ...(await denied("proposal", root)) };
    }
    if (name === "ownership") {
      if (process.getuid?.() !== 0)
        throw new UnverifiedError("ownership fixture requires Linux root");
      mkdirSync(join(root, "store"), { mode: 0o700 });
      chownSync(join(root, "store"), 65534, 65534);
      return { outcome: "denied", ...(await denied("proposal", root)) };
    }
    if (name === "symlink") {
      let target = join(base, "target-" + randomUUID());
      mkdirSync(target, { mode: 0o700 });
      symlinkSync(target, join(root, "store"), "dir");
      return { outcome: "denied", ...(await denied("proposal", root)) };
    }
    if (name === "hardlink") {
      expect((await run("proposal", root)).code === 0, "seed failed");
      let outside = join(root, "outside");
      writeFileSync(outside, "{}", { mode: 0o600 });
      linkSync(
        outside,
        join(root, "store", "proposals", randomUUID() + ".json"),
      );
      let first = await run("inspect-proposal", root),
        second = await run("inspect-proposal", root),
        x = done(first),
        y = done(second);
      expect(
        first.code === 0 &&
          second.code === 0 &&
          x.healthy === false &&
          y.healthy === false &&
          x.proposals.length === 2 &&
          y.proposals.length === 2 &&
          x.quarantine.length === 0 &&
          y.quarantine.length === 0,
        `hard link was not persistently denied and latched: first=${JSON.stringify(x)} second=${JSON.stringify(y)}`,
      );
      assertStableRecovery(x, y);
      return { outcome: "denied-latched", first: x, second: y };
    }
    if (name === "nonregular") {
      writeFileSync(join(root, "store"), "file", { mode: 0o600 });
      return { outcome: "denied", ...(await denied("proposal", root)) };
    }
    if (name === "permissions") {
      if (process.getuid?.() !== 0)
        throw new UnverifiedError(
          "unprivileged child fixture requires Linux root",
        );
      chmodSync(base, 0o755);
      chmodSync(root, 0o755);
      mkdirSync(join(root, "store"), { mode: 0o700 });
      return {
        outcome: "denied",
        ...(await denied("proposal", root, { uid: 65534, gid: 65534 })),
      };
    }
    throw Error("unhandled fixture " + name);
  });
expect(
  JSON.stringify([...rows.keys()].sort()) ===
    JSON.stringify([...requiredRows].sort()),
  "mandatory persistence row registry mismatch",
);
emit({ type: "manifest", version: 1, requiredRows, shim, compiler: cfg.cc });
let results = [];
try {
  for (const id of requiredRows) {
    let at = Date.now();
    try {
      let evidence = await rows.get(id)(),
        r = {
          type: "row",
          id,
          status: "PASSED",
          durationMs: Date.now() - at,
          evidence,
        };
      results.push(r);
      emit(r);
    } catch (e) {
      let r = {
        type: "row",
        id,
        status: e instanceof UnverifiedError ? "UNVERIFIED" : "FAILED",
        durationMs: Date.now() - at,
        error: String(e?.message ?? e),
      };
      results.push(r);
      emit(r);
    }
  }
} finally {
  rmSync(base, { recursive: true, force: true });
}
let bad = results.filter((x) => x.status === "FAILED"),
  uv = results.filter((x) => x.status === "UNVERIFIED"),
  summary = {
    type: "summary",
    status: bad.length ? "FAILED" : uv.length ? "BLOCKED" : "PASSED",
    required: requiredRows.length,
    executed: results.length,
    failed: bad.map((x) => x.id),
    unverified: uv.map((x) => x.id),
  };
emit(summary);
if (cfg.output)
  writeFileSync(
    cfg.output,
    results.map(JSON.stringify).join("\n") +
      "\n" +
      JSON.stringify(summary) +
      "\n",
    { mode: 0o600 },
  );
if (bad.length || uv.length) process.exitCode = 1;
