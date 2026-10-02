# Recovery

- Audit unavailable: stop the service, restore writable protected `/data`, then restart. Calls fail closed.
- Token expired: replace the local secret or restart the add-on so Supervisor injects the current runtime token. Diagnostics never print it.
- HTTP identity changed: do not bypass pinning; use authenticated ingress to download and verify the new public certificate, then update bridge pins.
- Phase 2 activation failure: the runtime falls back to Phase 1 tools with sanitized activation diagnostics. Investigate the failed artifact, protected state, secrets, or catalog gate before expecting repository/proposal tools.
- Apply, reload, rollback, and crash recovery are not exposed by the MCP runtime. The isolated Phase 3 components and POC do not provide production recovery authority.

Before any later write phase, create and test a Home Assistant backup and retain the global mutation kill switch.

## Project context as of 2026-10-02

Phase 3 scope was narrowed following the independent proportionality review on the
same date. The direct automation proposal path, complete topology admission, real
HA validation/reload/loaded-state proof, shared queue, typed local operator approval
and recovery, grant/journal linkage, and one-transaction epoch archive/resume are
implemented. Disposable Linux amd64/native/HA and automated real-terminal evidence
are recorded in the ledger. The explicit operator wrapper/helper are packaged;
source release `0.2.1` retains the read-only mapping, so production apply/recovery
remain unavailable. Native aarch64, actual Supervisor deployment, backup and write
enablement approval remain open. Custody/key extensions are deferred research.
Start with the
[accepted review](requirements-ledger.md#phase-3-proportionality-review-and-scope-adjustment)
and [revised Phase 3 plan](implementation-plan.md#phase-3-guarded-application) before
resuming Phase 3 work. Production writes remain disabled.

For the local operator contract, fixed paths, retention limits, uncertainty, and
manual bootstrap recovery, use
[operator and epoch lifecycle](phase3-contracts.md#local-operator-and-epoch-lifecycle).
Do not selectively delete/copy approval receipts, checkpoints, journal records, or
archives to bypass a refusal. A nonterminal/manual/drifted epoch cannot rotate.
Production deployment/write enablement remains a separate decision after native
target evidence and a tested HA backup; source commits and disposable fixtures do
not authorize it.

This is the resumption entry point for the Home Assistant Engineering MCP. The
repository contains a working read-only server, conditional protected repository
and proposal tools, and extensive isolated mutation foundations. Production
configuration application is not enabled. This snapshot reconciles source and Git
history with the existing contracts; it does not establish current live HA health.

Latest scoped delivery evidence: authoritative verification passed 1,340 tests
with 16 platform skips; independent review approved the implementation; the
candidate image passed eight packaging rows and all 24 disposable HA/native/operator
rows passed. See [full workflow acceptance](requirements-ledger.md#disposable-full-nativeha-workflow-acceptance-on-2026-10-02)
for reproduction, image pins and limits. The attempted ARM64 build was blocked by
`exec format error` on the amd64 host; use a native aarch64 environment for that
remaining gate. Source commits/pushes are authorized by the user's continuation
instruction, separately from deployment/write approval.

The detailed inventory below is the initial historical resumption snapshot;
references to July HEAD and its POC are not the latest delivered implementation.

### Historical repository and target inventory

- Checkout: `D:\Bellforge-software\Home Assistant`, branch `main`, reviewed HEAD
  `4e8e5527b049ddb3f1dc29f6819a2f4555afb633` dated 2026-07-25. The working tree was
  clean before this documentation update.
- Repository URL recorded in add-on metadata: `https://github.com/GeorgeBell1982/HA-MCP`.
  Remote freshness and CI status were not checked during this review.
- Confirmed historical target: Raspberry Pi 5, native `aarch64`, HA OS 18.1,
  Core 2026.7.2, Supervisor 2026.06.2, storage-mode dashboards. These are recorded
  July values, not a fresh inventory of the installed system.
- Source add-on version: `0.2.0`. Root npm package version: `0.1.0`; these are
  separate version fields. Source versions do not prove installed versions.
- TypeScript ESM; Node `>=22 <25`; pnpm `11.7.0`; pinned MCP SDK `1.29.0`,
  YAML `2.9.0`, Zod `3.25.76`. This review used Node `24.18.0` on Windows.

### Available runtime capabilities

Phase 1 has 15 tools for system information, entities, automations, scripts,
helpers, scenes, config status, recent errors, and dashboard/blueprint capability
queries. Unsupported storage-mode dashboard/blueprint reads return bounded
capability refusals. Local stdio, paired TLS Streamable HTTP, and a pinned local
stdio bridge share the registry. Pairing/rotation/revocation use authenticated HA
ingress. Exact Host checks, certificate pinning, redaction, bounded outputs, and
fail-closed audit remain security requirements; public exposure is unsupported.

Phase 2 activation was added by `76f6dde` on 2026-07-20. `src/index.ts` composes
`ReadTools` with `buildPhase2Registry`; add-on option `enable_phase2` defaults true.
Local mode, disabled Phase 2, or any startup gate failure retains Phase 1 only.
The successful add-on inventory is 26 tools: 15 Phase 1 plus these 11 Phase 2 tools:

- `ha_list_config_files`, `ha_read_config_file`, `ha_search_config`
- `ha_list_config_resources`, `ha_get_config_resource`
- `ha_get_git_status`, `ha_get_git_diff`
- `ha_list_proposals`, `ha_get_pending_diff`, `ha_propose_config_change`,
  `ha_discard_proposed_change`

The official `homeassistant_config` mapping is read-only at `/homeassistant`.
Proposal, audit, and protected key/cursor state live under `/data`. Startup checks
fixed native artifacts, protected master key/state, proposal audit/store recovery,
secret registration, and repository catalog proof before registration. Native
filesystem and Git brokers enforce confined reads. Secret-source contents remain
inaccessible; proposals never write HA config, reload, restart, apply, or write Git.

### Phase 3 implementation boundary

`src/phase3` and its exact add-on source mirrors contain the guarded coordinator,
resource locks, protected proposal input, durable journal/checkpoints, source
adapter, native atomic replacement, YAML validation, narrow reload/recovery,
post-effect verification/digest, durable single-use approvals, stale-stage
remediation, conditional advisory custody, and approval-key provision/load/sync.
The [Phase 3 contracts](phase3-contracts.md) and
[requirements ledger](requirements-ledger.md) retain the per-slice evidence through
Phase 3Q. `tests/phase3Isolation.test.ts` enforces the runtime isolation boundary.
There is no registered apply/reload/restart/commit tool or production adapter wiring.

Historical commit `4e8e552` adds a repository-only workflow POC with its worker and
focused tests. Its eight mandatory evidence rows cover Linux/unprivileged
environment, private workspace, helper provenance, success, rollback, commit-kill,
restart recovery, and proved cleanup. The documented command is:

```sh
pnpm validate:linux:phase3-poc -- --ack-disposable-phase3-poc
```

It requires an unprivileged Linux user with equal real/effective UIDs, Node 22–24,
`cc`, `readelf`, and `libcrypto.so.3`. It accepts no caller paths and uses disposable
private state under canonical `/tmp` or `/var/tmp`. Verification and reload probes
and the domain-reload proposal fixture are fakes. No HA, Supervisor, or network
calls occur. SIGKILL evidence covers process death, not power loss. Uncertain
cleanup preserves the workspace and prevents a passing summary. Native execution
of this POC was not performed during the October review; code presence and its
Windows tests cannot establish a passing Linux workflow run.

### Retained validation and outstanding gates

- Fresh local evidence on 2026-10-02: `CI=true pnpm.cmd verify` exited zero on
  Windows with Node `24.18.0` and pnpm `11.7.0`. Add-on mirror/context, repository
  formatting, ESLint, TypeScript typecheck/build, and all 41 test files passed:
  1,132 tests passed, 16 skipped. The POC test file passed 11 cases with two skips;
  this does not prove native Linux POC execution. After the documentation changes,
  changed-file Prettier and `git diff --check` also passed.
- Phase 1: deployed `0.1.4` failed recent-error retrieval and malformed-cursor
  rejection; installed `0.1.5` repaired both and passed the full read-only live
  acceptance matrix on 2026-07-15. Details are in [deployment](deployment.md).
- Packaging: `0.1.6` hit Supervisor/base-image packaging failures; `0.1.7` contains
  the documented repair. Source `0.2.0` adds Phase 2 activation. The ledger records
  7/8 arm64 candidate packaging rows under emulation; its Git protocol execution
  remains unverified there. Emulation is not native aarch64 evidence.
- Phase 3Q historical closure: Windows authoritative verification passed 1,121
  tests with 14 skips; pinned Linux focused/isolation execution passed 44 cases
  with zero skips. The historical Linux clean-room full suite reproduced seven
  inherited failures (missing OpenSSL, hardlink-message case, process-group
  cleanup). Those are retained limits, not October verification results.
- Native aarch64 provenance/runtime evidence and Phase 2 live Supervisor install,
  activation, and repository/proposal acceptance remain unverified in the ledger.
- Production Phase 3 still needs operator authorization/custody/audit/recovery,
  external non-rollback identity authority, lifecycle serialization, stronger
  descriptor-relative boundaries, key rotation/migration/backup, process/power-loss
  evidence, production composition, disposable HA E2E, and explicit deployment and
  write enablement authorization. Do not equate tested primitives with readiness.

### Resumption sequence

1. Read this snapshot, then the Slice H and Phase 3Q ledger sections, Phase 3
   contracts, and `scripts/linux/README.md`. Earlier slice statements about absent
   Phase 2 registration/mounts are historical and superseded by Slice H.
2. Run `pnpm verify` for local source evidence. Native-only gates require their
   documented Linux environment; persistence ENOSPC tests require a dedicated
   tmpfs capped at 128 MiB. Never point those tests at production storage.
3. Establish current installed add-on/HA versions and Phase 2 gate status through
   an authorized read-only deployment check before claiming current live health.
4. Close native aarch64 and Phase 2 live acceptance gaps before advancing deployment.
   For Phase 3 research, collect the isolated Linux POC evidence before proposing
   runtime composition. Live mutation remains a separate explicit approval boundary.

Review scope: repository documentation, relevant runtime composition/configuration,
isolation tests, POC manifest, and local Git history. The recent-chat inventory
returned no prior Home Assistant chat among its 50 entries; older/archived chats
were not exhaustively searched. No credentials, HA endpoint, remote repository,
deployment, or production state were accessed or changed.
