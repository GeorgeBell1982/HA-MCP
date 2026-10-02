# Recovery

- Audit unavailable: stop the service, restore writable protected `/data`, then restart. Calls fail closed.
- Token expired: replace the local secret or restart the add-on so Supervisor injects the current runtime token. Diagnostics never print it.
- HTTP identity changed: do not bypass pinning; use authenticated ingress to download and verify the new public certificate, then update bridge pins.
- Phase 2 activation failure: the runtime falls back to Phase 1 tools with sanitized activation diagnostics. Investigate the failed artifact, protected state, secrets, or catalog gate before expecting repository/proposal tools.
- Guarded MCP apply in `0.2.3` requires explicit add-on opt-in and exact-diff form approval. Unsupported approval fails closed. Manual recovery remains local; inspect uncertain transactions before another apply.

Before operator effects, keep a Home Assistant backup outside the Pi and test
restoration or explicitly record the deployment owner's waiver. The current owner
has downloaded a backup on their phone and waived restore testing. Each local
effect requires its write flag and typed approval; each opted-in MCP apply requires
approval through the originating client's form UI.

## Project context as of 2026-10-02

Latest requested extension: the owner wants MCP changes with approval in this
chat. Release `0.2.3` is published and installed with guarded MCP writes enabled.
It adds the opt-in guarded automation apply, completed epoch
archive, and harmless approval display check. The bridge relays form elicitation
and never retries mutations after an uncertain session response. Source, fixture
and deployed acceptance evidence are recorded separately in the ledger. This
supersedes the historical terminal-only MCP restriction described below. All 1,373
tests and 27 disposable native/real HA checks on amd64 and Pi arm64 passed, and
independent review approved the change. Installed health and 29-tool inventory
passed; unsupported hosts refuse approval. The current chat's inventory has
reconnected, but its active `never` approval policy still automatically declines
the harmless check. The prepared granular config must be selected through this
chat's permissions control, then human prompt acceptance verified. No live
proposal has been applied or authorized by the feature request.

Phase 3 scope was narrowed following the independent proportionality review on the
same date. The direct automation proposal path, complete topology admission, real
HA validation/reload/loaded-state proof, shared queue, typed local operator approval
and recovery, grant/journal linkage, and one-transaction epoch archive/resume are
implemented. Disposable Linux amd64/native/HA and automated real-terminal evidence
are recorded in the ledger. The explicit operator wrapper/helper are packaged;
release `0.2.1` was verified with a read-only mapping. Following explicit user
authorization, `0.2.2` is now installed with a writable mapping and initialized
protected operator state. Local apply/recovery is available only with per-command
write enablement and exact typed terminal approval; none has been performed.
MCP remains read-only. Earlier read-only system/config/proposal checks
passed against Core `2026.9.4`; Git status refused `repository_unavailable` because
the actual `/homeassistant/.git` directory is absent (`ENOENT` verified over SSH).
The 24-row disposable workflow now also passes against Core `2026.9.4`.
Native Pi packaging/ABI checks passed over dedicated-key SSH: arm64 image/ELF
helpers, root `555` artifacts, resolved linkage, operator import and read-only
kernel mount/Node `EROFS` refusal. Native Pi approval (56), persistence (45) and
disposable workflow (eight) checks also passed; the isolated test container was
removed with inventory proof. Full native Git/security/image-runner provenance,
actual production apply/recovery acceptance remain open. Phone backup download is
confirmed, restoration is untested by user choice, and operator enablement is
approved and complete. The full 24-row real HA/native/operator fixture now also
passes on the Pi, with automated terminal confirmation and proved cleanup; see
[native real HA workflow](requirements-ledger.md#native-pi-real-ha-workflow-on-2026-10-02).
Custody/key extensions are
deferred research. See the [installed smoke evidence](requirements-ledger.md#installed-021-read-only-smoke-evidence-on-2026-10-02).
See [current-Core acceptance](requirements-ledger.md#current-core-202694-disposable-acceptance-on-2026-10-02)
for the updated immutable fixture and historical Git diagnosis boundary.
See [native Pi acceptance](requirements-ledger.md#native-pi-read-only-packaging-acceptance-on-2026-10-02)
for target hashes and the resolved SSH/Git/mount-check findings.
The subsequent native Git matrix exposed an additional blocker: this Pi kernel
has Landlock disabled, so the broker fails closed even with a disposable repository.
See the [kernel compatibility evidence](requirements-ledger.md#native-pi-git-confinement-blocker-on-2026-10-02).
Start with the
[accepted review](requirements-ledger.md#phase-3-proportionality-review-and-scope-adjustment)
and [revised Phase 3 plan](implementation-plan.md#phase-3-guarded-application) before
resuming Phase 3 work. MCP writes remain disabled; the local operator is available.

For the local operator contract, fixed paths, retention limits, uncertainty, and
manual bootstrap recovery, use
[operator and epoch lifecycle](phase3-contracts.md#local-operator-and-epoch-lifecycle).
Do not selectively delete/copy approval receipts, checkpoints, journal records, or
archives to bypass a refusal. A nonterminal/manual/drifted epoch cannot rotate.
See [installed operator enablement](requirements-ledger.md#installed-022-operator-enablement-on-2026-10-02)
for the explicit authorization, deployed image, protected state and health evidence.
The downloaded phone backup predates operator initialization; include key and
complete epoch state together in later backups. Do not restore a partial subset.

This is the resumption entry point for the Home Assistant Engineering MCP. The
repository contains a working read-only server, conditional protected repository
and proposal tools, and extensive isolated mutation foundations. Production
configuration application requires the explicit local operator's approval. This snapshot reconciles source and Git
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
