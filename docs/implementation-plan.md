# Phased implementation plan

Risk: `HIGH`. This plan requires independent review before implementation. No phase authorizes live Home Assistant mutation, Git commit, push, deployment, or token access.

Current context (2026-10-02): Phase 1 has historical live acceptance; Phase 2 is
conditionally wired into source add-on `0.2.1`, with native aarch64 and live
deployment gates still unverified in the retained record. The scoped Phase 3 local
operator, audited recovery, bounded archive/resume, and disposable real-HA workflow
are implemented and verified on Linux amd64. The packaged add-on mapping remains
read-only; native aarch64 and production enablement remain gated. The phase
descriptions and original approval points below are planning
history; use the [current context](recovery.md#project-context-as-of-2026-10-02) and
the requirements ledger to resume from the actual implementation boundary.

## Phase 0: decisions and environment contract

1. Record confirmed target and deployment choice: Home Assistant OS 18.1, Core 2026.7.2, Supervisor 2026.06.2, Raspberry Pi 5 `aarch64`, purpose-built managed add-on, host /config exposed by the official add-on mapping as /homeassistant only after the Phase 2 security gates, storage-mode dashboards.
2. Select a supported Node LTS add-on base image with multi-architecture provenance; do not treat the bundled Node 24 runtime as the production baseline automatically.
3. Resolve and pin current production v1 MCP SDK and supporting libraries; record licenses/advisories and lockfile.
4. Prove YAML library round-trip fidelity with HA-tag fixtures before adopting it.
5. Finalize proposal persistence, crash recovery, approval metadata, audit-failure, and adapter capability contracts.

Exit: reviewed ADRs/contracts and no material ambiguity in the first deployment adapter. Deployment/access is resolved by the add-on decision. Phase 1 may begin after the revised plan review; dependency and base-image resolution is authorized by the user's instruction to start. YAML fidelity remains a Phase 2 gate, not a Phase 1 blocker.

## Phase 1: read-only server

Scaffold TypeScript package and add-on repository; strict compiler/lint/format/test/build scripts; config loader with safe defaults; shared MCP registry; stdio and disabled-by-default TLS-only authenticated Streamable HTTP transports; bounded optional stdio bridge; separate ingress TLS/client pairing, rotation/revocation, fingerprint, and diagnostics; per-client session ownership; result/error schemas; fixed Core-proxy HA REST/WebSocket clients using the runtime-injected credential; Phase 1 tools from the delivery matrix; exact/heuristic redaction; bounded error summaries; fail-closed mandatory audit; HA add-on metadata/container/options for `aarch64`; least-privilege installation and Codex setup docs. Do not map `/config` and do not register mutation tools.

Exit: stdio smoke test, mocked API integration, CLI tests, security gates, full verify, independent review, clean-room validation.

Status (2026-07-15): deployed add-on 0.1.4 passed the read-only inventory, bridge, system, entity, automation, script, helper, scene, capability-refusal, schema, and shutdown checks, but failed recent-error retrieval and strict malformed-cursor rejection. Installed add-on 0.1.5 then passed both repaired paths and the complete read-only acceptance matrix against Core 2026.7.2; the bridge also recovered across the release. Phase 1 live closeout is `PASSED`. This status does not authorize mutation or any later-phase deployment.

## Phase 2: repository inspection and proposals

Implement the frozen phase2-contracts.md inventory against confined /homeassistant: bounded repository/include inspection; fail-closed path and secret identity; the exact YAML gate; hardened Git status/diff; durable /data audit/proposal recovery; proposal/discard/pending-diff tools. Proposals never touch live config. Register tools and add the read-only mapping only after every security layer passes.

Exit: adversarial filesystem/YAML/Git/proposal tests, full verify, review, clean room.

Slice F implementation gate: land only the unregistered fixed-operation Git broker protocol/source, strict status and plumbing parsers, deterministic redacted YAML patch engine, fake-broker/source-contract tests, and exact add-on mirrors. Windows and unpackaged runtimes remain unavailable. Real Linux Git execution, hostile config/filter/fsmonitor/hooks, openat2 topology/races, Landlock/seccomp/rlimits, and packaged runtime remain Slice G `UNVERIFIED`. No tool/application/config/container/build/version/mount/package/release/deployment wiring is part of Slice F.

## Phase 3: guarded application

The independent assessment on 2026-10-02 found the transaction core proportionate,
but approval/custody infrastructure too elaborate for one managed add-on while real
HA integration remains incomplete. The first delivery is narrowed to one supported
automation YAML change class, an explicitly stored `automation.reload` target, and
one shared apply/recovery queue. Restart-required changes remain denied. Git commit,
additional domains, restart support, and deployment generalization are outside this
delivery.

Keep exact proposal/digest binding, default-disabled writes, human approval with
short expiry and durable single-use consumption, atomic replacement, checkpoint,
durable transaction intent, reload ambiguity tracking, rollback, startup recovery,
and explicit manual recovery. Preserve the existing transaction state machine.

Complete the following delivery gates in order:

1. Global serialization: all apply, rollback, verification, and recovery use one
   shared `Phase3ResourceLocks` instance per deployment. Implemented in source on
   2026-10-02; this is in-process serialization, not cross-process custody.
2. Real proposal path: extend the protected producer/schema to store a verified
   supported target; exercise the real Phase 2 producer through the Phase 3 adapter
   and coordinator without POC impact overrides. Candidate metadata and local seam
   integration are implemented for the direct automation include and plain-list
   class on 2026-10-02. The isolated admission policy and reload catalog now use the
   existing complete bounded include graph to reject transitive/hardlink sharing,
   bind source hashes, and recheck reachable sources/catalog. Runtime composition
   is now implemented in the explicit local operator and verified against real HA
   with native Linux amd64 and aarch64 helpers. Live production acceptance remains OPEN.
   Unsupported layouts and
   existing restart-required proposals retain their conservative classification;
   actual Supervisor mapping and target validation remain deployment gates.
3. Real HA boundaries: implement deployment-aware HA configuration validation,
   exact domain reload, and observable post-reload verification. YAML parsing and
   fake probes are insufficient. Invalid candidate semantics must refuse before
   effects; failures after replacement must restore and revalidate the checkpoint
   in a disposable HA environment.
   Fixed HTTP installed-config validation/reload boundaries are isolated in
   source. Installed-config checks alone can miss filtered automation errors;
   Component validation and exact loaded raw-configuration comparison are now
   implemented in an isolated automation boundary. A pinned disposable HA smoke
   covers semantic rejection, reload, stale loaded state, and restoration. Full
   real-producer/native atomic/durable HA workflow acceptance passed on Linux amd64,
   including rollback and fresh-process recovery. Explicit local operator
   composition is implemented; production writes remain disabled.
4. Operator approval: add an explicit human approval path outside MCP-controlled
   identity fields. Evaluate journal-backed approval consumption before adding any
   more bespoke storage. Keep current replay protection until a replacement proves
   expiry, exact binding, one-time use, crash recovery, and restart behavior.
   The evaluation recommends retaining the tested grant/receipt store: consumption
   precedes transaction intent, so consolidation would add a pre-intent record type
   and archive replay lookup. New records link to the consumed grant ID without
   changing the 13 states. Exact typed local TTY approval and audited recovery are
   implemented and exercised through the actual wrapper/CLI in a disposable PTY.
   This is automated terminal evidence, not a human acceptance session.
5. Retention: provide supported archive/compaction for terminal transactions and
   associated checkpoints/approval evidence. Preserve nonterminal and manual
   recovery state; test restart and recovery across the retention boundary. Raising
   the existing caps alone does not solve the lifecycle gap. Implemented with one
   transaction per epoch, finite preserved archives, fresh recovery/checkpoint/
   receipt proof, durable interrupted-rotation resume, and tests beyond original
   store lifetime caps. Archive export/removal is outside this delivery.
6. Disposable HA evidence: demonstrate successful real-producer apply/reload,
   semantic-validation failure, reload/verification failure, rollback, process
   interruption recovery, and continued use across retention limits. All 24 owned
   HA/native/operator evidence rows passed, with proved container/volume cleanup.
   Authoritative verification passed 1,340 tests with 16 platform skips; independent
   review approved the scoped implementation. Native aarch64 packaging and the
   56-row approval, 45-row persistence and eight-row disposable workflow matrices
   now pass on the Pi, along with all 24 real HA/native/operator fixture rows.
   Full native Git/security/provenance, actual production Supervisor/human operator
   apply/recovery acceptance remain open. The user downloaded a backup, waived
   restore testing and authorized local operator enablement; `0.2.2` is installed
   with a writable mount and initialized protected state. MCP remains read-only.

Current-Core follow-up: the same 24-row disposable native/HA/operator workflow
passed against pinned Core `2026.9.4`, matching the installed Pi version. Source
release `0.2.1` installation and read-only configuration/proposal checks are
confirmed. Native Pi packaging/ABI availability, root-owned helpers, actual
read-only mount and operator import are now verified over SSH; `.git` is absent,
explaining the Git refusal. Native approval/persistence/disposable workflow checks
passed and their owned test container was removed. Full native Git/security/image
provenance and actual production apply/recovery evidence remain open. Local operator
enablement is now user-authorized and deployed; restore testing was waived after
phone backup download. The subsequent native Git matrix is
blocked specifically by the Pi kernel's disabled Landlock support (`ENOSYS`);
the broker's fail-closed protection remains intact. Adding Git metadata would not
resolve that kernel incompatibility.
See the requirements ledger for evidence and limitations.

Freeze the separate approval custody helper, stale-stage remediation, key-sync
protocol, and hostile injected-object defenses as isolated research. They are not
first-delivery dependencies; do not expand or compose them without a concrete threat
or deployment requirement. Do not delete them or weaken existing protections before
the simpler replacement has equivalent tested guarantees.

Exit: the scoped real-producer/disposable-HA workflow, crash/recovery and retention
regressions, authoritative verification, focused independent review, and explicit
deployment/write enablement approval. Native aarch64 execution remains a separate
target gate. Environment isolation is required only when the evidence depends on
packaging, bootstrap, or suspected contamination. MCP writes remain disabled;
production local operator effects require explicit per-command typed approval.

## Phase 4: structured operations and broader deployments

Add structured automation/script/helper/dashboard/scene builders only for supported storage/API modes; each delegates to proposal workflow. Add OS/Supervised/Container/Core adapters incrementally behind contract tests. Add Docker matrix, hardening, audit rotation guidance, and complete tool/recovery/deployment documentation.

Exit: definition-of-done traceability, complete workflow tests, cross-platform validation, independent review, clean-room completion gate.

## Planned module boundaries

`src/domain`, `src/application`, `src/policy`, `src/transport/mcp`, `src/ha/rest`, `src/ha/websocket`, `src/config-repository`, `src/yaml`, `src/deployment`, `src/git`, `src/audit`, `src/cli`; tests mirror boundaries plus `test/integration`, `test/fixtures`, and `test/e2e`.

## Validation commands (planned)

`pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:security`, `pnpm build`, `pnpm test:mcp`, and aggregate `pnpm verify`. Exact commands become authoritative only after Phase 1 creates and verifies them.

## Next approval point

After revised plan review, Phase 1 scaffold/package resolution may proceed under the user's “let's start” instruction. This is not approval to install/deploy the add-on, access production tokens, mutate Home Assistant, enable writes, restart, initialize Git, or commit.
