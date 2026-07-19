# Phased implementation plan

Risk: `HIGH`. This plan requires independent review before implementation. No phase authorizes live Home Assistant mutation, Git commit, push, deployment, or token access.

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

Implement deployment validation adapter for the confirmed environment, local/HA/post-apply validators, resource locks, journaled atomic apply, non-commit backup/checkpoint, operator-controlled approval CLI/port, narrow reload adapters, WebSocket/REST verification, startup recovery, automatic scoped rollback, explicit restart gate, and separately authorized scoped commit tool. Writes remain disabled by default; disposable HA E2E precedes any production enablement.

Exit: failure injection at every transaction edge, disposable E2E success/rollback, full verify, high-risk review, clean room, explicit human gate before production writes.

## Phase 4: structured operations and broader deployments

Add structured automation/script/helper/dashboard/scene builders only for supported storage/API modes; each delegates to proposal workflow. Add OS/Supervised/Container/Core adapters incrementally behind contract tests. Add Docker matrix, hardening, audit rotation guidance, and complete tool/recovery/deployment documentation.

Exit: definition-of-done traceability, complete workflow tests, cross-platform validation, independent review, clean-room completion gate.

## Planned module boundaries

`src/domain`, `src/application`, `src/policy`, `src/transport/mcp`, `src/ha/rest`, `src/ha/websocket`, `src/config-repository`, `src/yaml`, `src/deployment`, `src/git`, `src/audit`, `src/cli`; tests mirror boundaries plus `test/integration`, `test/fixtures`, and `test/e2e`.

## Validation commands (planned)

`pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:security`, `pnpm build`, `pnpm test:mcp`, and aggregate `pnpm verify`. Exact commands become authoritative only after Phase 1 creates and verifies them.

## Next approval point

After revised plan review, Phase 1 scaffold/package resolution may proceed under the user's “let's start” instruction. This is not approval to install/deploy the add-on, access production tokens, mutate Home Assistant, enable writes, restart, initialize Git, or commit.
