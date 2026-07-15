# Phased implementation plan

Risk: `HIGH`. This plan requires independent review before implementation. No phase authorizes live Home Assistant mutation, Git commit, push, deployment, or token access.

## Phase 0: decisions and environment contract

1. Record confirmed target and deployment choice: Home Assistant OS 18.1, Core 2026.7.2, Supervisor 2026.06.2, Raspberry Pi 5 `aarch64`, purpose-built managed add-on, mapped `/config`, storage-mode dashboards.
2. Select a supported Node LTS add-on base image with multi-architecture provenance; do not treat the bundled Node 24 runtime as the production baseline automatically.
3. Resolve and pin current production v1 MCP SDK and supporting libraries; record licenses/advisories and lockfile.
4. Prove YAML library round-trip fidelity with HA-tag fixtures before adopting it.
5. Finalize proposal persistence, crash recovery, approval metadata, audit-failure, and adapter capability contracts.

Exit: reviewed ADRs/contracts and no material ambiguity in the first deployment adapter. Deployment/access is resolved by the add-on decision. Phase 1 may begin after the revised plan review; dependency and base-image resolution is authorized by the user's instruction to start. YAML fidelity remains a Phase 2 gate, not a Phase 1 blocker.

## Phase 1: read-only server

Scaffold TypeScript package and add-on repository; strict compiler/lint/format/test/build scripts; config loader with safe defaults; shared MCP registry; stdio and disabled-by-default TLS-only authenticated Streamable HTTP transports; bounded optional stdio bridge; separate ingress TLS/client pairing, rotation/revocation, fingerprint, and diagnostics; per-client session ownership; result/error schemas; fixed Core-proxy HA REST/WebSocket clients using the runtime-injected credential; Phase 1 tools from the delivery matrix; exact/heuristic redaction; bounded error summaries; fail-closed mandatory audit; HA add-on metadata/container/options for `aarch64`; least-privilege installation and Codex setup docs. Do not map `/config` and do not register mutation tools.

Exit: stdio smoke test, mocked API integration, CLI tests, security gates, full verify, independent review, clean-room validation.

Status (2026-07-15): deployed add-on 0.1.4 passed the read-only inventory, bridge, system, entity, automation, script, helper, scene, capability-refusal, schema, and shutdown checks. It failed recent-error retrieval and strict malformed-cursor rejection. Repository candidate 0.1.5 contains repairs and deterministic test coverage, but those behaviours are not live-verified. Phase 1 live closeout is `BLOCKED` pending an explicitly authorized 0.1.5 deployment and read-only retest; this status does not authorize deployment or mutation.

## Phase 2: repository inspection and proposals

Implement bounded config repository and include graph; canonical path/symlink/size/encoding controls; HA-tag-aware YAML document layer; config/list/search/read tools; Git status/diff adapter; durable proposal store; proposal/discard/pending-diff tools. Proposals never touch live config.

Exit: adversarial filesystem/YAML/Git/proposal tests, full verify, review, clean room.

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
