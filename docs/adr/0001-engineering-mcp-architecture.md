# ADR-0001: Capability-gated engineering MCP architecture

Status: Accepted for Phase 1

Date: 2026-07-11

## Context

The server must complement the official Home Assistant MCP, safely bridge live APIs and configuration repositories, and work across deployment styles without pretending every environment offers filesystem, supervisor, container, or process access.

Primary-source findings:

- The official MCP TypeScript SDK main branch is v2 beta against the 2026-07-28 specification. Its maintainers state that v1.x remains the production-supported release until v2 stabilizes. Phase 1 should therefore pin a current audited v1.x `@modelcontextprotocol/sdk` release; exact package/version is selected and lockfile-recorded at implementation time, not inferred from the v2 README.
- Home Assistant REST is JSON over the frontend port, bearer-authenticated, and documents `/api/config`, `/api/states`, `/api/services`, and `POST /api/config/core/check_config`; Core 2026.7.2 exposes recent system-log entries through the authenticated WebSocket command `system_log/list`.
- Home Assistant WebSocket at `/api/websocket` has explicit auth and correlation phases, supports event subscription and service commands, and is appropriate for post-reload verification.
- Home Assistant documents that configuration access and validation vary by installation type, and most configuration should be reloaded without restart where supported.

Sources:

- https://github.com/modelcontextprotocol/typescript-sdk
- https://developers.home-assistant.io/docs/api/rest/
- https://developers.home-assistant.io/docs/api/websocket/
- https://www.home-assistant.io/docs/configuration/

## Decision

Use a ports-and-adapters architecture with one side-effect-free domain core:

1. `transport`: one tool registry/application surface with two adapters: stdio for local development/tests and authenticated Streamable HTTP for the Home Assistant add-on. A separately packaged local stdio bridge may forward Codex stdio to the add-on without duplicating tool logic.
2. `application`: use-case services, proposal state machine, apply transaction coordinator, impact mapping, verification orchestration.
3. `policy`: centralized capability, risk, approval, path, size, and mutation gates evaluated before side effects.
4. `domain`: typed proposal, validation, audit, diff, risk, resource, and result models.
5. `ha`: separate REST and WebSocket ports/adapters with response validation, timeouts, and redacted errors.
6. `config-repository`: capability interface implemented by local filesystem first only if actual deployment grants safe access; future remote/sidecar adapter without changing core workflow.
7. `deployment`: capability-negotiated adapters for validation/reload/restart. Unsupported operations return structured `capability_unavailable`, never fallback to arbitrary shell.
8. `yaml`: use the exact direct dependency `yaml@2.9.0` (eemeli) with incremental `Parser` + `Composer`, YAML 1.2 core, strict diagnostics, unique keys, merge disabled, known YAML 1.1 tags disabled, explicit Home Assistant scalar tags, and non-resolution of `!secret`. Validation preserves the caller byte snapshot and returns metadata only; it never reserializes the document.
9. `git`: argument-array, scoped pathspec adapter with no remote/history-rewrite operations.
10. `audit`: mandatory middleware writing redacted JSONL. Sink unavailability fails all tool calls before protected output or effects; health remains observable only through process exit/diagnostic stderr containing no request data.
11. `cli`: diagnostics composed from the same services and policies.

Every adapter reports capabilities at startup and through diagnostics. Tool registration may remain stable while calls return a typed unsupported result when the configured deployment lacks a capability.

## Proposal state machine

`draft -> locally_validated -> approved -> applying -> applied -> verified -> committed`

Terminal/exception states: `discarded`, `expired`, `stale`, `validation_failed`, `rolled_back`, `rollback_failed`.

The proposal store must be durable before Phase 3 live writes. A write transaction uses same-directory temporary files, fsync/close where supported, atomic rename, and recoverable journal/checkpoint semantics. Checkpoints are proposal-scoped backup artifacts, not Git commits. The exact commit point and startup recovery algorithm are specified and failure-injection-tested before writes are enabled.

## Authenticated endpoint policy

`HA_BASE_URL` must parse as an origin-only `http:` or `https:` URL with no username/password, fragment, or unexpected path/query. HTTPS certificate verification is never disabled. Authenticated requests do not follow redirects; a redirect is a structured configuration error. The WebSocket URL is derived from the validated same origin (`https` -> `wss`, `http` -> `ws`) and cannot be supplied independently in Phase 1. Environment proxy inheritance is disabled by default; any future proxy is an explicit trusted configuration with tests proving authorization headers remain origin-bound. Rendered URLs omit userinfo/query and pass through credential-pattern redaction.

## Human approval boundary

MCP arguments cannot prove human intent. Phase 3 therefore introduces an `ApprovalPort` separate from MCP. The initial adapter is an operator-invoked local CLI command attached to the server's protected proposal store; it displays the redacted exact diff/digest and creates a short-lived, single-use server-side grant bound to proposal ID, digest, operation, risk, and expiry. `ha_apply_proposed_change` references the proposal only and cannot manufacture the grant. Approval grants do not survive replay and are invalidated when proposal content/state changes. A restart preserves only grants whose protected storage and expiry checks pass; otherwise reapproval is required.

## API versus repository ownership

- Use documented REST/WebSocket interfaces for live state, supported check-config, service catalog, recent-error summaries, reload calls, and event-based verification.
- Use a repository adapter only for resources actually backed by accessible YAML/config files.
- UI-storage dashboards/helpers/automations must use an officially supported API/adapter where available. Do not edit `.storage` as a generic shortcut. Unsupported resource mutations remain unavailable.
- Do not expose a generic service-call tool. Register only explicit allowlisted reload/restart operations with policy metadata.

## First-target capability matrix

The actual target is Home Assistant OS 18.1 on Raspberry Pi 5 (`aarch64`), Core 2026.7.2, Supervisor 2026.06.2, host config directory /config, exposed inside the add-on as /homeassistant only through the official mapping, with storage-mode dashboards. The user selected a purpose-built Home Assistant add-on. The core server therefore runs inside the managed add-on container; Codex connects using authenticated Streamable HTTP when supported or a small local stdio bridge.

| Capability                                                     | Initial source                                                 | Status before access provisioning                                                                                                                       |
| -------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Entity/config metadata, states, services, check-config         | Authenticated documented HA REST API                           | Feasible for Phase 1, subject to endpoint/token setup.                                                                                                  |
| Recent errors (`system_log/list`), events, reload verification | Authenticated HA WebSocket API                                 | Recent errors are Phase 1; events and reload verification are Phase 3, subject to endpoint/token setup.                                                 |
| /homeassistant reads/search/proposals                          | Official read-only homeassistant_config add-on mapping         | Host /config is not a container path. Add the mapping only after Phase 2 path/secret/audit/YAML/Git/proposal security gates; live writes remain absent. |
| Storage-mode dashboards                                        | Supported HA API only                                          | Read capability must be verified; direct `.storage` editing prohibited. Mutation remains unavailable until a supported interface is proven.             |
| HA validation                                                  | REST `POST /api/config/core/check_config` first                | Feasible; Supervisor/CLI fallback is not assumed.                                                                                                       |
| Domain reload                                                  | Explicit allowlisted HA services verified from `/api/services` | Planned, writes disabled by default.                                                                                                                    |
| Core restart                                                   | Separate high-risk adapter/policy                              | Disabled; Supervisor access not assumed.                                                                                                                |
| Git status/diff/commit                                         | Confined repository detection within /homeassistant            | Status/diff are Phase 2 after hardening; no initialization or commit without explicit authorization.                                                    |

Home Assistant OS's internal Docker/Supervisor environment does not authorize shelling into arbitrary containers or host access. The approved add-on receives only declared Home Assistant add-on mappings and APIs. It requests no Docker socket, host PID/network namespace, privileged mode, or generic shell MCP tool.

## Add-on and transport decision

The repository is also a custom Home Assistant add-on repository. Phase 1 provides add-on metadata, a multi-architecture container build with `aarch64` as the required target, no homeassistant_config mapping, persistent add-on data for audit/auth state, authenticated ingress diagnostics/setup, health checks, watchdog-compatible exit behavior, and UI options whose mutation flags default false.

The add-on's Streamable HTTP endpoint is disabled by default and has no default port exposure. Enabling it requires a TLS identity and a separately paired client credential generated through the Home Assistant-authenticated ingress setup listener. Each client receives a random public client ID plus 32 random secret bytes encoded base64url, returned once, never accepted through options/query/URL, and stored server-side only as a client-keyed salted `scrypt` hash with mode-restricted files under `/data`. Rotation/revocation is per client and deletes that client's sessions; rotate-all revokes every client. No plaintext credential is persisted. Authentication uses `Authorization: Bearer <client-id>.<secret>`, constant-time secret verification, and generic failures.

Ingress/setup and MCP run on separate listeners. The ingress listener binds the add-on container wildcard so the Supervisor proxy can reach it, is not declared as a host port, and is used only behind authenticated Home Assistant ingress. The MCP listener starts only when `enable_http=true`, a valid credential hash exists, and an explicit host-port mapping is configured. It accepts configured LAN Host values, rejects missing/mismatched Host, rejects browser requests with missing/unapproved Origin when Origin is present, ignores all forwarded headers unless the exact peer is in an explicit proxy allowlist, and never derives security decisions from untrusted forwarding headers. Query credentials are rejected. Public/Cloudflared exposure is unsupported; startup refuses explicitly configured public bind/proxy modes, while documentation states that undisclosed external forwarding cannot be detected.

Sessions are owned by the paired client identity, use at least 128 bits of server-generated entropy, have idle and absolute expiry, are deleted on rotation/revocation/shutdown, and reject cross-client/session replay. Requests enforce header/body/output bounds, parse/deadline timeouts, bounded sessions and concurrency, rate limits, and graceful overload.

The direct MCP listener is HTTPS only. On first ingress setup the add-on generates an ECDSA P-256 private key and self-signed server certificate using a reviewed library, stores both under mode-restricted `/data`, and shows the SHA-256 certificate fingerprint only through authenticated ingress. It refuses non-loopback plaintext configuration and never sends bearer credentials to `http://` non-loopback endpoints. A supported alternative is TLS termination at an explicitly trusted private reverse proxy whose exact peer address is allowlisted; the add-on-facing hop must be loopback or an isolated add-on network boundary and forwarding headers are trusted only from that peer. Public/Cloudflared termination is unsupported. The bridge pins the certificate fingerprint, expected server instance ID, and compatible protocol/server version and refuses certificate/identity changes until operator re-pairing.

Certificate rotation is performed through ingress, invalidates all sessions, and requires every bridge/client to pin the new fingerprint. Startup detects and regenerates a mismatched pair if replacement was interrupted. Recovery documentation distinguishes expired/corrupt certificates from suspected compromise and never offers a trust-on-first-use bypass over the network.

The optional local stdio bridge stores the add-on endpoint credential in the OS credential store where available (mode-restricted file fallback with warning), never in URL/config examples, forwards bounded MCP messages, performs server identity/version checks, and contains no Home Assistant/business logic. Direct stdio remains available for tests and non-add-on local development.

## Add-on Home Assistant credential decision

Phase 1 declares only the documented `homeassistant_api: true` add-on permission and uses the Supervisor-injected runtime token to call the fixed Core proxy origin `http://supervisor/core/api` and its corresponding WebSocket endpoint. It does not declare `hassio_api`, `docker_api`, `host_network`, privileged mode, or host mappings. The process receives `SUPERVISOR_TOKEN` in memory but never persists, echoes, audits, diagnoses, or forwards it; the HTTP/bridge credential is unrelated. The HA client rejects caller-supplied base URLs in add-on mode and allowlists only Core proxy paths, preventing use of the credential against general Supervisor endpoints. Token rotation is managed by Supervisor and takes effect on add-on restart; 401/403 produces a redacted health failure without printing headers.

### Phase 2 YAML parser decision

`yaml@2.9.0` is selected and lockfile-pinned in both the root and mirrored add-on package. The gate uses only its public `Parser`, `Composer`, `LineCounter`, and node identity APIs. Input is incrementally supplied in at most 4096 UTF-16 code units without splitting surrogate pairs; parser and composer errors and warnings all fail closed. The library may buffer an entire bounded 512 KiB scalar, so cancellation and deadlines are cooperative between chunks rather than hard-real-time. No AST, source text, parser message, or secret name crosses the gate output.

## Consequences

Benefits: testable seams, deployment isolation, fail-closed policy, no shell/write escape hatch, stable tool contracts, and deterministic rollback design.

Costs: more explicit types/adapters; some requested operations may remain capability-unavailable until a supported HA interface is confirmed for the user's deployment/version; round-trip YAML fidelity requires fixture proof.

## Rejected alternatives

- Directly wrapping SSH/Samba/shell: violates least privilege and exposes broad execution.
- Generic file editor or service caller: bypasses proposal/policy guarantees.
- Editing `.storage`: undocumented/internal and unsafe across HA versions.
- Binding core logic to `ha core check`, Docker, or local Python: breaks deployment portability.
- Starting with MCP SDK v2 beta: inappropriate for the requested production-quality initial release before its stated stable date.
