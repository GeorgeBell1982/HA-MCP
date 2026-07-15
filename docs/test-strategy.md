# Test strategy

## Layers

1. Unit: schemas, paths/symlinks, redaction, risk/policy, proposal state/hash/expiry, YAML document edits, diffs, validation parsing, audit records, impact mapping, transaction state, Git scoping.
2. Integration: mocked HA REST and WebSocket servers covering auth, reads, config check, reload commands, response validation, correlation, reconnect, timeouts, safe retry, and no mutation retry.
3. Filesystem/Git: temporary directories and repositories only, realistic split HA fixtures, all include tags, `secrets.yaml`, comments, packages, dashboards, stale files, symlink attacks, dirty/conflicted Git states.
4. Workflow: inspect -> propose -> review -> validate -> apply -> reload -> verify -> commit, plus injected failure and rollback at every transition.
5. E2E: pinned Docker Home Assistant fixture when practical, no production dependency. Run read-only first; mutation uses disposable volumes and test credentials only.
6. MCP/CLI: stdio client smoke tests, tool inventory/annotations, structured envelopes, pagination, CLI exit codes, diagnostics, signal/cancellation behavior.

## Security gates

- Canary credentials must never appear in captured stdout/stderr, MCP content, audit JSONL, diffs, Git objects/messages, snapshots, or test reports. Tests include direct/renamed/aliased/symlinked secret-source reads, searches, diffs, diagnostics, errors, and audit paths.
- Adversarial path suite covers traversal, absolute paths, Unicode/separator variants, symlinks and link swaps.
- Tool inventory asserts absence of generic shell, arbitrary file write, arbitrary service call, and delete tools.
- Mutation defaults are tested from an empty environment.
- Audit partial writes/concurrent appends/permissions/rotation failure, stale proposal, forged/replayed/expired/wrong-digest approval, server restart, unrelated Git dirt, and failed rollback must fail closed.
- Auth tests reject userinfo/unsupported schemes and prove bearer headers are not sent on redirects, cross-origin destinations, or independently supplied WebSocket URLs.
- Recent-error tests cover authenticated WebSocket connection reuse/reconnect, command failure, oversized messages, malformed structured entries, timestamp/count/source validation, token/webhook redaction, exception exclusion, and bounded summaries.
- Add-on manifest tests assert Phase 1 has no `/config`, Supervisor, Docker, privileged, host-network, or host-filesystem capability and declares only the Core API permission needed.
- HTTP tests cover disabled/unprovisioned startup, ingress-only per-client 256-bit pairing, hash persistence/permissions, constant-time bearer verification, query rejection, per-client/rotate-all revocation, access-log canaries, Host/Origin/DNS rebinding, trusted/untrusted forwarded headers, request/header/output/time/session/concurrency/rate bounds, graceful overload, distinct-client session ownership, expiry/replay/reconnect, and cross-client rejection.
- TLS tests cover ECDSA certificate/key generation, mode-restricted storage, fingerprint rendering, expiry/corruption, recoverable rotation, all-session invalidation, non-loopback plaintext server/client refusal, passive/active MITM rejection, and certificate-rotation recovery without TOFU bypass.
- Bridge tests cover OS credential-store/fallback behavior, per-client credential redaction, pinned certificate fingerprint, expected server identity and compatible version pinning, mandatory re-pairing after credential/certificate/identity change, and malicious/oversized remote responses. They prove bearer credentials are never transmitted to non-loopback `http://` endpoints.
- HA credential tests prove the injected runtime token is used only for fixed Core proxy HTTP/WebSocket paths and never appears in options, diagnostics, audit, errors, logs, MCP results, HTTP/bridge traffic, snapshots, or fixtures.

## Platform matrix

The Home Assistant add-on `aarch64` image is the authoritative Phase 1 artifact. Linux/amd64 container runs development and clean-room tests where practical. Windows runs platform-neutral core and bridge tests with platform-specific credential/path cases; macOS is a best-effort core/bridge lane. Deployment adapters use contract tests across supported lanes and native HA OS E2E only in a disposable environment where available.

## Phase gates

Every phase: format check, lint, type check, focused tests, all relevant tests, security suite, `git diff --check`, diff inspection, build/package smoke test, and clean-room validation. Any critical safety test failure blocks continuation. E2E unavailable for a phase is reported `UNVERIFIED`, never passed.

The authoritative deterministic non-production command is `pnpm verify`; it composes add-on mirror, formatting, lint, type, build, and complete test checks.
