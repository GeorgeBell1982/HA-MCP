# Threat model

## Assets

Home Assistant availability and safety; configuration and history; access tokens and `secrets.yaml`; webhook IDs/credential-bearing URLs; Git integrity; MCP client identity/intent; audit integrity; household privacy and physical-device behavior.

## Trust boundaries

- MCP client input to tool/schema/policy layer.
- Environment credentials to HA clients.
- HA API responses/events to response validators.
- Config root and Git repository to filesystem/Git adapters.
- Deployment adapter to narrowly allowlisted process/API operations.
- Proposal/audit persistence to local storage.

## Threats and controls

| Threat                                       | Required controls                                                                                                                                                                                                                                                      |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Prompt/tool input triggers unintended action | Explicit tools, strict schemas, policy decision before effects, high-risk approval bound to proposal ID and diff digest.                                                                                                                                               |
| Arbitrary file access                        | Canonical configured roots, relative paths, `lstat`/realpath checks, no traversal, symlink escape/write rejection, size/type/encoding limits.                                                                                                                          |
| TOCTOU/stale overwrite                       | Original hash plus identity metadata rechecked immediately before atomic replacement; per-resource lock; stale refusal.                                                                                                                                                |
| Secret disclosure                            | Never resolve `!secret`; structural and pattern redaction before diff/log/error/response/commit; canary tests; no token tool inputs.                                                                                                                                   |
| Direct/aliased secret-file disclosure        | Deny content reads, searches, indexing, snippets, diffs, Git content, and diagnostics for `secrets.yaml` and configured secret sources by canonical file identity; deny aliases and symlink routes; metadata only.                                                     |
| Bearer token forwarded off-origin            | Strict `http`/`https` origin parsing, no URL userinfo, no authenticated redirects, same-origin WebSocket derivation, TLS verification always on, proxies disabled by default.                                                                                          |
| Add-on runtime token abuse                   | Request only `homeassistant_api`; fixed Core proxy origin/path allowlist; no caller URL; memory-only token; no persistence/diagnostics/audit/response; no general Supervisor permission.                                                                               |
| HTTP credential theft/replay                 | Disabled-by-default TLS-only listener; ingress-only per-client pairing; 256-bit secrets; salted scrypt hashes; constant-time verify; header only; per-client rotation/revocation and session cleanup; no access-log secrets.                                           |
| Passive/active LAN interception              | HTTPS only; SAN-bound ECDSA identity protected in `/data`; bridge CA and fingerprint pinning; non-loopback plaintext refusal; no proxy/public exposure or TOFU bypass. The internal add-on wildcard is reachable only through an explicitly published Supervisor port. |
| DNS rebinding/forged proxy/CSRF              | Explicit Host allowlist, Origin policy, separate unexposed ingress listener, trusted-peer proxy list, ignore forwarded headers otherwise, query credentials forbidden.                                                                                                 |
| Session fixation or cross-client use         | Distinct paired client identities, server-generated >=128-bit IDs, client ownership binding, idle/absolute expiry, client rotation/shutdown deletion, replay/cross-client rejection.                                                                                   |
| Public endpoint exposure                     | No default port/listener, explicit LAN enablement, refusal of configured public/proxy modes, TLS requirements, Cloudflared unsupported, clear residual limit for undetectable forwarding.                                                                              |
| Bridge impersonation                         | Expected server instance ID and compatible protocol/version pinning; operator re-pair required after identity change; credential held in OS store or restricted fallback.                                                                                              |
| YAML semantic corruption                     | Duplicate-key rejection, HA-tag-aware parser, document-node edits, bounded diff, local and HA validation, rollback.                                                                                                                                                    |
| Uncontrolled HA action/restart               | No generic service tool; explicit allowlist; mutation/restart feature flags default false; narrow reload first.                                                                                                                                                        |
| Replay/double apply                          | Durable proposal states, idempotency/request IDs, single transition ownership, terminal-state rejection.                                                                                                                                                               |
| Partial write or crash                       | Journaled transaction, same-filesystem atomic replacement, backup/checkpoint, startup recovery, failure injection.                                                                                                                                                     |
| Rollback destroys unrelated work             | Proposal-scoped backups/Git pathspecs, dirty-tree conflict detection, hash verification, no reset/history rewrite.                                                                                                                                                     |
| Malicious/invalid HA response                | Runtime schema validation, bounds, timeouts, correlation IDs, safe-read retry only.                                                                                                                                                                                    |
| WebSocket confusion/reconnect gaps           | Monotonic command IDs per connection, authenticated state machine, subscription restoration, verification deadline and fresh REST confirmation.                                                                                                                        |
| Audit tampering/failure                      | Append-only JSONL permissions, serialized writes, correlation IDs, newline-safe encoding, partial-record recovery, redaction, documented external rotation; fail all calls if audit cannot persist.                                                                    |
| Command injection                            | No shell; spawn fixed executable plus argument arrays from allowlisted adapter operations; sanitized bounded outputs.                                                                                                                                                  |
| Excessive data/resource use                  | Pagination, filters, output/file/header/body limits, declared-length POSTs, rate limits, per-client/global session caps, idle/absolute expiry, timeouts, bounded concurrency, and cleanup.                                                                             |
| Privilege creep                              | Dedicated HA user, least-privilege docs, startup capability report, disabled mutations/restarts/deletes.                                                                                                                                                               |

## Approval binding

Client-supplied approval metadata is informational only. Authoritative approval comes from the separate operator-controlled `ApprovalPort`; its single-use grant identifies proposal ID, immutable diff digest, risk, timestamp, expiry, and permitted operation. Approval for one digest cannot authorize a refreshed or expanded proposal. Destructive capability remains absent by default even with approval.

## Residual risks

Home Assistant does not expose uniform fine-grained API permissions for every resource; long-lived access tokens act with their user privileges. Unknown secret-like household values in arbitrary upstream text cannot be recognized perfectly, so raw error logs are suppressed and only bounded classified summaries are returned; heuristic redaction is defense-in-depth, not a proof for unknown values. YAML semantic validation cannot perfectly model all integrations locally. Reload success does not prove physical-device safety. These require least privilege, HA-side validation, bounded verification, explicit human review, and conservative capability refusal.
