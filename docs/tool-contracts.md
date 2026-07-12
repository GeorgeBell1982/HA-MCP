# MCP tool contract plan

All results use a bounded envelope: `{ ok, requestId, data?, error?, warnings, evidence, pagination? }`. Errors use stable codes and redacted messages. Mutating tools include policy decision, risk, proposal state, validation, reload/restart, verification, rollback, and audit correlation. Tool descriptions explicitly declare read/write, approval, reload/restart, file, and Git effects.

## Read tools

The requested `ha_get_system_info`, entity, automation, script, helper, dashboard, scene, blueprint, config, error, Git, and pending-diff tools are read-only. List/search tools accept typed filters, `limit` with a conservative maximum, and opaque cursor. File reads accept only repository-relative paths, ranges, and maximum bytes. Large content returns a summary/hash and bounded follow-up reference.

Discovery sources are explicit in responses: REST state/config, WebSocket, supported HA API resource, YAML repository, or capability unavailable. API objects and YAML resources are not silently merged when identity cannot be proven.

`secrets.yaml` and configured secret-source canonical identities are metadata-only. They are excluded from reads, search/indexing, snippets, diffs, Git content inspection, diagnostics, and error context. Renames, configured aliases, includes, hard-link identity where detectable, and symlink paths cannot bypass denial. Known secret values may be loaded into a locked in-memory redactor by the repository boundary but are never returned or persisted; heuristic redaction separately covers token/password/key/webhook/credential-URL shapes.

`ha_get_recent_errors` returns classified summaries, counts, normalized timestamps/source labels, and truncation evidence—not raw log lines by default. The adapter fetches at most a configured byte ceiling, rejects/marks oversized or malformed input, normalizes multiline records, filters newest/error severity, strips context, and applies exact plus heuristic redaction. No raw-log override is exposed in the initial tool.

## Proposal tools

`ha_propose_config_change` accepts a structured operation or bounded proposed document/edit against an allowed resource. It writes proposal metadata only, never live config. It returns the exact redacted diff, hashes, risk, validation plan, required approval, and reload/restart impact.

`ha_apply_proposed_change` accepts a proposal ID only. When risk requires approval, it consumes a short-lived single-use grant previously created through the separate operator CLI for the exact proposal/diff digest. MCP client metadata or asserted approver fields never authorize a write. The server re-renders the diff and digest, checks state/expiry/hash/locks/policy/audit availability, then runs the transactional workflow. It never accepts replacement content.

`ha_discard_proposed_change` terminally marks a proposal without touching live configuration.

## Explicit operational tools

Validation, domain reload, restart, verification, commit, and rollback are separate tools/use cases. They are not generic service/process wrappers. Restart is high-risk and disabled by default. Rollback is proposal/checkpoint-scoped, never `git reset` or history rewrite.

`ha_commit_change` commits only verified proposal paths after rechecking the index/worktree scope. It does not push. A user request to apply is not implicit authorization to commit, and apply/checkpoint logic never creates a Git commit.

## Tool delivery matrix

| Phase | Tools                                                                                                                                                                                                                                     | Source/capability                                                                | Contract status                                                                                                                                                                    |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | `ha_get_system_info`, `ha_list_entities`, `ha_get_entity_state`, `ha_search_entities`, API-feasible automation/script/helper/dashboard/scene/blueprint list/get operations, `ha_get_config_status`, `ha_get_recent_errors`                | Documented REST/WebSocket or explicit API capability against HA OS/Core 2026.7.1 | Schemas freeze when shipped; unsupported sources return typed `capability_unavailable`. Storage-mode dashboard access must use a verified supported API, never `.storage` editing. |
| 2     | Repository-backed automation/script/helper/dashboard/scene/blueprint list/get operations, `ha_read_config_file`, `ha_search_config`, `ha_get_git_status`, `ha_get_pending_diff`, `ha_propose_config_change`, `ha_discard_proposed_change` | Safe config/Git/proposal adapters                                                | Schemas freeze when shipped; secret sources metadata-only.                                                                                                                         |
| 3     | `ha_apply_proposed_change`, `ha_validate_config`, reload tools, `ha_restart_core`, `ha_verify_change`, `ha_commit_change`, `ha_rollback_last_change`                                                                                      | Deployment capabilities, policy, transaction coordinator                         | Registered only when safety implementation is complete; runtime flags still default deny.                                                                                          |
| 4     | Structured create/update/disable tools                                                                                                                                                                                                    | Supported YAML/API resource builders                                             | Always proposal-generating; delete tools absent.                                                                                                                                   |

Each required resource tool has a source mapping decided during Phase 0 capability discovery. A tool is not considered delivered merely because a placeholder is registered. Default list limit is planned at 100, hard maximum 500, with opaque cursors; file/error limits are configuration-bound and capped by server constants. Phase exit evidence enumerates delivered versus typed-unavailable tools.

## Transport contract

The add-on MCP endpoint is disabled and unpublished by default. Add-on mode alone may
bind its container listener to a wildcard for Supervisor port forwarding; local mode
rejects wildcard binds. Every request still requires SAN-valid TLS, a paired bearer,
exact Host, no Origin/forwarding headers, declared bounded length, rate allowance, and
a client-owned unexpired session. Per-client/global session caps and idle/absolute
expiry apply; shutdown, revocation, and rotation close sessions.

## Structured tools

Automation/script/helper/dashboard/scene create/update/disable tools validate domain schemas and then call the same proposal service. Active automation updates are high risk; new disabled automations are normally low risk. Deletes are intentionally not registered initially.

## Approval and risk

Read: no approval. Low-risk write: writes must be enabled and proposal explicitly applied. High-risk: writes enabled plus approval bound to exact digest. Destructive: capability absent unless separately enabled and implemented; still requires bound approval. Feature flags cannot elevate missing HA/deployment capabilities.
