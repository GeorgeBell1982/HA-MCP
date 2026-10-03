# Phase 1 tool reference

Phase 1 tools are read-only and return a bounded envelope. Entity lists default to 100 and cap at 500.

Available through documented REST: `ha_get_system_info`, `ha_list_entities`, `ha_get_entity_state`, `ha_search_entities`, automation/script/helper/scene list and entity-get operations, and `ha_get_config_status`. Bounded `ha_get_recent_errors` summaries use Home Assistant's authenticated `system_log/list` WebSocket command and discard exception details.

`ha_list_dashboards({})` and `ha_get_dashboard({urlPath})` use the authenticated
Lovelace WebSocket API. Dashboard reads return redacted configuration plus a hash
of the original source. `ha_list_blueprints` remains unavailable. Repository/Git/
proposal/mutation tools are not registered in Phase 1. No arbitrary shell,
file-write, delete, or service-call tool exists.

## Dashboard changes and setup in 0.3.0

Guarded writes expose `ha_propose_dashboard_change({urlPath,expectedSha256,patch})`,
`ha_apply_change({proposalId})`, `ha_get_change_status({proposalId})` and
`ha_propose_change_archive({})`. Dashboard patches use bounded add/replace/remove
JSON pointers, reject secret changes and operate only on explicit storage dashboards.
Approval shows the exact diff. The source is checked again immediately before one
save, then read back. Lost responses remain uncertain and cannot be replayed.
Settled history is archived privately after approval; checkpoints are retained.
With `enable_mcp_setup` enabled, the three [setup tools](third-party-setup.md)
add integration flows, HACS integration/frontend components and Supervisor apps.

## Opt-in guarded automation application

These tools register only in the managed add-on with Phase 2 active and
`enable_mcp_writes: true`:

- `ha_check_approval({})`: harmless chat approval display check; no HA effects.
- `ha_apply_proposal({proposalId})`: exact-diff form approval, semantic validation,
  checkpoint, guarded replacement of `automations.yaml`, automation reload and
  loaded-state verification. Automatic rollback handles supported failed outcomes.
  Never blindly retry an uncertain result.
- `ha_rotate_epoch({})`: archive the completed transaction; no configuration write
  or reload. Refuses nonterminal, uncertain, manual or drifted state.

Unsupported, declined, cancelled, expired or stale approvals issue no grant.
Initialization and manual recovery remain local terminal operations.
