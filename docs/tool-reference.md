# Phase 1 tool reference

All tools are read-only and return a bounded envelope. Entity lists default to 100 and cap at 500.

Available through documented REST: `ha_get_system_info`, `ha_list_entities`, `ha_get_entity_state`, `ha_search_entities`, automation/script/helper/scene list and entity-get operations, `ha_get_config_status`, and bounded `ha_get_recent_errors` summaries.

`ha_list_dashboards`, `ha_get_dashboard`, and `ha_list_blueprints` return `capability_unavailable` because no verified documented API is used. Repository/Git/proposal/mutation tools are not registered in Phase 1. No arbitrary shell, file-write, delete, or service-call tool exists.
