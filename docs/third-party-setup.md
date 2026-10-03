# Third-party setup through MCP

Setup tools require the separate `enable_mcp_setup` opt-in and guarded MCP writes. The add-on needs Supervisor manager API access for store/app management. Local mode cannot manage Supervisor apps. Integration flows need a browser-accessible Home Assistant origin in `setup_frontend_url` (`HA_SETUP_FRONTEND_URL`), or a valid Core-configured internal/external URL. The Supervisor API proxy is never used as a browser callback origin.

The agent reads the installed integration/HACS/app catalogs, prepares a specific change, asks the originating chat for approval through `ha_apply_change`, sends the approved operation once, and checks its observed result. Source registration, installation, configuration, start and restart are separate proposals so that approval describes each effect. Preparation never installs code or advances an integration flow.

## Tools

- `ha_list_setup_catalog`: `kind` is `integration`, `hacs` or `app`; optional `query` and bounded `limit` filter the configured catalogs.
- `ha_get_setup_status`: `kind` is `integration`, `flow`, `hacs` or `app`. Except for integration entry listings, supply the catalog/flow `target` ID. Flow status reads a cached response and never calls Core's advancing flow GET route.
- `ha_propose_setup_change`: prepares one of the finite actions below. Apply the returned proposal with `ha_apply_change`; inspect `ha_get_change_status` if a result is uncertain. Pending plans and cached flows expire when the runtime restarts.

| Action                | Required fields                                                              | Effect after approval                                                                             |
| --------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `integration_start`   | `domain` from catalog                                                        | Starts that loaded config-flow handler.                                                           |
| `integration_submit`  | `flowId`, non-secret `fields`                                                | Refreshes the approved flow, checks its step/schema, submits offered fields only.                 |
| `hacs_add_repository` | GitHub `repository` as `owner/repo`, `category` as `integration` or `plugin` | Registers the exact custom HACS source.                                                           |
| `hacs_install`        | `repositoryId`, exact catalog `version`                                      | Downloads a new integration or frontend repository through HACS.                                  |
| `app_add_repository`  | GitHub `repository` as `owner/repo`                                          | Registers its canonical HTTPS GitHub app-store source.                                            |
| `app_install`         | catalog `slug`                                                               | Installs the selected app; verifies its approved catalog version.                                 |
| `app_options`         | installed `slug`, non-secret scalar/list `options`                           | Merges offered options, preserves existing options, verifies the complete resulting options hash. |
| `app_start`           | installed, stopped `slug`                                                    | Starts that app and verifies started state.                                                       |
| `app_restart`         | installed, started `slug`                                                    | Restarts that app once and checks readiness.                                                      |
| `core_restart`        | none                                                                         | Restarts Core once and checks that its API reports `RUNNING`.                                     |

App installation approval displays catalog version, source and declared security privileges. Successful installation requires both exact-version membership in Supervisor's installed-only `/addons` inventory and an installed info state (`started` or `stopped`); the uninstalled catalog fallback cannot prove installation. App self-management and system-managed app changes are refused. Setup never disables protection, adds arbitrary network/device privileges, updates existing HACS installations, deletes entries, installs files directly, or accepts arbitrary API paths, WebSocket command types or shell commands. Repository inputs accept GitHub identifiers only. HACS's recorded version is checked; this is not a cryptographic artifact digest.

Core and app restarts are disruptive and require their own approval. Integration installation can report that a Core restart is required; it never restarts automatically. Restart verification uses at most six 15-second passive reads separated by two seconds, and never resends the restart request. Lost responses and failed verification remain uncertain instead of being treated as success.

## Authentication and supported flow steps

The agent can progress scalar/list, non-secret form fields offered by a loaded integration handler, or a simple menu by submitting exactly one offered `next_step_id`. Menu lists are bounded to 64 simple step identifiers; unsupported menus receive a secure handoff. The API validates integration-specific values. Other flow types and credential fields return a precise secure handoff to `/config/integrations`; passwords, OAuth URLs/tokens, raw config-entry data, flow context, schema defaults and description placeholders are not returned to chat. Required sensitive fields cannot be bypassed with an empty submission. Credentials cannot be supplied in tool arguments or approval text. Provider login, MFA and consent still belong to the account owner inside Home Assistant's authentication interface.

Core's flow-resource GET calls `async_configure`, so it can advance the flow. It is part of the approved submission action, never a read/status tool. A step/schema change during that approved refresh prevents submission and leaves an inspectable uncertain result. Flow results are process-local; a pre-existing browser flow cannot be taken over by guessing its ID. A provider flow that requires unsupported selectors or authentication is not claimed to be fully configured.

Every create/refresh/submit call sends `HA-Frontend-Base` using a validated browser origin, as required by Core's OAuth redirect construction. The approval summary displays that exact credential-free callback origin. Missing origin configuration refuses preparation before a flow is sent. Nonterminal flow responses must identify the approved handler and a usable flow ID; submissions cannot substitute the flow ID, and created entries must belong to the approved domain. Terminal responses may omit the handler when their entry/domain evidence is sufficient.

## Source and verification evidence

API contracts were checked against the installed Core **2026.9.4** and HACS **2.0.5** source files over read-only SSH. HACS `repository/info` can refresh metadata and clear its new flag, so setup reads use `hacs/repositories/list` instead.

- [Core 2026.9.4 config-entry views](https://github.com/home-assistant/core/blob/2026.9.4/homeassistant/components/config/config_entries.py): handler and entry lists, start/configure flow routes.
- [Core 2026.9.4 flow views](https://github.com/home-assistant/core/blob/2026.9.4/homeassistant/helpers/data_entry_flow.py): GET flow advancement and serialized field schema.
- [Core 2026.9.4 OAuth flow helper](https://github.com/home-assistant/core/blob/2026.9.4/homeassistant/helpers/config_entry_oauth2_flow.py): browser frontend base header and provider authentication redirect handling.
- [Core 2026.9.4 flow manager](https://github.com/home-assistant/core/blob/2026.9.4/homeassistant/data_entry_flow.py): menu `next_step_id` submission and handler/flow identifiers.
- [HACS 2.0.5 repository list/add commands](https://github.com/hacs/integration/blob/2.0.5/custom_components/hacs/websocket/repositories.py): integration/frontend catalog and custom repository registration.
- [HACS 2.0.5 download commands](https://github.com/hacs/integration/blob/2.0.5/custom_components/hacs/websocket/repository.py): exact repository/version download; no direct filesystem installer.
- [Supervisor API endpoints](https://developers.home-assistant.io/docs/api/supervisor/endpoints/): modern `/store/addons/{slug}/install`, repository registration, app info/options/start/restart, Core info/restart.

Focused setup tests cover exact approval/no effects before approval, declined approval, stale target refusal, catalog misses/version refusal, GitHub-only registration and verification, declared app privileges, credential rejection/redaction, non-secret options preserving stored secrets, flow step drift, secure OAuth handoff, durable attempt audit refusal, restart single-send behavior and finite API routes. These tests use disposable mocked upstreams and do not prove a live third-party installation or provider authentication. No live install or restart was performed during implementation.
