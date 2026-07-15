# Discovery and primary-source research

Date: 2026-07-11

## Repository and toolchain

- Working directory: `C:\Users\jora4\OneDrive\Documents\Home Assistant`.
- Git: unborn `master` branch, no commits, no tracked/untracked project files, no nested `AGENTS.md`.
- Host PATH: Node.js and npm unavailable; pnpm 8.10.2 was visible during the first probe.
- Bundled workspace runtime: Node.js v24.14.0 and pnpm 11.7.0. No locally bundled `@modelcontextprotocol/sdk` package was found.
- Therefore package versions must be resolved and locked during scaffold implementation, with network/package installation explicitly approved if required.

## MCP SDK

The official repository states on 2026-07-11 that its main branch is v2 beta for the 2026-07-28 spec and v1.x remains supported for production until the stable transition. Decision: use a pinned current v1.x SDK for Phase 1; create a separate future migration ADR for v2.

Source: https://github.com/modelcontextprotocol/typescript-sdk

## Home Assistant interfaces

Official REST documentation confirms bearer authentication and documented endpoints including config, components, services, states, service calls, and check-config. Official WebSocket documentation confirms `/api/websocket`, authentication phases, command correlation, subscriptions, and service commands; Core 2026.7.2 registers the admin-only `system_log/list` WebSocket command for recent system-log entries. Configuration documentation confirms config access/validation varies by installation type and recommends reload over restart where supported.

Sources:

- https://developers.home-assistant.io/docs/api/rest/
- https://developers.home-assistant.io/docs/api/websocket/
- https://www.home-assistant.io/docs/configuration/

## Actual Home Assistant environment

User-supplied Home Assistant system information on 2026-07-11 establishes:

- Home Assistant Core `2026.7.1`, Supervisor `2026.06.2`, Home Assistant OS `18.1`.
- Home Assistant OS installation (`hassio=true`, Docker-backed), healthy and supported.
- Raspberry Pi 5 64-bit / `aarch64`; Linux `6.18.34-haos-raspi`.
- Home Assistant runs as root; configuration directory is `/config`.
- Time zone is `Africa/Johannesburg`.
- Dashboards use storage mode: 8 dashboards, 9 resources, 7 views.
- Recorder uses SQLite 3.53.2, approximately 459 MiB.
- Studio Code Server is installed, but that does not by itself grant this external MCP process safe `/config` access.

Security-relevant consequence: Home Assistant OS is appliance-managed and is not treated as a general-purpose Ubuntu/Node host. The user selected a purpose-built managed add-on. Home Assistant maps `/config` into that add-on according to declared permissions; the add-on receives no implicit host, Docker, or arbitrary container access.

## Deployment decision and remaining discovery

- Package as a custom Home Assistant add-on with `aarch64` as the required image architecture.
- Do not map `/config` in Phase 1 because no Phase 1 tool requires it. Add read-only access only with Phase 2 repository tools and security gates; writes require a later packaging revision and Phase 3 approval.
- Store proposal/audit/runtime data in the add-on data directory, not in `/config`.
- Connect Codex through authenticated Streamable HTTP or a local stdio bridge; keep direct stdio for development/tests.
- Detect whether `/config` is a Git repository read-only in Phase 2; do not initialize it automatically.
- Declare only `homeassistant_api: true`; use the Supervisor-injected runtime token solely against the fixed Home Assistant Core API proxy. Do not request general Supervisor, Docker, privileged, host-network, or host-filesystem access.
