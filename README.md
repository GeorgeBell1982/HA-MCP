# Home Assistant Engineering MCP

Engineering MCP for Home Assistant with read-only diagnostics and protected
configuration proposals and optional human-approved automation, dashboard and setup changes. It supports local stdio and an
installable HA OS aarch64 add-on with paired, TLS-only Streamable HTTP plus a pinned
local stdio bridge. The managed add-on can enable Phase 2 configuration and Git
inspection plus proposal storage after startup security gates pass. Home Assistant
configuration is mounted writable at `/homeassistant`. Add-on `0.2.3` adds
`enable_mcp_writes` (false by default): it exposes guarded application of pending
`automations.yaml` proposals with the exact redacted diff and a human confirmation
through MCP form elicitation. The client must support approval; unsupported,
declined, cancelled or stale responses fail closed. The existing validation,
checkpoint, narrow automation reload, rollback and verification remain in force.
Arbitrary services, shell and Git writes are unavailable. Initialization
and manual recovery use the local terminal operator.

Start with the [current project context](docs/recovery.md#project-context-as-of-2026-10-02)
for implemented capabilities, historical live acceptance, remaining gates, and
resumption guidance. The source add-on version is `0.3.0`; deployment and acceptance
evidence are recorded separately from source publication.

Version `0.3.0` supports storage dashboard patches with source-drift checks, exact
chat approval and read-back verification. `enable_mcp_setup` separately enables
integration flows, HACS integration/frontend repository setup and Supervisor app
management. Installation, configuration and disruptive restarts each need approval.
The manifest grants Supervisor manager authority even when setup tools are disabled.
See [third-party setup](docs/third-party-setup.md) for supported actions and secure
authentication limits. Settled checkpoints can be archived through the MCP without
changing Home Assistant; uncertain records remain active. The private archive holds
at most 1,024 records and active history at most 128 before archival is required.
An interrupted archive can leave records split between active and archived storage;
status lookup checks both and no checkpoints are deleted. Dashboard saves have no
atomic compare-and-save API, so a concurrent external editor remains a residual race.

See [deployment](docs/deployment.md), [Codex setup](docs/codex-setup.md),
[security](docs/security.md), and [tool reference](docs/tool-reference.md).

Validation: `pnpm verify`, `pnpm test:security`, and `pnpm test:mcp`.

## Linux-only native reliability lanes

These repository-owned tests remain outside the add-on bundle.

Git candidate matrix:

    pnpm validate:linux:git

Persistence reliability matrix:

    node scripts/linux/persistence-harness.mjs --cc cc --tmpfs-root /path/to/dedicated-bounded-tmpfs

The persistence lane requires a dedicated tmpfs no larger than 128 MiB because its
ENOSPC row deliberately fills and then cleans that filesystem.
