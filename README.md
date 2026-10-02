# Home Assistant Engineering MCP

Engineering MCP for Home Assistant with read-only diagnostics and protected
configuration proposals. It supports local stdio and an
installable HA OS aarch64 add-on with paired, TLS-only Streamable HTTP plus a pinned
local stdio bridge. The managed add-on can enable Phase 2 configuration and Git
inspection plus proposal storage after startup security gates pass. Home Assistant
configuration is mounted writable at `/homeassistant` in add-on `0.2.2` for the
guarded local terminal operator; MCP proposals write only to
protected `/data`. Apply, restart, deletion, arbitrary service calls, shell, and Git
writes are absent from the MCP runtime. Phase 3 components and their disposable
workflow are composed only by the explicit local operator, with per-command write
enablement and typed terminal approval.

Start with the [current project context](docs/recovery.md#project-context-as-of-2026-10-02)
for implemented capabilities, historical live acceptance, remaining gates, and
resumption guidance. The source add-on version is `0.2.2`; deployment and acceptance
evidence are recorded separately from source publication.

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
