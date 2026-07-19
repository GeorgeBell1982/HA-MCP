# Home Assistant Engineering MCP

Read-only Phase 1 engineering MCP for Home Assistant. It supports local stdio and an
installable HA OS aarch64 add-on with paired, TLS-only Streamable HTTP plus a pinned
local stdio bridge. Mutation, restart, deletion, `/config`, arbitrary service calls,
shell, and Git tools are absent.

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
