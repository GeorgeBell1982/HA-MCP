# Home Assistant Engineering MCP

Read-only Phase 1 engineering MCP for Home Assistant. It supports local stdio and an
installable HA OS aarch64 add-on with paired, TLS-only Streamable HTTP plus a pinned
local stdio bridge. Mutation, restart, deletion, `/config`, arbitrary service calls,
shell, and Git tools are absent.

See [deployment](docs/deployment.md), [Codex setup](docs/codex-setup.md),
[security](docs/security.md), and [tool reference](docs/tool-reference.md).

Validation: `pnpm verify`, `pnpm test:security`, and `pnpm test:mcp`.
