# Home Assistant Engineering MCP

Install version `0.2.2` from this custom add-on repository. It provides read-only
diagnostics, protected configuration inspection and proposals. It requests only
`homeassistant_api` and maps Home Assistant configuration writable for the guarded
local terminal operator; Docker, host
networking, privileged mode, and broad Supervisor access are absent.
The ingress page is reserved for local
pairing and diagnostics and is separate from port 8443. Direct MCP HTTPS is disabled
by default. Never expose it via Cloudflare or the public Internet.

Installing this release expands container filesystem permissions. MCP tools remain
read-only. Each local apply/recovery requires a real terminal, `--enable-writes`
and exact typed confirmation; there is no automatic apply or MCP approval endpoint.
The native Pi real HA workflow passed all 24 disposable checks. Keep an external
backup before operator use. Git requires a kernel with Landlock support.
