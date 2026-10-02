# Home Assistant Engineering MCP

Install version `0.2.3` from this custom add-on repository. It provides read-only
diagnostics, protected configuration inspection and proposals. It requests only
`homeassistant_api` and maps Home Assistant configuration writable for the guarded
local terminal operator and opt-in MCP application; Docker, host
networking, privileged mode, and broad Supervisor access are absent.
The ingress page is reserved for local
pairing and diagnostics and is separate from port 8443. Direct MCP HTTPS is disabled
by default. Never expose it via Cloudflare or the public Internet.

`enable_mcp_writes` defaults to false. When enabled with Phase 2 active, each MCP
apply requests human approval of the exact pending automation proposal and redacted
diff using form elicitation. Use `ha_check_approval` to verify the chat prompt first;
it makes no Home Assistant changes. Clients without approval support fail closed.
Every paired client is trusted to present human prompts honestly; this is not
cryptographic proof of human identity. Revoke clients you do not trust.
Local apply/recovery still requires a real terminal, `--enable-writes` and exact
typed confirmation. Manual recovery and initialization remain local.
The native Pi real HA workflow passed all 24 disposable checks. Keep an external
backup before operator use. Git requires a kernel with Landlock support.
