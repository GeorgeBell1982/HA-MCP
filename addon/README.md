# Home Assistant Engineering MCP

Install from this custom add-on repository. Phase 1 is read-only and requests only
`homeassistant_api`; `/config`, Docker, host networking, privileged mode, and broad
Supervisor access are deliberately absent. The ingress page is reserved for local
pairing and diagnostics and is separate from port 8443. Direct MCP HTTPS is disabled
by default. Never expose it via Cloudflare or the public Internet.
