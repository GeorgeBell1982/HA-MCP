# Home Assistant Engineering MCP

Install version `0.2.1` from this custom add-on repository. It provides read-only
diagnostics, protected configuration inspection and proposals. It requests only
`homeassistant_api` and maps Home Assistant configuration read-only; Docker, host
networking, privileged mode, and broad Supervisor access are absent.
The ingress page is reserved for local
pairing and diagnostics and is separate from port 8443. Direct MCP HTTPS is disabled
by default. Never expose it via Cloudflare or the public Internet.

This release packages the guarded local operator for subsequent validation.
Installing it does not enable production writes. Native aarch64 build and actual
Supervisor acceptance remain to be verified on the Pi.
