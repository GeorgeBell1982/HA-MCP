# Architecture

The current read-only application registry is shared by stdio and authenticated HTTPS MCP. The HA REST adapter accepts only an origin in local mode, normalizes it to `/api`, and uses the fixed Core proxy in add-on mode. Every call first establishes audit availability; results and errors are redacted and bounded. WebSocket-backed tools, repository, Git, proposal, and mutation capabilities remain unavailable.

Direct HTTPS is disabled by default. Pairing creates a 128-bit public client ID and 256-bit secret, persists only salted scrypt material, and uses constant-time verification. The add-on generates a SAN-bound P-256 certificate and publishes its SHA-256 fingerprint. Add-on mode permits an internal wildcard solely for Supervisor port forwarding while the host port remains unpublished by default; local mode rejects wildcard binds. TLS/auth/Host/Origin enforcement and bounded client-owned sessions remain mandatory.
