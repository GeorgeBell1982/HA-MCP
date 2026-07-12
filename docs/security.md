# Security contract

Phase 1 is read-only. The add-on requests only `homeassistant_api`, has no `/config`
mapping, and the MCP inventory contains no mutation, restart, delete, generic service,
shell, file, or Git capability.

Direct MCP is off by default and requires ECDSA P-256 TLS with an IP/DNS SAN matching
the external endpoint, a paired client, exact `Host`, no browser `Origin`, and no forwarding headers. The
ingress listener is separate and loopback-only. Each client has a random 128-bit ID
and 256-bit secret; only salted scrypt hashes persist. Revocation and rotation are
per-client. MCP sessions are owned by the authenticating client and limited per
client; another client receives no session existence oracle.

The container uses an internal wildcard only in add-on mode because Supervisor port
forwarding cannot reach container loopback; the host port defaults unpublished and
local mode rejects wildcard binds. Headers and declared bodies are bounded, chunked
POSTs are rejected, and per-client/global sessions, request rate, idle lifetime, and
absolute lifetime are limited. Shutdown and client revocation/rotation clean sessions.

The bridge takes credentials only from a protected file and requires both the copied
certificate as a startup trust anchor and an independently verified SHA-256 DER
certificate fingerprint. Public, Cloudflare, reverse-proxy, and plaintext non-loopback
operation are unsupported.

The Supervisor token is runtime-injected and used only against the fixed Core proxy.
REST redirects are rejected and safe reads have bounded retries/timeouts. WebSocket
authentication, requests, disconnect rejection, timeouts, and bounded reconnect are
implemented without putting credentials in URLs. Audit JSONL is mandatory, redacted,
synced before results return, and failure closes tool calls.
