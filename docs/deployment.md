# Home Assistant OS add-on deployment

The supported Phase 1 target is Home Assistant OS 18.1 on Raspberry Pi 5
(`aarch64`). No host shell is needed.

1. Use the published add-on repository URL:
   `https://github.com/GeorgeBell1982/HA-MCP`.
2. In **Settings > Apps > App store > Repositories**, add that repository URL.
3. Install **Home Assistant Engineering MCP**. Leave `enable_http: false`, start it,
   and open its ingress panel. The operator page at `/` shows health, fingerprint,
   and paired clients.
4. Select **Pair new client**. Copy the displayed one-time credential immediately
   into a local file readable only by your desktop account; the page does not persist
   it and the add-on stores only scrypt material. Use the client buttons to rotate or
   revoke individual credentials.
5. Download the public certificate from the operator page and compare its displayed
   SHA-256 fingerprint independently before copying it to the Codex computer.
6. Keep the internal add-on `bind` at `0.0.0.0` so Supervisor port forwarding can reach it, set the matching external-LAN `allowed_host`, publish TCP 8443,
   then set `enable_http: true` and restart the add-on.

The wildcard is permitted only in verified add-on mode; the port remains unpublished (`null`) until explicitly configured, TLS/auth and exact Host checks remain mandatory, and local mode still rejects wildcard binds. The add-on requests only `homeassistant_api`. It has `map: []` and no Docker,
privileged, host-network, or broad Supervisor access. Inside the add-on container,
port 8099 binds a wildcard so the Supervisor ingress proxy can reach it, but it has no
host port mapping and is accessible only through authenticated Home Assistant ingress.
Port 8443 is TLS-only MCP and is disabled by
default. Plaintext non-loopback MCP, browser `Origin` requests, mismatched `Host`,
and forwarded/proxied requests are rejected. Public and Cloudflare exposure is not
supported.

Certificate generation uses ECDSA P-256 and SHA-256 and stores key/certificate under
`/data/tls` with umask 077. The ingress operator page displays the DER certificate
fingerprint and provides the public certificate download. Its rotate-certificate
button creates a replacement identity and reports its fingerprint.
If replacement is interrupted, startup validates the key/certificate pair and safely
regenerates mismatched state. Restart afterward and replace every bridge certificate
and pin; the running listener retains its old in-memory identity until restart.

Repository builds and tests do not install or contact Home Assistant. Live acceptance is recorded separately below and never authorizes mutation or deployment.

## Live acceptance record: 2026-07-15

The deployed add-on was version 0.1.4 on the actual HA OS/aarch64 target with Core 2026.7.2. The read-only bridge discovered all 15 tools; direct bridge and registered Codex MCP system-information calls passed, and bridge shutdown exited cleanly. System information, entity pagination, entity search/state, automation/script/helper/scene reads, expected dashboard/blueprint capability refusals, schema limits, and the absence of mutation-like tools passed. All calls returned request IDs through the fail-closed audit middleware; the audit file was not independently inspected.

Two deployed 0.1.4 checks failed: `ha_get_recent_errors` received a safe `upstream_error` from the nonexistent REST error-log route (HTTP 404), and malformed cursor `!!!` was accepted. Repository candidate 0.1.5 replaces that route with validated `system_log/list` WebSocket reads and requires canonical cursor encoding. Candidate 0.1.5 has not been deployed; both fixes remain `UNVERIFIED` live until an explicitly authorized add-on deployment and read-only retest.
