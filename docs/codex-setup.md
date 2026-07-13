# Codex stdio bridge setup

Build on the Codex computer with Node 22 or 24 and `pnpm install --frozen-lockfile &&
pnpm build`. Save the one-time pairing credential in a user-only file. Save the
verified add-on certificate separately.

Configure the MCP command as `node /absolute/path/dist/bridge.js` with:

- `HA_MCP_URL=https://192.168.50.160:8443/mcp`
- `HA_MCP_CREDENTIAL_FILE=/absolute/private/path/credential`
- `HA_MCP_CA_FILE=/absolute/private/path/server.crt`
- `HA_MCP_CERT_SHA256=<64 lowercase hex digits shown and independently verified>`
- `NODE_EXTRA_CA_CERTS=/absolute/private/path/server.crt`

The bridge refuses HTTP, a missing pin, a mismatched certificate, or a CA file not
selected before process startup. It does not accept the credential in command-line
arguments, URLs, or environment values. It applies bounded MCP reconnection. Restrict
the credential file to the desktop user and rotate/revoke it from ingress if copied,
lost, or exposed.

If the add-on expires an otherwise authenticated HTTP session, the bridge creates a
new pinned and authenticated session and retries the queued read-only request once.
Authentication, rate-limit, TLS, network, and endpoint failures are not retried.

Direct HTTP configuration is optional; local development can continue to use
`dist/index.js` over stdio with a dedicated Home Assistant user/token.
