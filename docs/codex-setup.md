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
Apply and epoch rotation are never replayed after session expiry or a lost response.
An uncertain result requires transaction inspection, not an automatic retry.
Ending the bridge's stdin or stopping it with SIGINT/SIGTERM closes its authenticated
HTTP session before exit. Shutdown is bounded so a stalled operation or remote close
cannot leave the bridge process or server-side session indefinitely.

Direct HTTP configuration is optional; local development can continue to use
`dist/index.js` over stdio with a dedicated Home Assistant user/token.

## Human approval for guarded application

Add-on `0.2.3` can opt in with `enable_mcp_writes: true` alongside `enable_phase2`.
Rebuild the local bridge and reconnect the MCP client to refresh its inventory.
Run `ha_check_approval`; it requests a harmless exact confirmation and changes no
Home Assistant state. This host must advertise MCP form elicitation and display
the prompt. Unsupported clients cannot apply proposals.

Codex must also permit MCP elicitation in its approval policy. A `never` policy can
silently decline the prompt even when the client advertises form support. To allow
human MCP prompts while retaining disabled command/permission approval categories,
the documented configuration is:

```toml
approval_policy = { granular = { sandbox_approval = false, rules = false, mcp_elicitations = true, request_permissions = false, skill_approval = false } }
approvals_reviewer = "user"
```

Changing the config file alone does not select it for an existing chat. In the
desktop app, use the permissions control below this chat's composer and select
**Custom (config.toml)**. If that mode is unavailable, **Ask for approval** is the
documented human-review mode. Available modes depend on local and organization
settings. See the [official permissions guide](https://learn.chatgpt.com/docs/permission-modes).
Then check the effective behavior using the harmless tool before a live apply.
See the [official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

`ha_apply_proposal` accepts only a proposal ID. It shows the exact redacted diff
and proposal identity through the client's approval UI, then requires an exact
typed confirmation. Approval booleans, approver names and grant IDs in tool input
are rejected. The server rereads the proposal after approval and uses an internal
short-lived single-use grant. The paired client is trusted to present this prompt
honestly; the protocol does not authenticate a human identity.

After a completed transaction, `ha_rotate_epoch` archives the protected state to
prepare the next apply. It refuses uncertain, incomplete or drifted transactions.
Manual recovery and interrupted rotation resumption remain terminal operations.
