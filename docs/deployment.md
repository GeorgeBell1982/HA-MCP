# Home Assistant OS add-on deployment

The supported Phase 1 target is Home Assistant OS 18.1 on Raspberry Pi 5
(`aarch64`). No host shell is needed.

Source release `0.2.2` permits the guarded local operator with a writable
configuration mapping. MCP tools remain read-only; local apply/recovery still
require `--enable-writes`, a real terminal and exact typed approval. Home
Assistant builds this add-on locally on the Pi; no prebuilt `image` is configured.
Refresh the repository in the App store, confirm version `0.2.2`, and install or
update it only when local operator capability is wanted. Keep existing pairing
and network options. Installation expands filesystem permissions; no proposal
is automatically applied. Native Pi disposable workflow evidence is recorded in
the requirements ledger; actual production deployment is recorded separately.

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

The wildcard is permitted only in verified add-on mode; the port remains unpublished (`null`) until explicitly configured, TLS/auth and exact Host checks remain mandatory, and local mode still rejects wildcard binds. The add-on requests only `homeassistant_api`. It has only the writable `homeassistant_config` mapping and no Docker,
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

## Guarded local operator in 0.2.2

After updating, verify Supervisor reports `0.2.2` and its `/homeassistant` mount
is writable. In an actual interactive terminal inside the MCP container, run
`/app/phase3-operator init` once to initialize protected operator state. It does
not apply a proposal or reload Home Assistant. Never replace/delete missing or
uncertain keys to bypass a refusal.

For a specific pending supported automation proposal, run
`/app/phase3-operator apply-proposal <UUID> --enable-writes`, review the displayed
diff and type its exact confirmation. Recovery independently requires
`/app/phase3-operator recover --enable-writes` and its displayed confirmation.
There is no unattended `--yes` path or persistent global write-enable option.
Do not run these effect commands just to test that enablement worked.

Keep a backup outside the Pi. Restore testing may be waived explicitly by the
deployment owner; record the untested status. MCP tools and runtime policy remain
read-only, regardless of the writable mount or operator initialization.

## Historical read-only Pi packaging checks for 0.2.1

Run the following inside the **Engineering MCP add-on container**. A shell in a
different Terminal/SSH add-on has a different filesystem and cannot validate these
paths. The commands inspect runtime/artifact metadata and import the operator
module; they do not initialize keys/state, approve proposals or change HA config.

```sh
set -eu
uname -m
node --version
stat -c '%u:%g %a %n' /app/phase3-operator /app/native/git-broker /app/native/openat2-list /app/native/openat2-read /app/native/openat2-replace
sha256sum /app/native/git-broker /app/native/openat2-list /app/native/openat2-read /app/native/openat2-replace
ldd /app/native/openat2-replace
node --input-type=module -e 'const m = await import("/app/dist/phase3/operatorRuntime.js"); if (typeof m.runPhase3OperatorCommand !== "function") process.exit(1); console.log("operator module available", process.arch);'
node --input-type=module -e 'import fs from "node:fs"; try { fs.accessSync("/homeassistant", fs.constants.W_OK); console.log("config mount writable: unexpected for 0.2.1"); process.exitCode = 1; } catch (e) { if (e.code === "EROFS") console.log("config mount read-only (EROFS)"); else { console.log("config mount unavailable", e.code); process.exitCode = 1; } }'
if [ -d /homeassistant/.git ] && [ ! -L /homeassistant/.git ]; then
  echo 'direct Git metadata directory present'
else
  echo 'direct Git metadata directory absent or unsupported'
fi
```

Expected on the Pi: `aarch64`/`arm64`, a supported Node version, wrapper and four
helpers owned by `0:0` with mode `555`, resolved loader/libcrypto linkage, importable
operator composition, and a read-only configuration mount. Preserve the helper
hashes as target evidence; amd64 helper hashes are not expected to match aarch64.
The Node access check matches the operator's actual preflight. BusyBox shell
`test -w` can report writable based on permissions even on the Pi's read-only bind
mount; do not use it as read-only proof. Missing/permission-denied mounts fail the
snippet and are not reported as read-only.
This checks packaging availability, not the complete native security/fault matrix
or a human-approved apply/recovery workflow.

Git inspection requires a normal direct `.git` directory and supported local
repository configuration. If it is absent, Git tools may refuse while configuration
inspection and proposal tools work. If it exists, `repository_unavailable` can
still indicate unsupported topology/configuration or confinement/runtime failure;
the directory check alone cannot identify the cause. Configuration is not
automatically initialized as a Git repository.

The actual Pi kernel `6.18.39-haos-raspi` was checked on 2026-10-02 and has
`CONFIG_SECURITY_LANDLOCK` disabled. The packaged Git broker requires Landlock;
its native matrix failed because `landlock_create_ruleset` returned `ENOSYS`.
Git therefore remains unavailable on this kernel even if a repository is created.
Configuration inspection and proposal tools have separate boundaries. Do not
disable broker confinement to bypass this refusal; a supported kernel or reviewed
equivalent confinement is required. See the
[native Git evidence](requirements-ledger.md#native-pi-git-confinement-blocker-on-2026-10-02).

## Live acceptance record: 2026-07-15

The deployed add-on was version 0.1.4 on the actual HA OS/aarch64 target with Core 2026.7.2. The read-only bridge discovered all 15 tools; direct bridge and registered Codex MCP system-information calls passed, and bridge shutdown exited cleanly. System information, entity pagination, entity search/state, automation/script/helper/scene reads, expected dashboard/blueprint capability refusals, schema limits, and the absence of mutation-like tools passed. All calls returned request IDs through the fail-closed audit middleware; the audit file was not independently inspected.

Two deployed 0.1.4 checks failed: `ha_get_recent_errors` received a safe `upstream_error` from the nonexistent REST error-log route (HTTP 404), and malformed cursor `!!!` was accepted. These failures are retained as historical evidence.

Installed add-on 0.1.5 subsequently passed the complete read-only retest against Core 2026.7.2 in `RUNNING` state. `ha_get_recent_errors` passed through authenticated WebSocket `system_log/list`, returning 21 structured entries with `truncated: false`, the expected bounded keys, and no exception field. Cursor `!!!` returned `invalid_input`; valid cursor `Mg` returned two items and next cursor `NA`. System information, entity pagination/search/state, automation/script/helper/scene reads, expected dashboard/blueprint capability refusals, schema-limit failures, the 15-tool inventory, and absence of mutation-like tools all passed. The bridge recovered across the add-on release. Phase 1 live acceptance is `PASSED`; no mutation was performed or authorized.
