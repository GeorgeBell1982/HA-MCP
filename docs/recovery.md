# Recovery

- Audit unavailable: stop the service, restore writable protected `/data`, then restart. Calls fail closed.
- Token expired: replace the local secret or restart the add-on so Supervisor injects the current runtime token. Diagnostics never print it.
- HTTP identity changed: do not bypass pinning; use authenticated ingress to download and verify the new public certificate, then update bridge pins.
- Validation, reload, mid-write crash, stale proposal, Git dirt, and failed startup: these workflows do not exist in read-only Phase 1. Do not attempt manual recovery through this server.

Before any later write phase, create and test a Home Assistant backup and retain the global mutation kill switch.
