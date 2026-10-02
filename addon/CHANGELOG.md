# Changelog

## 0.2.2

- Permit the guarded local terminal operator by mapping Home Assistant configuration writable. Installing this version expands container filesystem permissions.
- Keep MCP tools read-only; each apply/recovery command still requires `--enable-writes`, a real terminal and exact typed confirmation. No automatic apply, reload or recovery is enabled.
- Native Pi real Home Assistant workflow passed all 24 checks; approval, persistence and isolated workflow matrices also passed. Git remains unavailable on Pi kernels without Landlock.

## 0.2.1

- Add the guarded automation proposal path, Home Assistant semantic validation and loaded-configuration verification.
- Package the explicit local terminal operator with audited approval/recovery and bounded transaction archive/resume.
- Keep MCP tools and the Home Assistant configuration mount read-only; installing this release does not enable apply, reload or recovery writes.
- Pass 1,340 tests and 24 disposable Linux amd64/Home Assistant workflow checks. Native Raspberry Pi aarch64 build and actual Supervisor acceptance remain to be verified on the Pi.

## 0.2.0

- Activate secure read-only Home Assistant configuration inspection and protected proposal tools behind an add-on switch.
- Mount Home Assistant configuration read-only; proposals persist only under `/data` and cannot apply, reload, restart, or write Git state.

## 0.1.7

- Repair Supervisor packaging after 0.1.6 rejected `build.yaml` digest fields, fell back to the reserved `BUILD_FROM` base image, and broke immutable APK package pins.
- Move the pinned Home Assistant final base image into the Dockerfile-owned `HA_BASE_FROM` argument and remove the deprecated add-on build manifest.

## 0.1.6

- Harden atomic persistence writes by completing partial writes and retrying interrupted writes across both storage mirrors.
- Add strict candidate-image validation and fail-closed native aarch64 provenance checks.
