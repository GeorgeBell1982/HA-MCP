# Changelog

## 0.1.7

- Repair Supervisor packaging after 0.1.6 rejected `build.yaml` digest fields, fell back to the reserved `BUILD_FROM` base image, and broke immutable APK package pins.
- Move the pinned Home Assistant final base image into the Dockerfile-owned `HA_BASE_FROM` argument and remove the deprecated add-on build manifest.

## 0.1.6

- Harden atomic persistence writes by completing partial writes and retrying interrupted writes across both storage mirrors.
- Add strict candidate-image validation and fail-closed native aarch64 provenance checks.
