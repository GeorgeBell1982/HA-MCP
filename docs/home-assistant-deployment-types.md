# Home Assistant deployment types

- Home Assistant OS: the repository ships an installable `aarch64` managed add-on with only `homeassistant_api` and no `/config` mapping.
- Supervised: same add-on contract where supported.
- Container/Core: local process uses an explicit origin and dedicated token.

Filesystem, validation, reload, restart, and Git adapters are negotiated capabilities. Their absence never triggers a shell fallback.
