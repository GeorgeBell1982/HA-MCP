#!/usr/bin/with-contenv bashio
set -euo pipefail
umask 077
cert=/data/tls/server.crt
key=/data/tls/server.key
export HA_MODE=addon
export HA_ENABLE_HTTP="$(bashio::config 'enable_http')"
export HA_ENABLE_PHASE2="$(bashio::config 'enable_phase2')"
export HA_HTTP_BIND="$(bashio::config 'bind')"
export HA_HTTP_PORT=8443
export HA_HTTP_ALLOWED_HOST="$(bashio::config 'allowed_host')"
export HA_TLS_CERT="$cert"
export HA_TLS_KEY="$key"
export HA_MAX_CLIENTS="$(bashio::config 'max_clients')"
export HA_MAX_SESSIONS_PER_CLIENT="$(bashio::config 'max_sessions_per_client')"
export HA_AUDIT_LOG_PATH=/data/audit.jsonl
export HA_PHASE2_ROOT=/homeassistant
export HA_PHASE2_READ_HELPER=/app/native/openat2-read
export HA_PHASE2_LIST_HELPER=/app/native/openat2-list
export HA_PHASE2_GIT_BROKER=/app/native/git-broker
export HA_PHASE2_GIT=/usr/bin/git
export HA_PHASE2_RUNTIME_LOADER=/lib/ld-musl-aarch64.so.1
export HA_PHASE2_RUNTIME_INPUTS=/usr/lib/libpcre2-8.so.0.14.0:/usr/lib/libz.so.1.3.2
export HA_PHASE2_STATE_ROOT=/data/phase2
exec node /app/dist/index.js
