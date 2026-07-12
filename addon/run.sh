#!/usr/bin/with-contenv bashio
set -euo pipefail
umask 077
cert=/data/tls/server.crt
key=/data/tls/server.key
export HA_MODE=addon
export HA_ENABLE_HTTP="$(bashio::config 'enable_http')"
export HA_HTTP_BIND="$(bashio::config 'bind')"
export HA_HTTP_PORT=8443
export HA_HTTP_ALLOWED_HOST="$(bashio::config 'allowed_host')"
export HA_TLS_CERT="$cert"
export HA_TLS_KEY="$key"
export HA_MAX_CLIENTS="$(bashio::config 'max_clients')"
export HA_MAX_SESSIONS_PER_CLIENT="$(bashio::config 'max_sessions_per_client')"
export HA_AUDIT_LOG_PATH=/data/audit.jsonl
exec node /app/dist/index.js
