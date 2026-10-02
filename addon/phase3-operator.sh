#!/bin/sh
set -eu
umask 077
export HA_MODE=addon
exec node /app/dist/cli.js phase3 "$@"
