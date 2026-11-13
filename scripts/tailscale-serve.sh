#!/bin/sh
# Explicitly configure a dedicated node; never reset another service's Serve config.
set -eu
ts_bin=${TAILSCALE_BIN:-tailscale}
command -v "$ts_bin" >/dev/null 2>&1 || {
  echo 'Tailscale CLI not found; set TAILSCALE_BIN or install/enroll the chosen host.' >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required to validate existing Tailscale configuration.' >&2
  exit 1
}
ts() {
  if [ -n "${TAILSCALE_SOCKET:-}" ]; then
    "$ts_bin" --socket="$TAILSCALE_SOCKET" "$@"
  else
    "$ts_bin" "$@"
  fi
}
ts_state=$(ts status --json)
printf '%s' "$ts_state" | python3 -c '
import json, sys
s = json.load(sys.stdin)
if s.get("BackendState") != "Running":
    sys.exit("Tailscale must already be authenticated and running.")
'
ts_serve=$(ts serve status --json)
printf '%s' "$ts_serve" | python3 -c '
import json, sys
s = json.load(sys.stdin)
if s not in ({}, None):
    sys.exit("Existing Serve configuration found; inspect it and use a dedicated node. Nothing changed.")
'
ts serve --bg --https=443 http://127.0.0.1:8787
