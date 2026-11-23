#!/usr/bin/env bash
# Opens N separate LokiSigner members on this Mac for testnet testing, one process per profile.
# Member 1 uses the default profile; member N > 1 uses ~/Library/Application Support/LokiSigner-memberN.
# Each window is titled "LokiSigner — Member <slot>" once its profile is paired.
#
#   apps/macos/scripts/run-members.sh 3                      # LokiSigner from /Applications
#   APP=/path/to/loki_signer.app apps/macos/scripts/run-members.sh 3
set -euo pipefail

count="${1:-}"
if ! [[ "$count" =~ ^[1-9][0-9]?$ ]]; then
  echo "usage: $0 <number of members, 1-16>" >&2
  exit 2
fi
app="${APP:-/Applications/LokiSigner.app}"
if [[ ! -d "$app" ]]; then
  echo "LokiSigner app not found at $app (set APP=...)" >&2
  exit 1
fi
support="$HOME/Library/Application Support"

open -n -a "$app"
for ((member = 2; member <= count; member++)); do
  open -n -a "$app" --args --data "$support/LokiSigner-member$member"
done
