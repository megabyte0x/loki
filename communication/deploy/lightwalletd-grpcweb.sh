#!/usr/bin/env bash
# Serve the two browser signer scan RPCs over binary gRPC-web (requires Node.js 22+).
set -euo pipefail
exec node "$(dirname -- "$0")/lightwalletd-grpcweb.mjs"
