#!/usr/bin/env bash
# Put frostd behind TLS + CORS so an in-browser (wasm) signer can reach it.
#
# WHY: a browser can only POST to frostd over https/wss, and only if the response carries
# CORS headers for the page's origin. frostd itself is a plaintext loopback relay
# (`frostd -n -p 2744`) that sends NO CORS headers — a `fetch()` from the wallet origin to
# http://127.0.0.1:2744 is blocked twice over (mixed content + CORS). The native
# `FrostdTransport` dials out server-to-server, so it never hit this; the wasm transport
# (`core/wasm-transport`) runs IN the page and does.
#
# This runs Caddy as a TLS-terminating reverse proxy in front of the loopback frostd and
# injects CORS for one site origin, including the OPTIONS preflight. `require_tls_off_loopback`
# in both transports already demands https off loopback, so the wasm signer points at the
# Caddy https URL, not the tunnel.
#
# Usage:
#   ORIGIN=https://wallet.example FRONT=relay.example ./frostd-tls.sh        # real cert (ACME)
#   ORIGIN=https://localhost:3011 ./frostd-tls.sh                            # local https (internal CA)
#
# Env:
#   ORIGIN      the exact browser origin allowed to call frostd (REQUIRED, no trailing slash)
#   FRONT       public hostname Caddy serves + gets an ACME cert for (default: localhost)
#   UPSTREAM    loopback IP:port, unix//path, or verified https://host[:port]
#               (default: 127.0.0.1:2744)
#   LISTEN      https port Caddy binds                 (default: 443 for a real host, else 8443)
# Requires: caddy on PATH. For a public host, FRONT must resolve to this box and 80/443 be open.
set -euo pipefail

origin=${ORIGIN:?set ORIGIN to the wallet page origin, e.g. https://wallet.example}
front=${FRONT:-localhost}
upstream=${UPSTREAM:-127.0.0.1:2744}
# Accept one literal Caddy address, not DNS for plaintext or Caddyfile placeholders.
loopback='^(http://)?(127\.0\.0\.1|\[::1\]):[0-9]{1,5}$'
socket='^unix//[a-zA-Z0-9_./-]+$'
https='^https://([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(:[0-9]{1,5})?$'
if ! [[ $upstream =~ $loopback || $upstream =~ $socket || $upstream =~ $https ]]; then
  echo 'UPSTREAM must be a literal loopback IP:port, unix//path, or https://host[:port] (certificate verified)' >&2
  exit 2
fi
if [[ $front == localhost ]]; then
  listen=${LISTEN:-8443}
  bind='bind 127.0.0.1 [::1]'
  redirect='auto_https disable_redirects'
else
  listen=${LISTEN:-443}
  bind=
  redirect=
fi
command -v caddy >/dev/null || { echo "caddy not found on PATH" >&2; exit 1; }

conf=$(mktemp -t frostd-caddy.XXXXXX)
trap 'rm -f "$conf"' EXIT
cat > "$conf" <<EOF
{
	admin off
	${redirect}
}

https://${front}:${listen} {
	${bind}
	# CORS: only the one wallet origin, and answer the preflight ourselves so frostd
	# (which emits no CORS headers) never sees the OPTIONS.
	@preflight method OPTIONS
	handle @preflight {
		header Access-Control-Allow-Origin "${origin}"
		header Access-Control-Allow-Methods "POST, OPTIONS"
		header Access-Control-Allow-Headers "authorization, content-type"
		header Access-Control-Max-Age "600"
		respond 204
	}
	handle {
		header Access-Control-Allow-Origin "${origin}"
		header Vary "Origin"
		reverse_proxy ${upstream}
	}
}
EOF

echo "frostd TLS front: https://${front}:${listen}  ->  ${upstream}   (CORS origin: ${origin})"
echo "point the wasm signer at:  https://${front}:${listen}"
caddy run --config "$conf" --adapter caddyfile &
pid=$!
stop() {
  # Bash may start background jobs with SIGINT ignored. Use TERM for both signals.
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" || true
  exit "$1"
}
trap 'stop 130' INT
trap 'stop 143' TERM
wait "$pid"
