#!/usr/bin/env bash
# Builds the confidential-router enclave image + EIF and prints PCR0/1/2 — the measurement
# the client-sidecar pins. No sudo required. Paths resolve relative to this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # .../deploy/enclave
REPO="$(cd "$HERE/../.." && pwd)"                    # repo root (sub2api)
BACKEND="$REPO/backend"

IMAGE="${IMAGE:-confidential-router:local}"
EIF="$HERE/router.eif"
NITRIDING_COMMIT="2b7dfefaee56819681b7f5a4ee8d66a417ad457d" # pinned; matches the verified spike
NITRIDING_BIN="${NITRIDING_BIN:-/home/ubuntu/nitriding-spike/nitriding-daemon/nitriding}"

echo ">> building enclave-core (static, stripped)"
(cd "$BACKEND" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "$HERE/enclave-core" ./cmd/enclave-core)

echo ">> obtaining nitriding (pinned $NITRIDING_COMMIT)"
if [ -x "$NITRIDING_BIN" ]; then
	cp "$NITRIDING_BIN" "$HERE/nitriding"
else
	TMP="$(mktemp -d)"
	git clone https://github.com/brave/nitriding-daemon.git "$TMP/nitriding-daemon"
	git -C "$TMP/nitriding-daemon" checkout "$NITRIDING_COMMIT"
	(cd "$TMP/nitriding-daemon" && make nitriding)
	cp "$TMP/nitriding-daemon/nitriding" "$HERE/nitriding"
	rm -rf "$TMP"
fi

echo ">> docker build $IMAGE"
docker build -t "$IMAGE" "$HERE"

echo ">> nitro-cli build-enclave -> $EIF"
nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF"

echo ">> measurements (pin PCR0/1/2 in the client-sidecar):"
nitro-cli describe-eif --eif-path "$EIF" | grep -E '"PCR[012]"'
