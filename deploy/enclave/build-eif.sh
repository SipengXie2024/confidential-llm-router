#!/usr/bin/env bash
# Builds the confidential-router enclave image + EIF and prints PCR0/1/2 — the measurement
# the client-sidecar pins. No sudo required. Paths resolve relative to this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # .../deploy/enclave
REPO="$(cd "$HERE/../.." && pwd)"                    # repo root (sub2api)
BACKEND="$REPO/backend"

IMAGE="${IMAGE:-confidential-router:local}"
EIF="${EIF:-$HERE/router.eif}"
NITRIDING_COMMIT="2b7dfefaee56819681b7f5a4ee8d66a417ad457d" # pinned; matches the verified spike
NITRIDING_BIN="${NITRIDING_BIN:-/home/ubuntu/nitriding-spike/nitriding-daemon/nitriding}"
NITRIDING_SHA256="${NITRIDING_SHA256:-7a9e8aa7485b1f665b6acd98ed088f8af10f022ecbb6f16cdfc1dfb8bc3d617c}" # integrity-pin the exact nitriding binary baked into the EIF

# Reproducible-build inputs (so two builds of the same source yield identical PCR0/1/2):
# pin SOURCE_DATE_EPOCH (BuildKit clamps image timestamps to it; Go uses -trimpath) + the toolchain.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || echo 1700000000)}"
export DOCKER_BUILDKIT=1
want_go="go$(awk '/^go /{print $2; exit}' "$BACKEND/go.mod")"
# go.mod's `go` directive + GOTOOLCHAIN=auto pins the build toolchain (auto-fetched) IN the module,
# so read the effective version from inside $BACKEND (not the base `go` on PATH).
have_go="$( (cd "$BACKEND" && go version) | awk '{print $3}')"
[ "$have_go" = "$want_go" ] || { echo "!! go toolchain $have_go != go.mod $want_go (reproducibility needs the pinned toolchain)" >&2; exit 1; }
echo ">> pinned inputs: $have_go; $(nitro-cli --version 2>/dev/null | head -1); SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

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
have_nitriding_sha="$(sha256sum "$HERE/nitriding" | awk '{print $1}')"
[ "$have_nitriding_sha" = "$NITRIDING_SHA256" ] || {
	echo "!! nitriding sha256 $have_nitriding_sha != pinned $NITRIDING_SHA256" >&2
	exit 1
}
echo ">> nitriding sha256 verified ($NITRIDING_SHA256)"

echo ">> docker build $IMAGE"
docker build -t "$IMAGE" "$HERE"

echo ">> nitro-cli build-enclave -> $EIF"
nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF"

echo ">> measurements (pin PCR0/1/2 in the client-sidecar):"
read -r PCR0 PCR1 PCR2 < <(nitro-cli describe-eif --eif-path "$EIF" |
	python3 -c 'import sys,json;m=json.load(sys.stdin)["Measurements"];print(m["PCR0"],m["PCR1"],m["PCR2"])')
echo "    PCR0=$PCR0"
echo "    PCR1=$PCR1"
echo "    PCR2=$PCR2"

# Emit the ARPA Phase-0 measurement manifest (unsigned here; sign it deliberately with the
# operator key via cmd/measure-sign). The client-sidecar verifies the signature + pins these PCRs.
MANIFEST="${MANIFEST:-$HERE/measurements.json}"
MANIFEST="$MANIFEST" \
	M_TAG="$(git -C "$REPO" describe --tags --always --dirty 2>/dev/null || echo untagged)" \
	M_COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)" \
	M_PCR0="$PCR0" M_PCR1="$PCR1" M_PCR2="$PCR2" \
	M_BASE="$(grep -oE 'sha256:[0-9a-f]{64}' "$HERE/Dockerfile" | head -1)" \
	M_NITRIDING="$NITRIDING_COMMIT" M_EPOCH="$SOURCE_DATE_EPOCH" \
	python3 -c '
import json, os
json.dump({
  "schema_version": 1,
  "tag": os.environ["M_TAG"],
  "source_commit": os.environ["M_COMMIT"],
  "pcr0": os.environ["M_PCR0"], "pcr1": os.environ["M_PCR1"], "pcr2": os.environ["M_PCR2"],
  "base_image_digest": os.environ["M_BASE"],
  "nitriding_commit": os.environ["M_NITRIDING"],
  "source_date_epoch": int(os.environ["M_EPOCH"]),
}, open(os.environ["MANIFEST"], "w"), indent=2, sort_keys=True)'
echo ">> wrote measurement manifest: $MANIFEST"
echo ">> sign it (operator key):  (cd $BACKEND && go run ./cmd/measure-sign -priv KEY -in $MANIFEST -sig $MANIFEST.sig)"
