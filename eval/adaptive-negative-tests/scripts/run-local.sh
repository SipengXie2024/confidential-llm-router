#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/adaptive-negative-tests/raw/$STAMP}"
export GOCACHE="${GOCACHE:-/tmp/go-build}"

mkdir -p "$OUT_DIR"

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "branch=$(git -C "$ROOT" branch --show-current || true)"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "worktree_status_start="
  git -C "$ROOT" status --short
} > "$OUT_DIR/provenance.txt"

(
  cd "$ROOT/backend"
  go test -tags unit \
    ./internal/confidential \
    ./cmd/enclave-core \
    ./cmd/client-sidecar \
    ./internal/enclave \
    ./internal/sidecar \
    -run 'Test(RPCRoundTrip|AuthorizeArgsAreMetadataOnly|ControlChannelSchemasExcludeBodyAndDestination|EnclaveCore|HostChosenModel|Sidecar|PinnedTransport|RelaySSEObservationBoundary|RelayVerbatimObservationBoundary|Verify|CertBound)' \
    -count=1 -v
) | tee "$OUT_DIR/go-test-unit.log"

(
  cd "$ROOT/backend"
  go run ../eval/adaptive-negative-tests/control-channel-bound.go -repo ..
) | tee "$OUT_DIR/control-channel-bound.md"

cat > "$OUT_DIR/summary.md" <<'EOF'
# P0-2 Local Negative-Test Summary

## Tested Properties

- Control-channel schemas exclude request/response body fields, upstream URL/path
  fields, and arbitrary header carriers.
- Host-selected metadata model is not written into the client request body.
- Sidecar refuses to build a proxy when verification fails.
- A rotated enclave TLS certificate fails the pinned transport before the rotated
  endpoint handles the HTTP request.
- SSE relay emits one downstream chunk per upstream SSE line while preserving
  original bytes, including line endings; non-SSE relay emits one full-body
  chunk. The broader identity relation is covered by
  `eval/faithfulness-fuzz/scripts/run-local.sh`.

## Residual Side Channels

- No padding or timing jitter is implemented.
- Streamed responses expose size and timing at SSE-line granularity to an observer
  who can see TLS record sizes/timing.
- Deny-path `deny_reason` is host-controlled text returned to the client, but the
  sidecar/enclave do not release plaintext body bytes on that path.
EOF

echo "wrote $OUT_DIR"
