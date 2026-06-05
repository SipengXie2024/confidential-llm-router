#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/faithfulness-fuzz/raw/$STAMP}"
FUZZTIME="${FUZZTIME:-30s}"
mkdir -p "$OUT_DIR"

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "fuzztime=$FUZZTIME"
} > "$OUT_DIR/provenance.txt"

(
  cd "$ROOT/backend"
  for target in FuzzRelayVerbatimFaithfulness FuzzRelaySSEFaithfulness; do
    echo "== $target =="
    GOCACHE="${GOCACHE:-/tmp/go-build}" go test ./internal/enclave \
      -run='^$' -fuzz="^${target}$" -fuzztime="$FUZZTIME" -count=1 -v
  done
) > "$OUT_DIR/go-fuzz.log" 2>&1

tail -n 40 "$OUT_DIR/go-fuzz.log"
