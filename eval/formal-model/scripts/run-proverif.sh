#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/formal-model/raw/$STAMP}"
MODEL="$ROOT/eval/formal-model/model/aegis_five_invariants.pv"
PROVERIF_CMD="${PROVERIF:-proverif}"
mkdir -p "$OUT_DIR"

if ! command -v "${PROVERIF_CMD%% *}" >/dev/null 2>&1; then
  {
    echo "status=not-run"
    echo "reason=proverif not installed"
    echo "model=$MODEL"
  } > "$OUT_DIR/provenance.txt"
  echo "proverif not installed; install ProVerif and rerun" >&2
  exit 127
fi

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "model=$MODEL"
  echo "proverif_command=$PROVERIF_CMD"
} > "$OUT_DIR/provenance.txt"

read -r -a proverif_argv <<< "$PROVERIF_CMD"
"${proverif_argv[@]}" "$MODEL" > "$OUT_DIR/proverif.log" 2>&1
grep -E "RESULT|Query" "$OUT_DIR/proverif.log" > "$OUT_DIR/summary.txt" || true
cat "$OUT_DIR/summary.txt"
