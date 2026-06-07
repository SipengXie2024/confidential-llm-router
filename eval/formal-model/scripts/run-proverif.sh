#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/formal-model/raw/$STAMP}"
MODEL_DIR="$ROOT/eval/formal-model/model"
MODEL_GLOB="${MODEL_GLOB:-$MODEL_DIR/aegis_protocol_invariants.pv}"
PROVERIF_CMD="${PROVERIF:-proverif}"
mkdir -p "$OUT_DIR"

if ! command -v "${PROVERIF_CMD%% *}" >/dev/null 2>&1; then
  {
    echo "status=not-run"
    echo "reason=proverif not installed"
    echo "model_dir=$MODEL_DIR"
    echo "model_glob=$MODEL_GLOB"
  } > "$OUT_DIR/provenance.txt"
  echo "proverif not installed; install ProVerif and rerun" >&2
  exit 127
fi

read -r -a proverif_argv <<< "$PROVERIF_CMD"

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "model_dir=$MODEL_DIR"
  echo "model_glob=$MODEL_GLOB"
  echo "proverif_command=$PROVERIF_CMD"
  echo "proverif_version=$("${proverif_argv[@]}" --help 2>&1 | head -1)"
} > "$OUT_DIR/provenance.txt"

: > "$OUT_DIR/summary.txt"
for MODEL in $MODEL_GLOB; do
  name="$(basename "$MODEL" .pv)"
  "${proverif_argv[@]}" "$MODEL" > "$OUT_DIR/$name.log" 2>&1
  grep -E "^RESULT" "$OUT_DIR/$name.log" | sed "s|^|[$name] |" >> "$OUT_DIR/summary.txt"
done
cat "$OUT_DIR/summary.txt"
