#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${OPENGRADIENT_DIR:?set OPENGRADIENT_DIR to a local pinned checkout}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/open-gateway-comparison/raw/$STAMP}"
mkdir -p "$OUT_DIR"

loc_src() {
  local dir="$1"
  find "$dir" -type f \( -name '*.go' -o -name '*.py' -o -name '*.rs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.js' \) \
    -not -path '*/vendor/*' \
    -not -path '*/.git/*' \
    -not -path '*/__pycache__/*' \
    -print0 |
    xargs -0 awk 'NF && $1 !~ /^\/\// && $1 !~ /^#/ {n++} END {print n+0}'
}

{
  echo "timestamp_utc=$STAMP"
  echo "aegis_repo=$ROOT"
  echo "aegis_commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "opengradient_dir=$OPENGRADIENT_DIR"
  echo "opengradient_commit=$(git -C "$OPENGRADIENT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
} > "$OUT_DIR/provenance.txt"

aegis_loc="$(loc_src "$ROOT/backend/internal/confidential" )"
aegis_loc=$((aegis_loc + $(loc_src "$ROOT/backend/internal/enclave")))
og_loc="$(loc_src "$OPENGRADIENT_DIR")"

cat > "$OUT_DIR/comparison-table.md" <<EOF
| System | Pinned revision | Local source LOC proxy | Verify-before-send | Faithful passthrough | Provider coverage | Receipts |
| --- | --- | ---: | --- | --- | --- | --- |
| AEGIS | $(git -C "$ROOT" rev-parse --short HEAD) | $aegis_loc | yes | yes | OpenAI/OpenRouter/Gemini native policies | live attested session |
| OpenGradient tee-gateway | $(git -C "$OPENGRADIENT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown) | $og_loc | client-verifiable attestation/signatures; no local sidecar gate observed | not evaluated as byte-faithful passthrough; routes through OpenAI-compatible handlers | OpenAI/Anthropic/Gemini/xAI/ByteDance per checked-out README | source/docs inspection only; not run locally |
EOF

cat "$OUT_DIR/comparison-table.md"
