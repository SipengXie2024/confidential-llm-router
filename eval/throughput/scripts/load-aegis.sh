#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/throughput/raw/$STAMP}"
AEGIS_SIDE_URL="${AEGIS_SIDE_URL:-http://127.0.0.1:8788}"
: "${AEGIS_GATEWAY_KEY:?set AEGIS_GATEWAY_KEY}"
PROVIDER="${PROVIDER:-openai}"
case "$PROVIDER" in
  openai)
    MODEL="${MODEL:-gpt-4o-mini}"
    PATH_SUFFIX="/v1/responses"
    ;;
  openrouter)
    MODEL="${MODEL:-openai/gpt-4o-mini}"
    PATH_SUFFIX="/v1/chat/completions"
    ;;
  gemini)
    MODEL="${MODEL:-gemini-2.5-flash}"
    PATH_SUFFIX="/v1beta/models/$MODEL:generateContent"
    ;;
  *)
    echo "unknown PROVIDER: $PROVIDER" >&2
    exit 2
    ;;
esac
TOTAL="${TOTAL:-200}"
CONCURRENCY_SET="${CONCURRENCY_SET:-1 4 8 16 32 64}"
mkdir -p "$OUT_DIR"

payload="$OUT_DIR/payload.json"
case "$PROVIDER" in
  openai)
    jq -n --arg model "$MODEL" '{
      model:$model,
      input:"Return exactly: ok",
      temperature:0,
      max_output_tokens:16
    }' > "$payload"
    ;;
  openrouter)
    jq -n --arg model "$MODEL" '{
      model:$model,
      messages:[{role:"user", content:"Return exactly: ok"}],
      temperature:0,
      max_tokens:16,
      stream:false
    }' > "$payload"
    ;;
  gemini)
    jq -n '{
      contents: [{role:"user", parts:[{text:"Return exactly: ok"}]}],
      generationConfig: {temperature:0, maxOutputTokens:16}
    }' > "$payload"
    ;;
esac

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "side_url=$AEGIS_SIDE_URL"
  echo "provider=$PROVIDER"
  echo "path=$PATH_SUFFIX"
  echo "model=$MODEL"
  echo "total=$TOTAL"
  echo "concurrency_set=$CONCURRENCY_SET"
  echo "key=redacted"
} > "$OUT_DIR/provenance.txt"

summary="$OUT_DIR/summary.csv"
echo "concurrency,total,ok,failed,median_ms,p95_ms,p99_ms" > "$summary"

for c in $CONCURRENCY_SET; do
  raw="$OUT_DIR/c${c}.txt"
  : > "$raw"
  seq 1 "$TOTAL" | xargs -P "$c" -I{} sh -c '
    curl -sS -o /dev/null -w "%{http_code} %{time_total}\n" \
      "$0$3" \
      -H "Authorization: Bearer $1" \
      -H "Content-Type: application/json" \
      --data-binary "@$2" || echo "000 0"
  ' "$AEGIS_SIDE_URL" "$AEGIS_GATEWAY_KEY" "$payload" "$PATH_SUFFIX" >> "$raw"
  python3 - "$c" "$raw" "$summary" <<'PY'
import csv, statistics, sys
c, raw, summary = sys.argv[1:]
vals = []
ok = failed = 0
for line in open(raw):
    code, sec = line.split()
    if code.startswith("2"):
        ok += 1
        vals.append(float(sec) * 1000)
    else:
        failed += 1
vals.sort()
def pct(p):
    if not vals:
        return ""
    return f"{vals[min(len(vals)-1, int(len(vals)*p))]:.3f}"
row = [c, ok + failed, ok, failed, f"{statistics.median(vals):.3f}" if vals else "", pct(0.95), pct(0.99)]
with open(summary, "a", newline="") as f:
    csv.writer(f).writerow(row)
PY
done

cat "$summary"
