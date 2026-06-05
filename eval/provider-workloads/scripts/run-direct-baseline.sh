#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/provider-workloads/raw/$STAMP}"
N="${N:-3}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openai/gpt-4o-mini}"
GEMINI_BASE_URL="${GEMINI_BASE_URL:-https://generativelanguage.googleapis.com}"
OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}"

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

: "${GEMINI_API_KEY:?set GEMINI_API_KEY in deploy/.env}"
: "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY in deploy/.env}"

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "branch=$(git -C "$ROOT" branch --show-current || true)"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "n=$N"
  echo "gemini_model=$GEMINI_MODEL"
  echo "openrouter_model=$OPENROUTER_MODEL"
  echo "keys=redacted"
} > "$OUT_DIR/provenance.txt"

METRICS="$OUT_DIR/provider-direct-metrics.jsonl"
: > "$METRICS"

curl_json() {
  local provider="$1"
  local index="$2"
  local url="$3"
  local payload="$4"
  local marker="$5"
  local body="$TMP_DIR/${provider}-${index}.json"
  shift 5

  local metrics
  if metrics="$(curl -sS -o "$body" \
    -w '{"http_code":%{http_code},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total},"size_download":%{size_download}}' \
    -X POST "$url" "$@" --data-binary @"$payload")"; then
    :
  else
    jq -cn --arg provider "$provider" --argjson index "$index" \
      '{provider:$provider,index:$index,ok:false,error:"curl_failed"}' >> "$METRICS"
    return 0
  fi

  local text body_sha body_bytes text_sha err marker_seen
  body_sha="$(sha256sum "$body" | awk '{print $1}')"
  body_bytes="$(wc -c < "$body" | tr -d ' ')"
  case "$provider" in
    gemini)
      text="$(jq -r '.candidates[0].content.parts[0].text // ""' "$body" 2>/dev/null || true)"
      ;;
    openrouter)
      text="$(jq -r '.choices[0].message.content // ""' "$body" 2>/dev/null || true)"
      ;;
    *)
      text=""
      ;;
  esac
  text_sha="$(printf "%s" "$text" | sha256sum | awk '{print $1}')"
  if [[ "$text" == *"$marker"* ]]; then
    marker_seen=true
  else
    marker_seen=false
  fi
  err="$(jq -c '.error? // empty' "$body" 2>/dev/null || true)"

  jq -cn \
    --arg provider "$provider" \
    --argjson index "$index" \
    --argjson curl "$metrics" \
    --arg model "$(if [ "$provider" = gemini ]; then echo "$GEMINI_MODEL"; else echo "$OPENROUTER_MODEL"; fi)" \
    --arg body_sha256 "$body_sha" \
    --arg text_sha256 "$text_sha" \
    --argjson body_bytes "$body_bytes" \
    --argjson text_len "${#text}" \
    --argjson marker_seen "$marker_seen" \
    --arg error_json "$err" \
    '{
      provider:$provider,
      index:$index,
      model:$model,
      http_code:$curl.http_code,
      ok:($curl.http_code >= 200 and $curl.http_code < 300),
      time_starttransfer_ms:($curl.time_starttransfer * 1000),
      time_total_ms:($curl.time_total * 1000),
      size_download:($curl.size_download),
      body_bytes:$body_bytes,
      body_sha256:$body_sha256,
      text_sha256:$text_sha256,
      text_len:$text_len,
      marker_seen:$marker_seen,
      error:($error_json | if . == "" then null else . end)
    }' >> "$METRICS"
}

for i in $(seq 1 "$N"); do
  marker="AEGIS"
  prompt="Return only this token, with no punctuation or explanation: $marker"

  gemini_payload="$TMP_DIR/gemini-$i-payload.json"
  jq -n --arg text "$prompt" '{
    contents: [{role:"user", parts:[{text:$text}]}],
    generationConfig: {temperature:0, maxOutputTokens:32}
  }' > "$gemini_payload"
  curl_json gemini "$i" \
    "$GEMINI_BASE_URL/v1beta/models/$GEMINI_MODEL:generateContent" \
    "$gemini_payload" \
    "$marker" \
    -H "x-goog-api-key: $GEMINI_API_KEY" \
    -H "Content-Type: application/json"

  openrouter_payload="$TMP_DIR/openrouter-$i-payload.json"
  jq -n --arg model "$OPENROUTER_MODEL" --arg text "$prompt" '{
    model:$model,
    messages:[{role:"user", content:$text}],
    temperature:0,
    max_tokens:32,
    stream:false
  }' > "$openrouter_payload"
  curl_json openrouter "$i" \
    "$OPENROUTER_BASE_URL/chat/completions" \
    "$openrouter_payload" \
    "$marker" \
    -H "Authorization: Bearer $OPENROUTER_API_KEY" \
    -H "Content-Type: application/json" \
    -H "HTTP-Referer: https://aegis.local" \
    -H "X-Title: AEGIS provider workload"
done

jq -s '
  def median:
    sort as $s | if ($s|length)==0 then null else $s[(($s|length)/2|floor)] end;
  group_by(.provider)
  | map({
      provider: .[0].provider,
      model: .[0].model,
      requests: length,
      ok: map(select(.ok)) | length,
      failed: map(select(.ok|not)) | length,
      marker_seen: map(select(.marker_seen)) | length,
      median_total_ms: ([.[] | select(.ok) | .time_total_ms] | median),
      median_ttfb_ms: ([.[] | select(.ok) | .time_starttransfer_ms] | median),
      median_body_bytes: ([.[] | select(.ok) | .body_bytes] | median)
    })
' "$METRICS" > "$OUT_DIR/summary.json"

cat > "$OUT_DIR/README.md" <<EOF
# Provider Direct Baseline

Generated: $STAMP

This run calls Gemini and OpenRouter directly with synthetic prompts. It does
not pass traffic through AEGIS. The purpose is to validate provider keys and
capture baseline latency before implementing AEGIS-through provider adapters.

Files:

- \`provenance.txt\`: commit, branch, sample count, model names; keys redacted.
- \`provider-direct-metrics.jsonl\`: one sanitized record per provider request.
- \`summary.json\`: per-provider counts and medians.
EOF

cat "$OUT_DIR/summary.json"
