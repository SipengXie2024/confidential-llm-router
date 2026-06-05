#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT/eval/provider-workloads/raw/$STAMP}"
N="${N:-100}"
PROVIDERS="${PROVIDERS:-openai openrouter gemini}"
AEGIS_SIDE_URL="${AEGIS_SIDE_URL:-http://127.0.0.1:8788}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-openai/gpt-4o-mini}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

set -a
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

: "${AEGIS_OPENAI_GATEWAY_KEY:?set AEGIS_OPENAI_GATEWAY_KEY}"
: "${AEGIS_OPENROUTER_GATEWAY_KEY:?set AEGIS_OPENROUTER_GATEWAY_KEY}"
: "${AEGIS_GEMINI_GATEWAY_KEY:?set AEGIS_GEMINI_GATEWAY_KEY}"

{
  echo "timestamp_utc=$STAMP"
  echo "repo=$ROOT"
  echo "branch=$(git -C "$ROOT" branch --show-current || true)"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "n=$N"
  echo "providers=$PROVIDERS"
  echo "side_url=$AEGIS_SIDE_URL"
  echo "openai_model=$OPENAI_MODEL"
  echo "openrouter_model=$OPENROUTER_MODEL"
  echo "gemini_model=$GEMINI_MODEL"
  echo "keys=redacted"
} > "$OUT_DIR/provenance.txt"

METRICS="$OUT_DIR/aegis-provider-metrics.jsonl"
: > "$METRICS"

request_json() {
  local provider="$1"
  local index="$2"
  local path="$3"
  local key="$4"
  local payload="$5"
  local marker="$6"
  local body="$TMP_DIR/${provider}-${index}.json"

  local metrics
  if metrics="$(curl -sS -o "$body" \
    -w '{"http_code":%{http_code},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total},"size_download":%{size_download}}' \
    -X POST "${AEGIS_SIDE_URL%/}$path" \
    -H "Authorization: Bearer $key" \
    -H "Content-Type: application/json" \
    --data-binary @"$payload")"; then
    :
  else
    jq -cn --arg provider "$provider" --argjson index "$index" \
      '{provider:$provider,index:$index,ok:false,error:"curl_failed"}' >> "$METRICS"
    return 0
  fi

  local text body_sha body_bytes text_sha marker_seen err model
  body_sha="$(sha256sum "$body" | awk '{print $1}')"
  body_bytes="$(wc -c < "$body" | tr -d ' ')"
  case "$provider" in
    openai)
      text="$(jq -r '.output_text // ([.output[]?.content[]?.text] | join("")) // ""' "$body" 2>/dev/null || true)"
      model="$OPENAI_MODEL"
      ;;
    openrouter)
      text="$(jq -r '.choices[0].message.content // ""' "$body" 2>/dev/null || true)"
      model="$OPENROUTER_MODEL"
      ;;
    gemini)
      text="$(jq -r '.candidates[0].content.parts[0].text // ""' "$body" 2>/dev/null || true)"
      model="$GEMINI_MODEL"
      ;;
  esac
  text_sha="$(printf "%s" "$text" | sha256sum | awk '{print $1}')"
  if [[ "$text" == *"$marker"* ]]; then marker_seen=true; else marker_seen=false; fi
  err="$(jq -c '.error? // empty' "$body" 2>/dev/null || true)"
  err="$(printf "%s" "$err" | sed -E 's/sk-[A-Za-z0-9_*.-]+/sk-[redacted]/g')"

  jq -cn \
    --arg provider "$provider" \
    --argjson index "$index" \
    --argjson curl "$metrics" \
    --arg model "$model" \
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
      text_sha256:$text_sha256,
      body_sha256:$body_sha256,
      text_len:$text_len,
      marker_seen:$marker_seen,
      error:($error_json | if . == "" then null else . end)
    }' >> "$METRICS"
}

for i in $(seq 1 "$N"); do
  marker="AEGIS"
  prompt="Return only this token, with no punctuation or explanation: $marker"

  for provider in $PROVIDERS; do
    case "$provider" in
      openai)
        openai_payload="$TMP_DIR/openai-$i-payload.json"
        jq -n --arg model "$OPENAI_MODEL" --arg text "$prompt" '{
          model:$model,
          input:$text,
          temperature:0,
          max_output_tokens:32
        }' > "$openai_payload"
        request_json openai "$i" "/v1/responses" "$AEGIS_OPENAI_GATEWAY_KEY" "$openai_payload" "$marker"
        ;;
      openrouter)
        openrouter_payload="$TMP_DIR/openrouter-$i-payload.json"
        jq -n --arg model "$OPENROUTER_MODEL" --arg text "$prompt" '{
          model:$model,
          messages:[{role:"user", content:$text}],
          temperature:0,
          max_tokens:32,
          stream:false
        }' > "$openrouter_payload"
        request_json openrouter "$i" "/v1/chat/completions" "$AEGIS_OPENROUTER_GATEWAY_KEY" "$openrouter_payload" "$marker"
        ;;
      gemini)
        gemini_payload="$TMP_DIR/gemini-$i-payload.json"
        jq -n --arg text "$prompt" '{
          contents: [{role:"user", parts:[{text:$text}]}],
          generationConfig: {temperature:0, maxOutputTokens:32}
        }' > "$gemini_payload"
        request_json gemini "$i" "/v1beta/models/$GEMINI_MODEL:generateContent" "$AEGIS_GEMINI_GATEWAY_KEY" "$gemini_payload" "$marker"
        ;;
      *)
        echo "unknown provider in PROVIDERS: $provider" >&2
        exit 2
        ;;
    esac
  done
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
      p95_total_ms: ([.[] | select(.ok) | .time_total_ms] | sort | .[(length*95/100|floor)] // null),
      median_body_bytes: ([.[] | select(.ok) | .body_bytes] | median)
    })
' "$METRICS" > "$OUT_DIR/summary.json"

cat > "$OUT_DIR/README.md" <<EOF
# AEGIS Provider Workload

Generated: $STAMP

This run sends provider-native synthetic requests through an existing AEGIS
sidecar at \`$AEGIS_SIDE_URL\`. Raw provider credentials and gateway keys are
redacted.

Files:

- \`provenance.txt\`: commit, branch, sample count, model names, sidecar URL.
- \`aegis-provider-metrics.jsonl\`: one sanitized record per provider request.
- \`summary.json\`: per-provider counts and latency medians/tails.
EOF

cat "$OUT_DIR/summary.json"
