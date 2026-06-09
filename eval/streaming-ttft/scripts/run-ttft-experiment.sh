#!/usr/bin/env bash
# Streaming TTFT experiment: through-Aegis (arm A) vs direct-to-OpenAI (arm B).
#
# Both arms send the SAME streaming Responses request (temperature 0, capped at
# max_output_tokens so both produce ~identical token counts -> per-chunk cadence
# is comparable). Requests are interleaved A/B/A/B to cancel provider time-of-day
# jitter. Per-event arrival times are recorded by sse_timer.py on a monotonic
# clock; one JSON line per request lands in aegis-stream-metrics.jsonl.
#
#   arm A (through-Aegis): -> verified client-sidecar (127.0.0.1:8788) -> host -> enclave -> OpenAI
#   arm B (direct):        -> https://api.openai.com directly
#
# Prereqs: the attested Aegis plane must already be up (run-host.sh + a verified
# client-sidecar listening on $AEGIS_SIDE_URL with the current EIF's PCR0 pinned).
# Secrets come from deploy/.env and are NEVER printed or committed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR:-$ROOT/eval/streaming-ttft/raw/$STAMP}"
N="${N:-100}"
AEGIS_SIDE_URL="${AEGIS_SIDE_URL:-http://127.0.0.1:8788}"
OPENAI_DIRECT_URL="${OPENAI_DIRECT_URL:-https://api.openai.com}"
PROMPT="${PROMPT:-List the integers from 1 to 400, one per line.}"
MAX_OUTPUT_TOKENS="${MAX_OUTPUT_TOKENS:-256}"
PCR0_PIN="${PCR0_PIN:-unknown}"
SMOKE_DEBUG="${SMOKE_DEBUG:-0}"   # if 1, run a single debug request and exit (prints SSE event types)

set -a
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"
: "${GATEWAY_API_KEY:?set GATEWAY_API_KEY in deploy/.env (gateway-issued user key on an openai group)}"
: "${OPENAI_API_KEY:?set OPENAI_API_KEY in deploy/.env (for the direct arm)}"

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Same body for both arms. Responses API streaming uses max_output_tokens.
BODY="$TMP_DIR/body.json"
python3 - "$OPENAI_MODEL" "$PROMPT" "$MAX_OUTPUT_TOKENS" >"$BODY" <<'PY'
import json, sys
model, prompt, max_out = sys.argv[1], sys.argv[2], int(sys.argv[3])
json.dump({
    "model": model,
    "input": prompt,
    "stream": True,
    "temperature": 0,
    "max_output_tokens": max_out,
}, sys.stdout)
PY

run_one() {
  local arm="$1" url="$2" auth="$3" index="$4" extra="${5:-}"
  python3 "$HERE/sse_timer.py" \
    --url "$url/v1/responses" \
    --header "Authorization: Bearer $auth" \
    --body-file "$BODY" \
    --arm "$arm" \
    --provider openai \
    --index "$index" \
    --model "$OPENAI_MODEL" \
    --wall-ts "$(date -u +%Y%m%dT%H%M%S.%3NZ)" \
    $extra
}

if [ "$SMOKE_DEBUG" = "1" ]; then
  echo ">> SMOKE: arm A (through-Aegis), printing SSE event types" >&2
  run_one through-aegis "$AEGIS_SIDE_URL" "$GATEWAY_API_KEY" 0 "--debug-events"
  echo ">> SMOKE: arm B (direct), printing SSE event types" >&2
  run_one direct "$OPENAI_DIRECT_URL" "$OPENAI_API_KEY" 0 "--debug-events"
  exit 0
fi

METRICS="$OUT_DIR/aegis-stream-metrics.jsonl"
: >"$METRICS"

echo ">> running N=$N per arm, interleaved A/B, model=$OPENAI_MODEL, max_output_tokens=$MAX_OUTPUT_TOKENS" >&2
for i in $(seq 1 "$N"); do
  run_one through-aegis "$AEGIS_SIDE_URL" "$GATEWAY_API_KEY" "$i" >>"$METRICS"
  run_one direct "$OPENAI_DIRECT_URL" "$OPENAI_API_KEY" "$i" >>"$METRICS"
  if (( i % 10 == 0 )); then echo "   .. $i/$N pairs done" >&2; fi
done

# Summary: per-arm p50/p95 TTFT, p50/p95 inter-chunk, mean chunks/tokens.
python3 - "$METRICS" "$OUT_DIR/summary.json" <<'PY'
import json, sys

metrics_path, out_path = sys.argv[1], sys.argv[2]
rows = []
with open(metrics_path) as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

def pct(vals, q):
    s = sorted(v for v in vals if v is not None)
    if not s:
        return None
    if len(s) == 1:
        return s[0]
    idx = int(round((q / 100.0) * (len(s) - 1)))
    idx = max(0, min(idx, len(s) - 1))
    return s[idx]

def mean(vals):
    s = [v for v in vals if v is not None]
    return (sum(s) / len(s)) if s else None

summary = {}
for arm in sorted({r["arm"] for r in rows}):
    arm_rows = [r for r in rows if r["arm"] == arm]
    ok = [r for r in arm_rows if r.get("ok")]
    ttft = [r["ttft_ms"] for r in ok]
    inter = [x for r in ok for x in (r.get("inter_chunk_ms") or [])]
    chunks = [r["n_chunks"] for r in ok]
    toks = [r["n_output_tokens"] for r in ok if r.get("n_output_tokens") is not None]
    summary[arm] = {
        "requests": len(arm_rows),
        "ok": len(ok),
        "failed": len(arm_rows) - len(ok),
        "ttft_p50_ms": pct(ttft, 50),
        "ttft_p95_ms": pct(ttft, 95),
        "ttft_mean_ms": mean(ttft),
        "inter_chunk_p50_ms": pct(inter, 50),
        "inter_chunk_p95_ms": pct(inter, 95),
        "mean_n_chunks": mean(chunks),
        "min_n_chunks": min(chunks) if chunks else None,
        "mean_n_output_tokens": mean(toks),
        "total_stream_p50_ms": pct([r["total_stream_ms"] for r in ok], 50),
    }

# Comparability cross-check between the two arms' mean token counts.
arms = list(summary)
if len(arms) == 2:
    a, b = summary[arms[0]]["mean_n_output_tokens"], summary[arms[1]]["mean_n_output_tokens"]
    if a and b:
        summary["_token_count_rel_diff_pct"] = abs(a - b) / ((a + b) / 2) * 100.0

with open(out_path, "w") as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
PY

cat >"$OUT_DIR/README.md" <<EOF
# Streaming TTFT: through-Aegis vs direct-to-OpenAI

Generated: $STAMP

## What this measures

Two arms send the **identical** streaming OpenAI Responses request and record,
on a monotonic clock, the arrival time of every SSE event (see
\`../../sse_timer.py\`):

- **arm A (\`through-aegis\`)**: client -> verified client-sidecar (\`$AEGIS_SIDE_URL\`)
  -> untrusted host -> Nitro Enclave (TLS terminates inside) -> api.openai.com.
  The sidecar verified the signed measurement manifest and pinned the running
  EIF's **PCR0=$PCR0_PIN** before any plaintext was proxied (fail-closed).
- **arm B (\`direct\`)**: client -> \`$OPENAI_DIRECT_URL\` directly.

## Request parameters (identical across arms)

- \`stream: true\`
- \`temperature: 0\` (near-deterministic -> both arms emit ~identical token
  counts, so per-chunk cadence is comparable and generation-length is not a
  confound)
- \`max_output_tokens: $MAX_OUTPUT_TOKENS\` (both arms run to the cap -> many SSE
  chunks, enough to measure cadence)
- prompt: deterministic enumeration that fills the cap
- model: \`$OPENAI_MODEL\` (from deploy/.env)
- **N = $N per arm**, sent **interleaved A/B/A/B** to cancel provider
  time-of-day jitter.

## Definitions

- \`ttft_ms\`: request-bytes-sent -> first \`response.output_text.delta\` event.
- \`first_event_ms\`: request-bytes-sent -> first SSE event of any type (cross-check).
- \`inter_chunk_ms\`: differences between consecutive \`response.output_text.delta\`
  arrivals within one response.
- \`n_output_tokens\`: from the \`response.completed\` event's usage.

## Confound control & honest attribution

TTFT is the clean, fairly-attributable number here: it captures the one-time
extra cost of the attested path (the sidecar verify is one-time at session
setup; per-request it is the relay hop + amortized handshake). **Per-chunk
inter-arrival is dominated by the provider's own emission cadence**, which we do
not control; we therefore report inter-chunk only as **distributions** (p50/p95)
for each arm and do **not** claim a constant per-chunk overhead added by the
enclave. Interleaving + temperature-0 + a fixed token cap keep the two arms'
workloads matched so the TTFT comparison is apples-to-apples.

## Files

- \`provenance.txt\`: commit, PCR0, allocator state, machine spec, model, UTC date.
- \`aegis-stream-metrics.jsonl\`: one record per request (no prompts, no secrets).
- \`summary.json\`: per-arm p50/p95 TTFT, p50/p95 inter-chunk, mean chunks/tokens.
EOF

echo ">> wrote $OUT_DIR" >&2
