#!/usr/bin/env bash
# Performance evaluation for the confidential router: (1) one-time attestation handshake latency,
# (2) per-request added latency and (3) streaming time-to-first-token (TTFT) overhead vs sending the
# same request DIRECTLY to OpenAI. Requires the Nitro CPU pool reserved + deploy/.env (GATEWAY_API_KEY,
# OPENAI_API_KEY, OPENAI_MODEL). OpenAI latency is variable, so we report medians over N samples and
# the median delta (≈ our machinery overhead) with that caveat.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BACKEND="$REPO/backend"
set -a; [ -f "$REPO/deploy/.env" ] && . "$REPO/deploy/.env"; set +a
: "${GATEWAY_API_KEY:?set GATEWAY_API_KEY in deploy/.env}"
: "${OPENAI_API_KEY:?set OPENAI_API_KEY in deploy/.env}"
MODEL="${MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}"
SIDE="127.0.0.1:8788"; HOST_HTTPS_PORT=10443; SERVERNAME=router.local; EIF="$HERE/router.eif"
N="${N:-15}"

SIDECAR_PID=""
cleanup() {
	[ -n "$SIDECAR_PID" ] && kill "$SIDECAR_PID" 2>/dev/null
	eid="$(nitro-cli describe-enclaves 2>/dev/null | python3 -c 'import sys,json;e=json.load(sys.stdin);print(e[0]["EnclaveID"] if e else "")' 2>/dev/null || true)"
	[ -n "$eid" ] && sudo -n nitro-cli terminate-enclave --enclave-id "$eid" >/dev/null 2>&1
	pkill -INT -f 'gvproxy -listen vsock://:1024' 2>/dev/null
	pkill -f 'host-orchestrator -vsock-port' 2>/dev/null
	true
}
trap cleanup EXIT

[ -f "$EIF" ] || bash "$HERE/build-eif.sh"
read -r PCR0 PCR1 PCR2 < <(nitro-cli describe-eif --eif-path "$EIF" |
	python3 -c 'import sys,json;m=json.load(sys.stdin)["Measurements"];print(m["PCR0"],m["PCR1"],m["PCR2"])')
echo ">> bringing up host plane + enclave"
bash "$HERE/run-host.sh" >/tmp/cr-perf-host.log 2>&1
sleep 3
nitro-cli describe-enclaves | python3 -c 'import sys,json;e=json.load(sys.stdin);assert e and e[0]["State"]=="RUNNING" and e[0]["Flags"]=="NONE","not RUNNING/NONE"'

echo ">> measuring one-time attestation handshake"
(cd "$BACKEND" && go build -o "$HERE/client-sidecar" ./cmd/client-sidecar)
t0="$(date +%s.%N)"
"$HERE/client-sidecar" -enclave-url "https://127.0.0.1:$HOST_HTTPS_PORT" -servername "$SERVERNAME" \
	-listen "$SIDE" -pcr0 "$PCR0" -pcr1 "$PCR1" -pcr2 "$PCR2" >/tmp/cr-perf-sidecar.log 2>&1 &
SIDECAR_PID=$!
for _ in $(seq 1 150); do grep -q 'attestation verified' /tmp/cr-perf-sidecar.log && break; sleep 0.1; done
t1="$(date +%s.%N)"
ATT="$(python3 -c "print(f'{$t1-$t0:.2f}')")"
echo ">> attestation handshake (one-time, incl. sidecar start): ${ATT}s"

body="$(MODEL="$MODEL" python3 -c 'import json,os;print(json.dumps({"model":os.environ["MODEL"],"input":"Reply with exactly: ok","stream":True}))')"
warm() { curl -fsS -o /dev/null "$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$body" 2>/dev/null || true; }
warm "http://$SIDE/v1/responses" "$GATEWAY_API_KEY"; warm "https://api.openai.com/v1/responses" "$OPENAI_API_KEY"

measure() { # url key outfile : append "time_total time_starttransfer(=TTFT)" per request
	: > "$3"
	for _ in $(seq 1 "$N"); do
		curl -fsS -o /dev/null -w '%{time_total} %{time_starttransfer}\n' "$1" \
			-H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$body" >> "$3" 2>/dev/null || echo "ERR ERR" >> "$3"
	done
}
echo ">> sampling N=$N through the confidential router (ours)"; measure "http://$SIDE/v1/responses" "$GATEWAY_API_KEY" /tmp/cr-perf-ours.txt
echo ">> sampling N=$N direct to OpenAI (baseline)"; measure "https://api.openai.com/v1/responses" "$OPENAI_API_KEY" /tmp/cr-perf-direct.txt

ATT="$ATT" python3 - <<'PY'
import statistics as s, os
def load(f):
    tot, ttft = [], []
    for l in open(f):
        a, b = l.split()
        if a == "ERR": continue
        tot.append(float(a)*1000); ttft.append(float(b)*1000)
    return tot, ttft
ot, of = load('/tmp/cr-perf-ours.txt'); dt, df = load('/tmp/cr-perf-direct.txt')
def med(x): return s.median(x) if x else float('nan')
print("\n================ Performance (medians over N samples; ms) ================")
print(f"one-time attestation handshake : {os.environ['ATT']} s")
print(f"per-request total   ours={med(ot):.0f}  direct={med(dt):.0f}  added={med(ot)-med(dt):+.0f}")
print(f"time-to-first-token ours={med(of):.0f}  direct={med(df):.0f}  added={med(of)-med(df):+.0f}")
print(f"(n_ours={len(ot)} n_direct={len(dt)}; OpenAI latency is variable — added≈our machinery overhead)")
print("=========================================================================")
PY
