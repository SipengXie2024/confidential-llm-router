#!/usr/bin/env bash
# End-to-end acceptance for the confidential router (goals ①②④, single provider = OpenAI).
#
# Sequence: build the EIF -> bring up the host plane -> start the attesting client-sidecar
# pinned to THIS EIF's PCR0/1/2 -> send a real OpenAI Responses request THROUGH the sidecar
# -> assert a streamed completion comes back AND a host-side packet capture of the enclave
# hop shows only TLS ciphertext (no plaintext prompt). Confirms describe-enclaves = RUNNING
# with Flags NONE (real, non-debug attestation).
#
# What this proves:
#   ① confidentiality  - the host hop carries only ciphertext; the prompt never appears
#   ② integrity        - the sidecar fails closed unless PCR0/1/2 match THIS audited EIF
#   ④ tamper-resistance - TLS terminates inside the enclave; the host cannot alter the stream
#
# Requires (user-provisioned): a gateway-issued user key (GATEWAY_API_KEY, sk-...) routed to
# an 'openai' group whose account holds a real OpenAI key; the host plane's config + Postgres
# + Redis (run-host.sh starts host-orchestrator); sudo for run-enclave + tcpdump.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BACKEND="$REPO/backend"

# Pull GATEWAY_API_KEY / OPENAI_MODEL from the gitignored env if present.
set -a
[ -f "$REPO/deploy/.env" ] && . "$REPO/deploy/.env"
set +a

: "${GATEWAY_API_KEY:?set GATEWAY_API_KEY (in deploy/.env) to a gateway-issued user key on an openai group}"
# exported so the python body-builder below can read them via os.environ
export PROMPT="${PROMPT:-Reply with exactly: hello from the enclave}"
export MODEL="${MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}"
SIDECAR_LISTEN="${SIDECAR_LISTEN:-127.0.0.1:8788}"
HOST_HTTPS_PORT="${HOST_HTTPS_PORT:-10443}"
SERVERNAME="${SERVERNAME:-router.local}"
EIF="${EIF:-$HERE/router.eif}"
CAP="${CAP:-/tmp/router-e2e-capture.pcap}"

SIDECAR_PID="" TCPDUMP_PID=""
cleanup() {
	[ -n "$SIDECAR_PID" ] && kill "$SIDECAR_PID" 2>/dev/null || true
	[ -n "$TCPDUMP_PID" ] && sudo -n kill -INT "$TCPDUMP_PID" 2>/dev/null || true
	eid="$(nitro-cli describe-enclaves 2>/dev/null | python3 -c 'import sys,json;e=json.load(sys.stdin);print(e[0]["EnclaveID"] if e else "")' 2>/dev/null || true)"
	[ -n "$eid" ] && sudo -n nitro-cli terminate-enclave --enclave-id "$eid" >/dev/null 2>&1 || true
	pkill -INT -f 'gvproxy -listen vsock://:1024' 2>/dev/null || true
	pkill -f 'host-orchestrator -vsock-port' 2>/dev/null || true
}
trap cleanup EXIT

# Pin exactly what we built: read PCR0/1/2 from the EIF.
[ -f "$EIF" ] || bash "$HERE/build-eif.sh"
read -r PCR0 PCR1 PCR2 < <(nitro-cli describe-eif --eif-path "$EIF" |
	python3 -c 'import sys,json;m=json.load(sys.stdin)["Measurements"];print(m["PCR0"],m["PCR1"],m["PCR2"])')
echo ">> pinning PCR0=$PCR0"

echo ">> bringing up host plane (run-host.sh)"
bash "$HERE/run-host.sh"
sleep 3

# Non-debug check: real attestation requires State=RUNNING and Flags=NONE.
nitro-cli describe-enclaves | python3 -c '
import sys,json
e=json.load(sys.stdin)
assert e and e[0]["State"]=="RUNNING" and e[0]["Flags"]=="NONE", "enclave not RUNNING/NONE: %s"%e
print(">> enclave RUNNING, Flags NONE (real attestation)")'

echo ">> starting host-side capture of the enclave hop (lo:$HOST_HTTPS_PORT)"
# Remove any stale (root-owned) capture from a prior run so tcpdump opens a fresh savefile;
# otherwise the re-open fails once tcpdump drops privileges to the unprivileged capture user.
sudo -n rm -f "$CAP"
sudo -n tcpdump -i lo -s 0 -w "$CAP" "port $HOST_HTTPS_PORT" &
TCPDUMP_PID=$!
sleep 1

echo ">> starting attesting sidecar (fails closed unless PCR0/1/2 + cert binding verify)"
(cd "$BACKEND" && go build -o "$HERE/client-sidecar" ./cmd/client-sidecar)
"$HERE/client-sidecar" -enclave-url "https://127.0.0.1:$HOST_HTTPS_PORT" -servername "$SERVERNAME" \
	-listen "$SIDECAR_LISTEN" -pcr0 "$PCR0" -pcr1 "$PCR1" -pcr2 "$PCR2" &
SIDECAR_PID=$!
sleep 3

echo ">> sending a real OpenAI Responses request THROUGH the sidecar"
body="$(python3 -c 'import json,os;print(json.dumps({"model":os.environ["MODEL"],"input":os.environ["PROMPT"],"stream":True}))')"
resp="$(curl -fsS "http://$SIDECAR_LISTEN/v1/responses" \
	-H "Authorization: Bearer $GATEWAY_API_KEY" -H "Content-Type: application/json" -d "$body")"
echo "$resp" | grep -q "response.completed" ||
	{ echo "!! no streamed completion in response:"; echo "$resp" | head; exit 1; }
echo ">> got a streamed completion through the sidecar"

echo ">> stopping capture; asserting the host hop carried only ciphertext"
sudo -n kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""
# Guard against a vacuous pass: if the capture is empty (tcpdump failed to write the
# savefile), the plaintext search below would trivially find nothing. Require real packets
# on the enclave hop before trusting the "no plaintext" result (goal ①).
pkts="$(sudo -n tcpdump -r "$CAP" 2>/dev/null | wc -l)"
[ "${pkts:-0}" -gt 0 ] ||
	{ echo "!! capture empty ($pkts packets) — goal ① NOT verified (tcpdump did not record the hop)"; exit 1; }
echo ">> captured $pkts packets on the host hop (lo:$HOST_HTTPS_PORT)"
needle="$(printf '%s' "$PROMPT" | cut -c1-16)"
if strings "$CAP" | grep -qF "$needle"; then
	echo "!! LEAK: prompt plaintext found on the host hop"
	exit 1
fi
echo ">> no plaintext prompt on the host hop"
echo ">> E2E PASS (goals ①②④ hold for the OpenAI path)"
