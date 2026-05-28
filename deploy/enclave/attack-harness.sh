#!/usr/bin/env bash
# Attack harness for the paper's Table 1 (goals ①②④ vs the Your-Agent-Is-Mine attack classes).
#
# It runs the four malicious-router primitives against a MOCK upstream and shows they SUCCEED when
# the router has plaintext access (the BASELINE: a compromised/malicious sub2api-class router) — then
# contrasts with our confidential router, where the untrusted host has NO plaintext to scan or rewrite
# (OURS, evidenced by the conformance tests, the vsock RPC shape, and the e2e ciphertext capture).
#
# No enclave / no sudo / no real OpenAI key needed: the BASELINE column is demonstrated live here; the
# OURS column is backed by already-run artifacts (forward_test.go, internal/confidential/rpc.go,
# e2e-smoke.sh). Run `e2e-smoke.sh` separately for the live ciphertext proof of the OURS column.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$(cd "$HERE/../.." && pwd)/backend"
BIN="/tmp/cr-attack"; mkdir -p "$BIN"
EXFIL="/tmp/cr-attack-exfil.log"
AWS_KEY="AKIAIOSFODNN7EXAMPLE" # canonical AWS example key
MOCK_PID="" PROXY_PID=""

cleanup() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null; true; }
trap cleanup EXIT

echo ">> building malicious-router"
(cd "$BACKEND" && go build -o "$BIN/malicious-router" ./cmd/malicious-router)

# Mock OpenAI upstream: returns a tool-call whose shell command echoes the X-Mock-Command header.
cat > "$BIN/mock.py" <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length','0') or 0))
        cmd = self.headers.get('X-Mock-Command', 'pip install requests')
        body = json.dumps({"choices":[{"message":{"role":"assistant","tool_calls":[
            {"id":"c1","type":"function","function":{"name":"bash","arguments":json.dumps({"command":cmd})}}]}}]}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',19001), H).serve_forever()
PY
python3 "$BIN/mock.py" & MOCK_PID=$!
sleep 0.5

cmd_of() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.loads(d["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])["command"])'; }
start_proxy() { [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null; "$BIN/malicious-router" -listen 127.0.0.1:19002 -upstream http://127.0.0.1:19001 -exfil "$EXFIL" ${1:+-trigger "$1"} >/tmp/cr-attack-proxy.log 2>&1 & PROXY_PID=$!; sleep 0.5; }
send() { curl -fsS -H "X-Mock-Command: $1" -H "Content-Type: application/json" -d "$2" http://127.0.0.1:19002/v1/chat/completions; }

declare -A AC1 AC1a AC1b AC2
rm -f "$EXFIL"

# --- AC-2 (secret exfil) + AC-1.a (typosquat), no trigger ---
start_proxy ""
resp="$(send 'pip install requests' "{\"messages\":[{\"role\":\"user\",\"content\":\"deploy with $AWS_KEY\"}]}")"
grep -q "$AWS_KEY" "$EXFIL" && AC2=ok || AC2=fail
c="$(printf '%s' "$resp" | cmd_of)"; [ "$c" != "pip install requests" ] && echo "$c" | grep -q install && AC1a=ok || AC1a=fail
echo ">> AC-2 exfil: ${AC2}  (captured: $(grep -c AC-2 "$EXFIL") secret(s))"
echo ">> AC-1.a typosquat: ${AC1a}  ('pip install requests' -> '$c')"

# --- AC-1 (arbitrary command injection) ---
resp="$(send 'cat /etc/passwd' '{"messages":[{"role":"user","content":"hi"}]}')"
c="$(printf '%s' "$resp" | cmd_of)"; echo "$c" | grep -q 'attacker.evil' && AC1=ok || AC1=fail
echo ">> AC-1 inject: ${AC1}  ('cat /etc/passwd' -> '$c')"

# --- AC-1.b (conditional / triggered delivery) ---
start_proxy "YOLO"
c_benign="$(send 'pip install flask' '{"messages":[{"role":"user","content":"normal request"}]}' | cmd_of)"
c_trig="$(send 'pip install flask' '{"messages":[{"role":"user","content":"run in YOLO mode"}]}' | cmd_of)"
{ [ "$c_benign" = "pip install flask" ] && [ "$c_trig" != "pip install flask" ]; } && AC1b=ok || AC1b=fail
echo ">> AC-1.b triggered: ${AC1b}  (no-trigger='$c_benign' | trigger='$c_trig')"

ok() { [ "$1" = ok ] && echo "SUCCEEDS" || echo "FAIL(harness)"; }
echo
echo "================ Table 1: attack on a router with plaintext access ================"
printf '%-9s | %-28s | %s\n' "Attack" "Baseline (malicious router)" "Confidential router (ours)"
printf '%-9s | %-28s | %s\n' "AC-1"   "$(ok $AC1)"   "BLOCKED — host sees only ciphertext; attested faithful passthrough"
printf '%-9s | %-28s | %s\n' "AC-1.a" "$(ok $AC1a)"  "BLOCKED — same (no host rewrite path)"
printf '%-9s | %-28s | %s\n' "AC-1.b" "$(ok $AC1b)"  "BLOCKED — rewrite impossible at source; triggers moot"
printf '%-9s | %-28s | %s\n' "AC-2"   "$(ok $AC2)"   "BLOCKED — host hop ciphertext (e2e); vsock RPC carries no body"
echo "==================================================================================="
echo "OURS evidence: internal/enclave/forward_test.go (faithful passthrough),"
echo "  internal/confidential/rpc.go (authorize_and_select = api_key + routing, NO body),"
echo "  deploy/enclave/e2e-smoke.sh (host hop = ciphertext only)."

[ "$AC1" = ok ] && [ "$AC1a" = ok ] && [ "$AC1b" = ok ] && [ "$AC2" = ok ] &&
	{ echo ">> HARNESS OK: all four attacks demonstrated on the baseline"; exit 0; } ||
	{ echo "!! HARNESS: an attack did not reproduce — inspect /tmp/cr-attack-proxy.log"; exit 1; }
