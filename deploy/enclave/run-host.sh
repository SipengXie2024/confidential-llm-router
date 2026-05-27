#!/usr/bin/env bash
# Brings up the host plane for the confidential router: the host-orchestrator (vsock RPC),
# gvproxy (TCP<->vsock bridge), the enclave itself (NON-debug), and the gvproxy forwarder
# rule that exposes a host TCP port to the enclave's in-TLS :443.
#
# Prerequisites:
#   - build-eif.sh has produced router.eif
#   - host-orchestrator can reach its config + Postgres + Redis (it builds the real services)
#   - sudo is available for nitro-cli run-enclave; the Nitro allocator is configured
#   - gvproxy is installed (GVPROXY env or the default path below)
# Cleanup is intentionally separate (see RUNBOOK): terminate-enclave + kill gvproxy/orchestrator.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BACKEND="$REPO/backend"

# host-orchestrator builds the real sub2api services, so it needs the gateway env
# (DATABASE_*/REDIS_*/DATA_DIR + secrets). Source the gitignored env if present.
set -a
[ -f "$REPO/deploy/.env" ] && . "$REPO/deploy/.env"
set +a

EIF="${EIF:-$HERE/router.eif}"
VSOCK_PORT="${VSOCK_PORT:-9000}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-2048}"
HOST_HTTPS_PORT="${HOST_HTTPS_PORT:-10443}"
GVPROXY="${GVPROXY:-/home/ubuntu/go/bin/gvproxy}"
NETSOCK=/tmp/network.sock

[ -f "$EIF" ] || {
	echo "missing $EIF — run build-eif.sh first" >&2
	exit 1
}

echo ">> building host-orchestrator"
(cd "$BACKEND" && go build -o "$HERE/host-orchestrator" ./cmd/host-orchestrator)

echo ">> starting host-orchestrator (vsock port $VSOCK_PORT; needs config + Postgres + Redis)"
nohup "$HERE/host-orchestrator" -vsock-port "$VSOCK_PORT" >/tmp/cr-host-orchestrator.log 2>&1 &
ORCH_PID=$!
disown "$ORCH_PID" 2>/dev/null || true

echo ">> starting gvproxy (vsock://:1024 + $NETSOCK)"
rm -f "$NETSOCK"
nohup "$GVPROXY" -listen vsock://:1024 -listen "unix://$NETSOCK" >/tmp/cr-gvproxy.log 2>&1 &
GV_PID=$!
disown "$GV_PID" 2>/dev/null || true
sleep 2

echo ">> run-enclave (non-debug) cid=$ENCLAVE_CID cpu=$CPU_COUNT mem=${MEMORY_MIB}MiB"
sudo -n nitro-cli run-enclave \
	--cpu-count "$CPU_COUNT" \
	--memory "$MEMORY_MIB" \
	--enclave-cid "$ENCLAVE_CID" \
	--eif-path "$EIF"

echo ">> exposing host :$HOST_HTTPS_PORT -> enclave 192.168.127.2:443"
curl -fsS --unix-socket "$NETSOCK" http:/unix/services/forwarder/expose \
	-X POST -d "{\"local\":\":$HOST_HTTPS_PORT\",\"remote\":\"192.168.127.2:443\"}"

echo
echo ">> host plane up: host-orchestrator pid=$ORCH_PID gvproxy pid=$GV_PID"
nitro-cli describe-enclaves
