#!/usr/bin/env bash
# Reproducible-build check (ARPA "Reproduce" step): build the EIF twice and assert PCR0/1/2
# are identical. No sudo and no running enclave needed — only build-enclave/describe-eif, which
# do not require the Nitro CPU pool. Two builds of the same pinned source must yield the same
# measurement, so "PCR0 == hash(audited source)" is independently checkable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pcrs() {
	nitro-cli describe-eif --eif-path "$1" |
		python3 -c 'import sys,json;m=json.load(sys.stdin)["Measurements"];print(m["PCR0"],m["PCR1"],m["PCR2"])'
}

E1="$HERE/router.repro1.eif"
E2="$HERE/router.repro2.eif"
cleanup() { rm -f "$E1" "$E2"; }
trap cleanup EXIT

echo ">> build #1"
EIF="$E1" IMAGE="confidential-router:repro1" bash "$HERE/build-eif.sh" >/tmp/cr-repro1.log 2>&1 ||
	{ echo "!! build #1 failed:"; tail -25 /tmp/cr-repro1.log; exit 1; }
echo ">> build #2"
EIF="$E2" IMAGE="confidential-router:repro2" bash "$HERE/build-eif.sh" >/tmp/cr-repro2.log 2>&1 ||
	{ echo "!! build #2 failed:"; tail -25 /tmp/cr-repro2.log; exit 1; }

p1="$(pcrs "$E1")"
p2="$(pcrs "$E2")"
echo ">> build #1 PCR0/1/2: $p1"
echo ">> build #2 PCR0/1/2: $p2"

if [ "$p1" = "$p2" ]; then
	echo ">> REPRODUCIBLE: PCR0/1/2 identical across two independent builds"
	exit 0
fi
echo "!! NOT bit-reproducible: PCR0/1/2 differ — inspect the residual (Go binary, docker layer"
echo "!! timestamps, or nitro-cli/linuxkit determinism). Document it in the paper if it persists."
exit 1
