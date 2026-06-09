#!/usr/bin/env bash
# Transparency-log accountability evaluation for the ARPA flow (Sigstore Rekor).
#
# Proves that the client-sidecar pins an enclave measurement ONLY when the operator's signed
# measurement manifest is verifiably recorded in a public, append-only transparency log. One
# positive scenario (publish -> verify inclusion + SET + signed checkpoint + consistency -> pin)
# and three fail-closed negatives (not-logged, tampered measurement, forked/split tree head).
#
# This exercises the SAME verification code path the production sidecar runs at pin time
# (cmd/client-sidecar -audit-only), against the real public Rekor unless REKOR_URL overrides it.
# No enclave/Nitro is required: the transparency-log audit is logically separable from the live
# attestation, so this is self-contained, reproducible paper evidence.
#
# Output is tee'd to deploy/enclave/translog-eval.log.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BACKEND="$REPO/backend"
REKOR_URL="${REKOR_URL:-https://rekor.sigstore.dev}"
LOG="$HERE/translog-eval.log"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

exec > >(tee "$LOG") 2>&1

echo "=================================================================="
echo "ARPA transparency-log (Rekor) accountability evaluation"
echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "rekor_url=$REKOR_URL"
echo "repo_commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "work_dir=$WORK"
echo "=================================================================="

PASS=0
FAIL=0
# expect_ok NAME CMD...  -> scenario passes if CMD exits 0
expect_ok() {
	local name="$1"; shift
	echo; echo "------ [$name] expect: SUCCEED ------"
	echo "+ $*"
	if "$@"; then
		echo ">> [$name] PASS (verified + pinned as expected)"; PASS=$((PASS+1))
	else
		echo ">> [$name] FAIL (expected success, got failure)"; FAIL=$((FAIL+1))
	fi
}
# expect_fail NAME NEEDLE CMD... -> scenario passes if CMD exits non-zero (fail closed)
expect_fail() {
	local name="$1" needle="$2"; shift 2
	echo; echo "------ [$name] expect: FAIL CLOSED ------"
	echo "+ $*"
	local out rc
	out="$("$@" 2>&1)"; rc=$?
	echo "$out"
	if [ "$rc" -ne 0 ]; then
		if [ -z "$needle" ] || grep -qF "$needle" <<<"$out"; then
			echo ">> [$name] PASS (failed closed; refused to pin)"; PASS=$((PASS+1))
		else
			echo ">> [$name] FAIL (failed, but not at the expected check: want '$needle')"; FAIL=$((FAIL+1))
		fi
	else
		echo ">> [$name] FAIL (expected fail-closed, but it succeeded)"; FAIL=$((FAIL+1))
	fi
}

echo; echo ">> building operator tool (measure-sign) and client-sidecar"
(cd "$BACKEND" && go build -o "$WORK/measure-sign" ./cmd/measure-sign && go build -o "$WORK/client-sidecar" ./cmd/client-sidecar) || {
	echo "!! build failed"; exit 1; }
MS="$WORK/measure-sign"
SC="$WORK/client-sidecar"

echo ">> generating operator Ed25519 key"
"$MS" -genkey -priv "$WORK/op.key" -pub "$WORK/op.pub" >/dev/null
PUB="$(cat "$WORK/op.pub")"

# Build a realistic ARPA manifest from the current EIF measurements if available.
PCR0="11e0250e55f30435dc10352d5dea8e06e7affb7c299ee1242ff4aa2fb0d8cc5228dff43eebd4b4b5db0cc4e18e220f04"
PCR1="0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa"
PCR2="1a257dd24581cfdd974a95ce3d746970031e028bfd25befcaac075207364c9aaa1ab82fc911da85bc2db1c57cdebf4de"
if command -v nitro-cli >/dev/null 2>&1 && [ -f "$HERE/router.eif" ]; then
	read -r P0 P1 P2 < <(nitro-cli describe-eif --eif-path "$HERE/router.eif" 2>/dev/null |
		python3 -c 'import sys,json;m=json.load(sys.stdin)["Measurements"];print(m["PCR0"],m["PCR1"],m["PCR2"])' 2>/dev/null || true)
	[ -n "${P0:-}" ] && PCR0="$P0" PCR1="$P1" PCR2="$P2"
fi

mkmanifest() { # $1=outfile $2=tag (varies bytes so each run is a fresh leaf)
	PCR0="$PCR0" PCR1="$PCR1" PCR2="$PCR2" TAG="$2" python3 -c '
import json,os,sys
json.dump({"schema_version":1,"tag":os.environ["TAG"],"source_commit":"translog-eval",
"pcr0":os.environ["PCR0"],"pcr1":os.environ["PCR1"],"pcr2":os.environ["PCR2"],
"base_image_digest":"","nitriding_commit":"","source_date_epoch":0}, open(sys.argv[1],"w"))' "$1"
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MANIFEST="$WORK/measurements.json"
mkmanifest "$MANIFEST" "translog-eval-$STAMP"
"$MS" -priv "$WORK/op.key" -in "$MANIFEST" -sig "$MANIFEST.sig" >/dev/null
echo ">> manifest: $(python3 -c 'import hashlib;print("sha256="+hashlib.sha256(open("'"$MANIFEST"'","rb").read()).hexdigest())')"

# ---------------------------------------------------------------------------
# Scenario 1 (POSITIVE): publish to Rekor, then audit (inclusion+SET+checkpoint),
# then audit again to exercise the append-only CONSISTENCY proof.
# ---------------------------------------------------------------------------
echo; echo "------ [1-publish] publishing signed manifest to Rekor ------"
echo "+ $MS -publish -in measurements.json -sig measurements.json.sig -pub op.pub -rekor-url $REKOR_URL -bundle bundle.json"
if ! "$MS" -publish -in "$MANIFEST" -sig "$MANIFEST.sig" -pub "$WORK/op.pub" -rekor-url "$REKOR_URL" -bundle "$WORK/bundle.json"; then
	echo "!! publish failed (network to Rekor?)"; FAIL=$((FAIL+1))
fi
if [ -f "$WORK/bundle.json" ]; then
	UUID="$(python3 -c 'import json;print(json.load(open("'"$WORK/bundle.json"'"))["entry_uuid"])')"
	LIDX="$(python3 -c 'import json;print(json.load(open("'"$WORK/bundle.json"'"))["log_index"])')"
	echo ">> REKOR ENTRY uuid=$UUID globalLogIndex=$LIDX"
	echo ">> public entry URL: $REKOR_URL/api/v1/log/entries/$UUID"
fi

STORE="$WORK/treeheads.json"
expect_ok "1a-audit-first" "$SC" -audit-only -require-translog \
	-manifest "$MANIFEST" -manifest-pubkey "$PUB" \
	-translog-bundle "$WORK/bundle.json" -treehead-store "$STORE"

echo ">> waiting briefly so the tree grows, then re-auditing to exercise the consistency proof"
sleep 8
expect_ok "1b-audit-consistency" "$SC" -audit-only -require-translog \
	-manifest "$MANIFEST" -manifest-pubkey "$PUB" \
	-translog-bundle "$WORK/bundle.json" -treehead-store "$STORE"

# ---------------------------------------------------------------------------
# Scenario 2 (NEGATIVE: not logged): a signed-but-never-published manifest. With
# -require-translog and no bundle, the sidecar refuses to pin.
# ---------------------------------------------------------------------------
mkmanifest "$WORK/unlogged.json" "never-published-$STAMP"
"$MS" -priv "$WORK/op.key" -in "$WORK/unlogged.json" -sig "$WORK/unlogged.json.sig" >/dev/null
expect_fail "2-not-logged" "no Rekor entry to audit" "$SC" -audit-only -require-translog \
	-manifest "$WORK/unlogged.json" -manifest-pubkey "$PUB" -treehead-store "$WORK/s2.json"

# ---------------------------------------------------------------------------
# Scenario 3 (NEGATIVE: tampered measurement): operator presents a DIFFERENT but
# validly-signed manifest while pointing at the published entry. The transparency
# binding (logged digest != sha256(presented manifest)) catches the swap.
# ---------------------------------------------------------------------------
mkmanifest "$WORK/tampered.json" "translog-eval-$STAMP"   # same tag, but mutate a PCR below
python3 - "$WORK/tampered.json" <<'PY'
import json,sys
p=sys.argv[1]; m=json.load(open(p))
m["pcr0"]=("ff"+m["pcr0"][2:])   # flip the measurement: a different enclave image
json.dump(m,open(p,"w"))
PY
"$MS" -priv "$WORK/op.key" -in "$WORK/tampered.json" -sig "$WORK/tampered.json.sig" >/dev/null
expect_fail "3-tampered-measurement" "data hash != sha256(manifest)" "$SC" -audit-only -require-translog \
	-manifest "$WORK/tampered.json" -manifest-pubkey "$PUB" \
	-translog-bundle "$WORK/bundle.json" -treehead-store "$WORK/s3.json"

# ---------------------------------------------------------------------------
# Scenario 4 (NEGATIVE: fork / split view): seed the client's persisted tree head
# with a head INCONSISTENT with Rekor's actual log (larger size, wrong root) — the
# situation a forking operator/log would create. The consistency check rejects it.
# (We cannot fork the real public log, so we present the inconsistent head directly;
#  the rejection is exactly the mechanism that defeats an operator split-view.)
# ---------------------------------------------------------------------------
if [ -f "$WORK/bundle.json" ]; then
	python3 - "$WORK/bundle.json" "$WORK/fork-store.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
cp=b["entry"]["verification"]["inclusionProof"]["checkpoint"]
tree_id=cp.split("\n")[0].split(" - ")[-1].strip()
size=int(cp.split("\n")[1])
json.dump({"heads":{tree_id:{"tree_size":size+1000000000,"root_hash_hex":"deadbeef"+"00"*30}}},
          open(sys.argv[2],"w"))
print("seeded inconsistent tree head for shard",tree_id)
PY
	expect_fail "4-fork-split-view" "" "$SC" -audit-only -require-translog \
		-manifest "$MANIFEST" -manifest-pubkey "$PUB" \
		-translog-bundle "$WORK/bundle.json" -treehead-store "$WORK/fork-store.json"
fi

echo
echo "=================================================================="
echo "RESULT: PASS=$PASS FAIL=$FAIL"
echo "log written to: $LOG"
echo "=================================================================="
[ "$FAIL" -eq 0 ]
