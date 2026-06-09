//go:build livetranslog

// Live round-trip against the configured Rekor instance (default rekor.sigstore.dev).
// Not part of the default test set; run explicitly:
//
//	go test -tags=livetranslog -run TestLive -v ./internal/sidecar/translog/
//
// It validates the full operator-publish + client-audit path end to end against the real
// public log, plus the three fail-closed negatives (not-uploaded, tampered, fork).
package translog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func liveManifest(t *testing.T) []byte {
	t.Helper()
	m := map[string]any{
		"schema_version": 1,
		"tag":            "livetranslog",
		"source_commit":  "livetest",
		"pcr0":           "11e0250e55f30435dc10352d5dea8e06e7affb7c299ee1242ff4aa2fb0d8cc5228dff43eebd4b4b5db0cc4e18e220f04",
		"pcr1":           "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa",
		"pcr2":           "1a257dd24581cfdd974a95ce3d746970031e028bfd25befcaac075207364c9aaa1ab82fc911da85bc2db1c57cdebf4de",
		// vary the bytes so each run is a fresh leaf
		"nonce": fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLiveRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rekorURL := os.Getenv("REKOR_URL")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := Ed25519PubToPKIXPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	manifest := liveManifest(t)
	sig := ed25519.Sign(priv, manifest)

	// Operator publish.
	c := NewClient(rekorURL)
	proposed, err := BuildRekordEd25519(manifest, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	uuid, entry, err := c.SubmitRekord(ctx, proposed)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	t.Logf("PUBLISHED uuid=%s globalLogIndex=%d", uuid, entry.LogIndex)

	store := filepath.Join(dir, "treeheads.json")
	cfg := AuditConfig{RekorURL: rekorURL, EntryUUID: uuid, StorePath: store}

	// Positive: full audit succeeds.
	res, err := Audit(ctx, cfg, manifest, sig, pubPEM)
	if err != nil {
		t.Fatalf("positive audit failed: %v", err)
	}
	t.Logf("AUDIT OK shard=%s treeSize=%d firstUse=%v root=%s",
		res.ShardTreeID, res.TreeSize, res.FirstUse, res.RootHashHex[:16])

	// Second audit reuses the persisted tree head -> consistency proof path exercised.
	res2, err := Audit(ctx, cfg, manifest, sig, pubPEM)
	if err != nil {
		t.Fatalf("second audit failed: %v", err)
	}
	if res2.FirstUse {
		t.Fatalf("expected consistency path on second audit, got firstUse")
	}
	t.Logf("AUDIT#2 OK consistencyChecked=%v treeSize=%d", res2.ConsistencyChecked, res2.TreeSize)

	// Negative 1: not uploaded -> unknown UUID -> fail closed.
	bad := AuditConfig{RekorURL: rekorURL, EntryUUID: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", StorePath: filepath.Join(dir, "n1.json")}
	if _, err := Audit(ctx, bad, manifest, sig, pubPEM); err == nil {
		t.Fatal("negative1 (not uploaded) unexpectedly passed")
	} else {
		t.Logf("NEG1 fail-closed as expected: %v", err)
	}

	// Negative 2: tampered manifest -> BindManifest mismatch -> fail closed.
	tampered := append([]byte(nil), manifest...)
	tampered[len(tampered)-2] ^= 0xff
	if _, err := Audit(ctx, cfg, tampered, sig, pubPEM); err == nil {
		t.Fatal("negative2 (tampered manifest) unexpectedly passed")
	} else {
		t.Logf("NEG2 fail-closed as expected: %v", err)
	}

	// Negative 3: forked/rewound tree head -> consistency fails -> fail closed.
	// Seed the store with a bogus head at the same shard but a larger size + wrong root.
	forkStore := filepath.Join(dir, "fork.json")
	s := &treeHeadStore{Heads: map[string]TreeHead{
		res.ShardTreeID: {TreeSize: res.TreeSize + 1_000_000_000, RootHashHex: "deadbeef" + res.RootHashHex[8:]},
	}}
	if err := s.save(forkStore); err != nil {
		t.Fatal(err)
	}
	forkCfg := AuditConfig{RekorURL: rekorURL, EntryUUID: uuid, StorePath: forkStore}
	if _, err := Audit(ctx, forkCfg, manifest, sig, pubPEM); err == nil {
		t.Fatal("negative3 (fork) unexpectedly passed")
	} else {
		t.Logf("NEG3 fail-closed as expected: %v", err)
	}
}
