//go:build unit

package translog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// makeRekordBody builds the canonical rekord body Rekor stores (content replaced by its sha256),
// so BindManifest is tested against the exact shape it parses in production.
func makeRekordBody(t *testing.T, manifest, sig, pubPEM []byte) string {
	t.Helper()
	sum := sha256.Sum256(manifest)
	body := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "rekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(sum[:])},
			},
			"signature": map[string]any{
				"format":    "x509",
				"content":   base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestBindManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := Ed25519PubToPKIXPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"schema_version":1,"pcr0":"abc"}`)
	sig := ed25519.Sign(priv, manifest)
	bodyB64 := makeRekordBody(t, manifest, sig, pubPEM)

	if err := BindManifest(bodyB64, manifest, sig, pubPEM); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}

	// Negative: tampered manifest -> logged data hash no longer matches.
	tampered := []byte(`{"schema_version":1,"pcr0":"EVIL"}`)
	if err := BindManifest(bodyB64, tampered, sig, pubPEM); err == nil {
		t.Fatal("binding accepted a tampered manifest")
	}

	// Negative: different operator signature -> mismatch.
	otherSig := ed25519.Sign(priv, []byte("something else"))
	if err := BindManifest(bodyB64, manifest, otherSig, pubPEM); err == nil {
		t.Fatal("binding accepted a wrong signature")
	}

	// Negative: different operator public key -> mismatch.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPEM, _ := Ed25519PubToPKIXPEM(otherPub)
	if err := BindManifest(bodyB64, manifest, sig, otherPEM); err == nil {
		t.Fatal("binding accepted a wrong public key")
	}
}

func TestLeafHashFromBody(t *testing.T) {
	body := []byte(`{"kind":"rekord"}`)
	b64 := base64.StdEncoding.EncodeToString(body)
	got, err := LeafHashFromBody(b64)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(got, refLeaf(body)) {
		t.Fatal("leaf hash mismatch with reference")
	}
}
