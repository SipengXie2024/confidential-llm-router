//go:build unit

package sidecar

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func signedManifest(t *testing.T) (manifest []byte, sig []byte, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	manifest = []byte(`{"schema_version":1,"tag":"v0.1","source_commit":"abc","pcr0":"aa","pcr1":"bb","pcr2":"cc","base_image_digest":"sha256:d","nitriding_commit":"e","source_date_epoch":1700000000}`)
	return manifest, ed25519.Sign(priv, manifest), hex.EncodeToString(pub)
}

func TestLoadVerifiedManifestRoundtrip(t *testing.T) {
	manifest, sig, pubHex := signedManifest(t)
	m, err := LoadVerifiedManifest(manifest, sig, pubHex)
	if err != nil {
		t.Fatalf("LoadVerifiedManifest: %v", err)
	}
	if m.PCR0 != "aa" || m.PCR1 != "bb" || m.PCR2 != "cc" {
		t.Fatalf("parsed PCRs wrong: %+v", m)
	}
	e := m.ExpectedPCR()
	if e[0] != "aa" || e[1] != "bb" || e[2] != "cc" {
		t.Fatalf("ExpectedPCR wrong: %+v", e)
	}
}

func TestLoadVerifiedManifestRejectsTamper(t *testing.T) {
	manifest, sig, pubHex := signedManifest(t)
	// Flip one byte of the manifest (e.g. swap a PCR digit) — the signature must no longer verify.
	tampered := make([]byte, len(manifest))
	copy(tampered, manifest)
	idx := indexOf(tampered, []byte(`"pcr0":"aa"`)) + len(`"pcr0":"`)
	tampered[idx] = 'b'
	if _, err := LoadVerifiedManifest(tampered, sig, pubHex); err == nil {
		t.Fatal("expected signature failure on a tampered manifest (fail closed)")
	}
}

func TestLoadVerifiedManifestRejectsWrongKey(t *testing.T) {
	manifest, sig, _ := signedManifest(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := LoadVerifiedManifest(manifest, sig, hex.EncodeToString(otherPub)); err == nil {
		t.Fatal("expected verification failure under a different public key")
	}
	if _, err := LoadVerifiedManifest(manifest, sig, "not-hex"); err == nil {
		t.Fatal("expected error for a malformed public key")
	}
}

func TestLoadVerifiedManifestRejectsBadSigEncoding(t *testing.T) {
	// A signature decoded from base64 (as the sidecar does) that is the wrong length must fail.
	manifest, _, pubHex := signedManifest(t)
	badSig, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := LoadVerifiedManifest(manifest, badSig, pubHex); err == nil {
		t.Fatal("expected failure for a wrong-length signature")
	}
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}
