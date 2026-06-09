//go:build unit

package translog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func testECKey(t *testing.T) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return k, pemBytes, der
}

func signASN1(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifySET(t *testing.T) {
	k, pemBytes, _ := testECKey(t)
	e := &Entry{
		Body:           base64.StdEncoding.EncodeToString([]byte(`{"kind":"rekord"}`)),
		IntegratedTime: 1780975066,
		LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		LogIndex:       1761440625,
	}
	canon := fmt.Sprintf(`{"body":%q,"integratedTime":%d,"logID":%q,"logIndex":%d}`,
		e.Body, e.IntegratedTime, e.LogID, e.LogIndex)
	e.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(signASN1(t, k, []byte(canon)))

	if err := VerifySET(pemBytes, e); err != nil {
		t.Fatalf("valid SET rejected: %v", err)
	}
	// Tamper a field the SET covers -> must fail.
	e.LogIndex++
	if err := VerifySET(pemBytes, e); err == nil {
		t.Fatal("SET accepted after logIndex tamper")
	}
	e.LogIndex--
	// Wrong key -> must fail.
	_, otherPEM, _ := testECKey(t)
	if err := VerifySET(otherPEM, e); err == nil {
		t.Fatal("SET accepted under the wrong Rekor key")
	}
}

func makeCheckpoint(t *testing.T, k *ecdsa.PrivateKey, der []byte, origin string, size int64, root []byte) string {
	t.Helper()
	text := fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root))
	sig := signASN1(t, k, []byte(text))
	keySum := sha256.Sum256(der)
	blob := append(append([]byte{}, keySum[:4]...), sig...)
	return text + "\n— testlog " + base64.StdEncoding.EncodeToString(blob) + "\n"
}

func TestVerifyCheckpoint(t *testing.T) {
	k, pemBytes, der := testECKey(t)
	root := sha256.Sum256([]byte("root"))
	origin := "rekor.local - 1193050959916656506"
	cp := makeCheckpoint(t, k, der, origin, 1639560562, root[:])

	got, err := VerifyCheckpoint(pemBytes, cp)
	if err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	if got.TreeSize != 1639560562 {
		t.Fatalf("tree size: got %d", got.TreeSize)
	}
	if got.TreeID != "1193050959916656506" {
		t.Fatalf("tree id: got %q", got.TreeID)
	}
	if !equalBytes(got.RootHash, root[:]) {
		t.Fatal("root hash mismatch")
	}

	// Tamper the signed text (swap the root) -> signature must fail.
	bad := sha256.Sum256([]byte("evil-root"))
	tampered := fmt.Sprintf("%s\n%d\n%s\n", origin, int64(1639560562), base64.StdEncoding.EncodeToString(bad[:]))
	// reuse the original signature over the original text
	sig := signASN1(t, k, []byte(fmt.Sprintf("%s\n%d\n%s\n", origin, int64(1639560562), base64.StdEncoding.EncodeToString(root[:]))))
	keySum := sha256.Sum256(der)
	blob := append(append([]byte{}, keySum[:4]...), sig...)
	forged := tampered + "\n— testlog " + base64.StdEncoding.EncodeToString(blob) + "\n"
	if _, err := VerifyCheckpoint(pemBytes, forged); err == nil {
		t.Fatal("checkpoint accepted a tampered tree head")
	}

	// Wrong key hint -> must fail.
	_, otherPEM, _ := testECKey(t)
	if _, err := VerifyCheckpoint(otherPEM, cp); err == nil {
		t.Fatal("checkpoint accepted under the wrong Rekor key")
	}
}
