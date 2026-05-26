//go:build unit

package sidecar

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestCertBoundInUserData(t *testing.T) {
	cert := []byte("fake-cert-DER")
	sum := sha256.Sum256(cert)
	ud := make([]byte, 68)
	ud[0] = 0x12
	ud[1] = 0x20
	copy(ud[2:34], sum[:])
	if !certBoundInUserData(ud, cert) {
		t.Fatal("should be bound")
	}
	if certBoundInUserData(ud, []byte("other")) {
		t.Fatal("must reject wrong cert")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	// Empty nonce is rejected before any signature work (replay protection).
	if err := Verify(nil, map[int]string{0: "00"}, nil, nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("empty nonce must be rejected with a nonce error, got: %v", err)
	}
	// An expectedPCR map that does not pin PCR0 must be rejected (no measurement skip).
	if err := Verify(nil, map[int]string{1: "00"}, []byte("n"), nil); err == nil || !strings.Contains(err.Error(), "PCR0") {
		t.Fatalf("missing PCR0 pin must be rejected, got: %v", err)
	}
	if err := Verify(nil, nil, []byte("n"), nil); err == nil || !strings.Contains(err.Error(), "PCR0") {
		t.Fatalf("nil expectedPCR must be rejected, got: %v", err)
	}
}
