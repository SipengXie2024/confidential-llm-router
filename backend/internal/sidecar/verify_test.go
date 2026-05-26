//go:build unit

package sidecar

import (
	"crypto/sha256"
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
