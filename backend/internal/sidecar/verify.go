package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hf/nitrite"
)

// Verification logic ported from the verified spike:
// /home/ubuntu/nitriding-spike/verify-attestation/main.go (proven end-to-end against
// a live, non-debug Nitro enclave on this host, 2026-05-26).

const (
	hashPrefixLen  = 2
	sha256MultiTag = "\x12\x20" // multihash tag for SHA-256
)

// certBoundInUserData reports whether the attestation user_data binds the presented
// TLS leaf certificate: bytes 0..1 are the SHA-256 multihash tag and bytes 2..33 are
// SHA-256(certDER). This is what stops a malicious host from terminating the client
// TLS itself — the cert it could present is not the one in the NSM-signed document.
func certBoundInUserData(userData, certDER []byte) bool {
	if len(userData) < hashPrefixLen+sha256.Size {
		return false
	}
	if string(userData[:hashPrefixLen]) != sha256MultiTag {
		return false
	}
	sum := sha256.Sum256(certDER)
	return bytes.Equal(userData[hashPrefixLen:hashPrefixLen+sha256.Size], sum[:])
}

// Verify checks a raw Nitro attestation document end to end: AWS COSE signature + cert
// chain (nitrite.Verify), nonce freshness, the pinned PCRs, and the TLS-cert binding.
// expectedPCR maps PCR index → expected hex; an all-zero PCR (debug-mode enclave) is
// rejected. A non-nil error means the channel MUST NOT be trusted (fail closed).
func Verify(doc []byte, expectedPCR map[int]string, nonce, certDER []byte) error {
	res, err := nitrite.Verify(doc, nitrite.VerifyOptions{CurrentTime: time.Now()})
	if err != nil {
		return fmt.Errorf("attestation signature verification failed: %w", err)
	}
	d := res.Document

	if !bytes.Equal(d.Nonce, nonce) {
		return fmt.Errorf("nonce mismatch: expected %x got %x", nonce, d.Nonce)
	}

	for index, expectedHex := range expectedPCR {
		got, ok := d.PCRs[uint(index)]
		if !ok {
			return fmt.Errorf("attestation missing PCR%d", index)
		}
		if isAllZero(got) {
			return fmt.Errorf("PCR%d is all-zero (debug-mode enclave; untrusted)", index)
		}
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("bad expected PCR%d hex: %w", index, err)
		}
		if !bytes.Equal(got, expected) {
			return fmt.Errorf("PCR%d mismatch: expected %x got %x", index, expected, got)
		}
	}

	if !certBoundInUserData(d.UserData, certDER) {
		return fmt.Errorf("TLS cert not bound in attestation user_data")
	}
	return nil
}

func isAllZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
