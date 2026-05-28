package sidecar

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Manifest is the ARPA Phase-0 measurement anchor: it binds a published release (tag + source
// commit + reproducible build inputs) to the expected enclave measurement (PCR0/1/2). The client
// pins this signed manifest instead of trusting an operator-typed PCR value, so the verified
// chain becomes: trusted signing key -> manifest -> PCR -> live attestation.
type Manifest struct {
	SchemaVersion   int    `json:"schema_version"`
	Tag             string `json:"tag"`
	SourceCommit    string `json:"source_commit"`
	PCR0            string `json:"pcr0"`
	PCR1            string `json:"pcr1"`
	PCR2            string `json:"pcr2"`
	BaseImageDigest string `json:"base_image_digest"`
	NitridingCommit string `json:"nitriding_commit"`
	SourceDateEpoch int64  `json:"source_date_epoch"`
}

// LoadVerifiedManifest verifies the Ed25519 signature over the EXACT manifest bytes against the
// pinned public key, then parses it. Fails closed on a bad key, a bad signature, or a missing
// PCR0. Signing the literal bytes (not a re-canonicalized form) avoids JSON-canonicalization
// ambiguity — the client verifies precisely what was published.
func LoadVerifiedManifest(manifestBytes, sig []byte, pubKeyHex string) (*Manifest, error) {
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("manifest public key must be %d-byte ed25519 hex", ed25519.PublicKeySize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), manifestBytes, sig) {
		return nil, fmt.Errorf("manifest signature verification failed (refusing to pin)")
	}
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if strings.TrimSpace(m.PCR0) == "" {
		return nil, fmt.Errorf("manifest missing pcr0")
	}
	return &m, nil
}

// ExpectedPCR builds the verification map consumed by Verify. PCR0 is always present;
// PCR1/PCR2 are included only when non-empty.
func (m *Manifest) ExpectedPCR() map[int]string {
	e := map[int]string{0: m.PCR0}
	if m.PCR1 != "" {
		e[1] = m.PCR1
	}
	if m.PCR2 != "" {
		e[2] = m.PCR2
	}
	return e
}
