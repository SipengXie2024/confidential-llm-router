package translog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// --- ECDSA helpers -----------------------------------------------------------

// parseECDSAPubFromPEM parses a PKIX/SPKI PEM ECDSA public key (the Rekor log key form).
func parseECDSAPubFromPEM(pemBytes []byte) (*ecdsa.PublicKey, []byte, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, nil, fmt.Errorf("rekor public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse rekor public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("rekor public key is not ECDSA")
	}
	return ec, blk.Bytes, nil
}

// LogIDFromPEM returns the hex sha256 of the DER (SPKI) of a PEM public key — Rekor's logID.
func LogIDFromPEM(pemBytes []byte) (string, error) {
	_, der, err := parseECDSAPubFromPEM(pemBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// --- Signed Entry Timestamp (SET) -------------------------------------------

// VerifySET checks the per-entry SET: an ECDSA-P256/SHA-256 signature by the Rekor shard key
// over the RFC 8785 canonical JSON of {body, integratedTime, logID, logIndex}. The four fields
// are flat (two strings, two ints) so the canonical form is constructed directly. A valid SET
// means Rekor committed to exactly this entry at integratedTime (inclusion soundness).
func VerifySET(rekorPubPEM []byte, e *Entry) error {
	pub, _, err := parseECDSAPubFromPEM(rekorPubPEM)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.Verification.SignedEntryTimestamp))
	if err != nil {
		return fmt.Errorf("decode SET: %w", err)
	}
	canon := fmt.Sprintf(`{"body":%q,"integratedTime":%d,"logID":%q,"logIndex":%d}`,
		e.Body, e.IntegratedTime, e.LogID, e.LogIndex)
	digest := sha256.Sum256([]byte(canon))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("SET signature invalid (Rekor did not vouch for this entry)")
	}
	return nil
}

// --- Signed checkpoint (tree head) ------------------------------------------

// Checkpoint is a verified signed tree head extracted from a Rekor checkpoint note.
type Checkpoint struct {
	Origin   string // e.g. "rekor.sigstore.dev - <treeID>"
	TreeID   string
	TreeSize int64
	RootHash []byte
}

// VerifyCheckpoint verifies the ECDSA signature of a Rekor checkpoint note and returns the
// signed (treeSize, rootHash). The note's signed text is everything up to (but excluding) the
// newline before the "— " signature line; the signature blob is base64(4-byte keyhint ||
// ASN.1 ECDSA sig) over SHA-256(text). The keyhint must equal the first 4 bytes of the log ID.
func VerifyCheckpoint(rekorPubPEM []byte, checkpoint string) (*Checkpoint, error) {
	pub, der, err := parseECDSAPubFromPEM(rekorPubPEM)
	if err != nil {
		return nil, err
	}
	const sep = "\n— "
	idx := strings.Index(checkpoint, sep)
	if idx < 0 {
		return nil, fmt.Errorf("checkpoint missing signature line")
	}
	text := checkpoint[:idx]
	sigBlock := checkpoint[idx+len(sep):]
	fields := strings.Fields(strings.TrimSpace(sigBlock))
	if len(fields) < 2 {
		return nil, fmt.Errorf("checkpoint signature line malformed")
	}
	rawSig, err := base64.StdEncoding.DecodeString(fields[len(fields)-1])
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint signature: %w", err)
	}
	if len(rawSig) <= 4 {
		return nil, fmt.Errorf("checkpoint signature too short")
	}
	hint, sig := rawSig[:4], rawSig[4:]
	keySum := sha256.Sum256(der)
	if !equalBytes(hint, keySum[:4]) {
		return nil, fmt.Errorf("checkpoint key hint %x does not match Rekor key %x", hint, keySum[:4])
	}
	digest := sha256.Sum256([]byte(text))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, fmt.Errorf("checkpoint signature invalid (unsigned/forged tree head)")
	}

	lines := strings.Split(text, "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("checkpoint body has too few lines")
	}
	size, err := parseInt(lines[1])
	if err != nil {
		return nil, fmt.Errorf("checkpoint tree size: %w", err)
	}
	root, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[2]))
	if err != nil {
		return nil, fmt.Errorf("checkpoint root hash: %w", err)
	}
	cp := &Checkpoint{Origin: lines[0], TreeSize: size, RootHash: root}
	if i := strings.LastIndex(lines[0], " - "); i >= 0 {
		cp.TreeID = strings.TrimSpace(lines[0][i+3:])
	}
	return cp, nil
}

// --- RFC 6962 Merkle proofs (inline; no external dependency) -----------------

func hashLeaf(leaf []byte) []byte {
	buf := make([]byte, 0, 1+len(leaf))
	buf = append(buf, 0x00)
	buf = append(buf, leaf...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func hashChildren(l, r []byte) []byte {
	buf := make([]byte, 0, 1+len(l)+len(r))
	buf = append(buf, 0x01)
	buf = append(buf, l...)
	buf = append(buf, r...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

// VerifyInclusion verifies an RFC 6962 inclusion proof: that leaf is at position index in a
// tree of size with the given root. leaf is the already-leaf-hashed value (H(0x00||body)).
func VerifyInclusion(index, size int64, leafHash, root []byte, proof [][]byte) error {
	if index < 0 || size < 0 || index >= size {
		return fmt.Errorf("inclusion: index %d out of range for size %d", index, size)
	}
	fn, sn := index, size-1
	r := append([]byte(nil), leafHash...)
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("inclusion: proof longer than tree path")
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = hashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("inclusion: proof shorter than tree path")
	}
	if !equalBytes(r, root) {
		return fmt.Errorf("inclusion proof does not chain to the signed root")
	}
	return nil
}

// VerifyConsistency verifies an RFC 6962 consistency proof that a tree of size1/root1 is a
// prefix of a tree of size2/root2 (append-only; no rewrite or fork). This is the property the
// accountability argument relies on: the operator cannot present divergent log views.
func VerifyConsistency(size1, size2 int64, root1, root2 []byte, proof [][]byte) error {
	if size1 < 0 || size2 < 0 || size1 > size2 {
		return fmt.Errorf("consistency: bad sizes %d -> %d", size1, size2)
	}
	if size1 == 0 {
		return nil // empty tree is a prefix of any tree
	}
	if size1 == size2 {
		if len(proof) != 0 {
			return fmt.Errorf("consistency: non-empty proof for equal sizes")
		}
		if !equalBytes(root1, root2) {
			return fmt.Errorf("consistency: equal sizes but roots differ (fork)")
		}
		return nil
	}
	// RFC 6962 §2.1.2 consistency proof verification.
	var seed []byte
	var start int
	if isPowerOfTwo(size1) {
		seed = root1
		start = 0
	} else {
		if len(proof) == 0 {
			return fmt.Errorf("consistency: empty proof")
		}
		seed = proof[0]
		start = 1
	}
	node := size1 - 1
	lastNode := size2 - 1
	for node&1 == 1 {
		node >>= 1
		lastNode >>= 1
	}
	fr := seed
	sr := seed
	for _, c := range proof[start:] {
		if lastNode == 0 {
			return fmt.Errorf("consistency: proof too long")
		}
		if node&1 == 1 || node == lastNode {
			fr = hashChildren(c, fr)
			sr = hashChildren(c, sr)
			if node&1 == 0 {
				for node&1 == 0 && node != 0 {
					node >>= 1
					lastNode >>= 1
				}
			}
		} else {
			sr = hashChildren(sr, c)
		}
		node >>= 1
		lastNode >>= 1
	}
	if lastNode != 0 {
		return fmt.Errorf("consistency: proof too short")
	}
	if !equalBytes(fr, root1) {
		return fmt.Errorf("consistency: derived old root mismatch (fork or rewrite)")
	}
	if !equalBytes(sr, root2) {
		return fmt.Errorf("consistency: derived new root mismatch (fork or rewrite)")
	}
	return nil
}

func isPowerOfTwo(n int64) bool { return n > 0 && n&(n-1) == 0 }

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Entry body binding ------------------------------------------------------

// rekordBody is the subset of the canonical rekord body we bind against.
type rekordBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// LeafHashFromBody returns H(0x00 || body) for the entry's base64 body — the Merkle leaf.
func LeafHashFromBody(bodyB64 string) ([]byte, error) {
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bodyB64))
	if err != nil {
		return nil, fmt.Errorf("decode entry body: %w", err)
	}
	return hashLeaf(body), nil
}

// BindManifest checks that the logged rekord entry binds exactly this manifest, operator
// signature, and operator public key: data hash == sha256(manifest); signature.content ==
// operator sig; signature.publicKey == operator key (compared as raw key bytes, robust to PEM
// formatting). A mismatch means the log does not actually attest this manifest -> fail closed.
func BindManifest(bodyB64 string, manifest, operatorSig, operatorPubPEM []byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bodyB64))
	if err != nil {
		return fmt.Errorf("decode entry body: %w", err)
	}
	var b rekordBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("parse entry body: %w", err)
	}
	if b.Kind != "rekord" {
		return fmt.Errorf("unexpected entry kind %q", b.Kind)
	}
	if !strings.EqualFold(b.Spec.Data.Hash.Algorithm, "sha256") {
		return fmt.Errorf("unexpected data hash algorithm %q", b.Spec.Data.Hash.Algorithm)
	}
	want := sha256.Sum256(manifest)
	if !strings.EqualFold(b.Spec.Data.Hash.Value, hex.EncodeToString(want[:])) {
		return fmt.Errorf("logged data hash != sha256(manifest) (entry is for a different manifest)")
	}
	gotSig, err := base64.StdEncoding.DecodeString(b.Spec.Signature.Content)
	if err != nil {
		return fmt.Errorf("decode logged signature: %w", err)
	}
	if !equalBytes(gotSig, operatorSig) {
		return fmt.Errorf("logged signature != operator signature")
	}
	gotPubPEM, err := base64.StdEncoding.DecodeString(b.Spec.Signature.PublicKey.Content)
	if err != nil {
		return fmt.Errorf("decode logged public key: %w", err)
	}
	gotKey, err := pkixRawKey(gotPubPEM)
	if err != nil {
		return fmt.Errorf("parse logged public key: %w", err)
	}
	wantKey, err := pkixRawKey(operatorPubPEM)
	if err != nil {
		return fmt.Errorf("parse operator public key: %w", err)
	}
	if !equalBytes(gotKey, wantKey) {
		return fmt.Errorf("logged public key != operator public key")
	}
	return nil
}

// pkixRawKey parses a PKIX PEM public key and returns its DER (SPKI) bytes for comparison.
func pkixRawKey(pemBytes []byte) ([]byte, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
		return nil, err
	}
	return blk.Bytes, nil
}
