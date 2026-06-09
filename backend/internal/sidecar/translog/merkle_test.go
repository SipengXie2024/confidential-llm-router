//go:build unit

package translog

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// Independent, naive RFC 6962 reference implementation (full recompute / recursion). It is
// structurally different from the iterative, bit-twiddling Verify{Inclusion,Consistency} under
// test, so a shared bug is unlikely — this cross-checks the verifiers deterministically and
// offline. The live test (livetranslog) additionally proves them against real Rekor proofs.

func refLeaf(d []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(d)
	return h.Sum(nil)
}

func refNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// split returns the largest power of two strictly less than n (n > 1).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func refRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return refLeaf(leaves[0])
	default:
		k := split(len(leaves))
		return refNode(refRoot(leaves[:k]), refRoot(leaves[k:]))
	}
}

func refInclusion(leaves [][]byte, m int) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(refInclusion(leaves[:k], m), refRoot(leaves[k:]))
	}
	return append(refInclusion(leaves[k:], m-k), refRoot(leaves[:k]))
}

func refConsistency(leaves [][]byte, m int) [][]byte {
	return subproof(m, leaves, true)
}

func subproof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{refRoot(leaves)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, leaves[:k], b), refRoot(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), refRoot(leaves[:k]))
}

func makeLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = []byte(fmt.Sprintf("aegis-leaf-%d", i))
	}
	return out
}

func TestVerifyInclusionExhaustive(t *testing.T) {
	for n := 1; n <= 32; n++ {
		leaves := makeLeaves(n)
		root := refRoot(leaves)
		for m := 0; m < n; m++ {
			proof := refInclusion(leaves, m)
			leafHash := refLeaf(leaves[m])
			if err := VerifyInclusion(int64(m), int64(n), leafHash, root, proof); err != nil {
				t.Fatalf("inclusion n=%d m=%d: %v", n, m, err)
			}
		}
	}
}

func TestVerifyInclusionRejectsTampering(t *testing.T) {
	leaves := makeLeaves(11)
	root := refRoot(leaves)
	proof := refInclusion(leaves, 5)
	leaf := refLeaf(leaves[5])

	// Wrong leaf -> must fail.
	if err := VerifyInclusion(5, 11, refLeaf([]byte("forged")), root, proof); err == nil {
		t.Fatal("inclusion accepted a forged leaf")
	}
	// Tampered proof hash -> must fail.
	bad := make([][]byte, len(proof))
	copy(bad, proof)
	bad[0] = bytes.Repeat([]byte{0xaa}, 32)
	if err := VerifyInclusion(5, 11, leaf, root, bad); err == nil {
		t.Fatal("inclusion accepted a tampered proof")
	}
	// Wrong root -> must fail.
	if err := VerifyInclusion(5, 11, leaf, bytes.Repeat([]byte{0x00}, 32), proof); err == nil {
		t.Fatal("inclusion accepted a wrong root")
	}
	// Out-of-range index -> must fail.
	if err := VerifyInclusion(11, 11, leaf, root, proof); err == nil {
		t.Fatal("inclusion accepted out-of-range index")
	}
}

func TestVerifyConsistencyExhaustive(t *testing.T) {
	for n := 1; n <= 32; n++ {
		leaves := makeLeaves(n)
		rootN := refRoot(leaves)
		for m := 1; m <= n; m++ {
			rootM := refRoot(leaves[:m])
			proof := refConsistency(leaves, m)
			if err := VerifyConsistency(int64(m), int64(n), rootM, rootN, proof); err != nil {
				t.Fatalf("consistency m=%d n=%d: %v", m, n, err)
			}
		}
	}
}

func TestVerifyConsistencyDetectsFork(t *testing.T) {
	leaves := makeLeaves(20)
	rootN := refRoot(leaves)
	rootM := refRoot(leaves[:13])
	proof := refConsistency(leaves, 13)

	// Tampered old root (operator claims a different earlier history) -> fork detected.
	forkedOld := bytes.Repeat([]byte{0x11}, 32)
	if err := VerifyConsistency(13, 20, forkedOld, rootN, proof); err == nil {
		t.Fatal("consistency accepted a forked old root")
	}
	// Tampered new root -> fail.
	if err := VerifyConsistency(13, 20, rootM, bytes.Repeat([]byte{0x22}, 32), proof); err == nil {
		t.Fatal("consistency accepted a forged new root")
	}
	// Same size, different root = classic split view -> fail.
	if err := VerifyConsistency(20, 20, rootN, bytes.Repeat([]byte{0x33}, 32), nil); err == nil {
		t.Fatal("consistency accepted a same-size split view")
	}
	// Same size, same root, but a non-empty proof -> malformed, fail.
	if err := VerifyConsistency(20, 20, rootN, rootN, [][]byte{rootN}); err == nil {
		t.Fatal("consistency accepted a non-empty proof for equal sizes")
	}
	// Rolled-back size (size1 > size2) -> rejected by caller-level check; verifier rejects too.
	if err := VerifyConsistency(20, 13, rootN, rootM, nil); err == nil {
		t.Fatal("consistency accepted size1 > size2")
	}
}
