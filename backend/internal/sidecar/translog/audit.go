package translog

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

// Bundle is the operator's publish artifact, written alongside the signed manifest. It records
// the Rekor entry and the Rekor key pinned at publish time. The sidecar re-fetches the entry at
// audit time (to get a fresh inclusion proof + signed checkpoint against the current tree), so
// the bundle's main load-bearing fields are RekorURL, EntryUUID, and RekorPublicKeyPEM.
type Bundle struct {
	SchemaVersion     int    `json:"schema_version"`
	RekorURL          string `json:"rekor_url"`
	EntryUUID         string `json:"entry_uuid"`
	LogID             string `json:"log_id"`
	LogIndex          int64  `json:"log_index"`
	IntegratedTime    int64  `json:"integrated_time"`
	RekorPublicKeyPEM string `json:"rekor_public_key_pem"`
	Entry             *Entry `json:"entry,omitempty"`
}

// AuditConfig parameterizes the one-shot, pin-time transparency-log check.
type AuditConfig struct {
	RekorURL    string // log endpoint (default public instance)
	RekorPubPEM []byte // optional pinned Rekor key; if nil, fetched and bound by logID
	EntryUUID   string // the manifest's Rekor entry
	StorePath   string // tree-head persistence (consistency across runs)
}

// AuditResult summarizes a successful audit for logging/evidence.
type AuditResult struct {
	EntryUUID          string
	GlobalLogIndex     int64
	ShardTreeID        string
	TreeSize           int64
	RootHashHex        string
	ConsistencyChecked bool
	FirstUse           bool
}

// Audit performs the full pin-time verification and returns nil error ONLY if the manifest is
// provably included in the public append-only log under a signed tree head, the per-entry SET is
// valid, the entry binds exactly this manifest+operator key, and the log is consistent with
// previously observed state. Any failure returns an error and the caller MUST fail closed.
func Audit(ctx context.Context, cfg AuditConfig, manifest, operatorSig, operatorPubPEM []byte) (*AuditResult, error) {
	if strings.TrimSpace(cfg.EntryUUID) == "" {
		return nil, fmt.Errorf("transparency-log audit requires an entry UUID (no log entry to verify)")
	}
	c := NewClient(cfg.RekorURL)

	entry, err := c.GetEntry(ctx, cfg.EntryUUID)
	if err != nil {
		return nil, fmt.Errorf("fetch rekor entry: %w", err)
	}
	ip := entry.Verification.InclusionProof

	// Resolve the Rekor key for the shard this entry lives in (logID = sha256(SPKI)).
	rekorPub, err := c.resolveShardKey(ctx, cfg.RekorPubPEM, entry)
	if err != nil {
		return nil, err
	}

	// 1) SET: Rekor vouched for exactly this entry (inclusion soundness).
	if err := VerifySET(rekorPub, entry); err != nil {
		return nil, err
	}

	// 2) Signed checkpoint: authenticate the current tree head; bind it to the inclusion proof.
	cp, err := VerifyCheckpoint(rekorPub, ip.Checkpoint)
	if err != nil {
		return nil, err
	}
	ipRoot, err := hex.DecodeString(strings.TrimSpace(ip.RootHash))
	if err != nil {
		return nil, fmt.Errorf("decode inclusion root: %w", err)
	}
	if cp.TreeSize != ip.TreeSize || !equalBytes(cp.RootHash, ipRoot) {
		return nil, fmt.Errorf("inclusion proof not bound to signed checkpoint (size/root mismatch)")
	}

	// 3) Inclusion proof: the entry is in the tree the signed checkpoint commits to.
	leaf, err := LeafHashFromBody(entry.Body)
	if err != nil {
		return nil, err
	}
	proof, err := decodeHexAll(ip.Hashes)
	if err != nil {
		return nil, fmt.Errorf("decode inclusion hashes: %w", err)
	}
	if err := VerifyInclusion(ip.LogIndex, ip.TreeSize, leaf, cp.RootHash, proof); err != nil {
		return nil, err
	}

	// 4) Bind: the logged entry is for THIS manifest + operator signature + operator key.
	if err := BindManifest(entry.Body, manifest, operatorSig, operatorPubPEM); err != nil {
		return nil, err
	}

	// 5) Consistency: append-only from the last verified tree head (no rewrite/fork).
	res := &AuditResult{
		EntryUUID:      cfg.EntryUUID,
		GlobalLogIndex: entry.LogIndex,
		ShardTreeID:    cp.TreeID,
		TreeSize:       cp.TreeSize,
		RootHashHex:    hex.EncodeToString(cp.RootHash),
	}
	store, err := loadTreeHeadStore(cfg.StorePath)
	if err != nil {
		return nil, err
	}
	if prev, ok := store.get(cp.TreeID); ok {
		prevRoot, err := hex.DecodeString(prev.RootHashHex)
		if err != nil {
			return nil, fmt.Errorf("stored root hash invalid: %w", err)
		}
		switch {
		case prev.TreeSize > cp.TreeSize:
			return nil, fmt.Errorf("log rolled back: stored size %d > current %d (fork/rewrite)", prev.TreeSize, cp.TreeSize)
		case prev.TreeSize == cp.TreeSize:
			if !equalBytes(prevRoot, cp.RootHash) {
				return nil, fmt.Errorf("split view: same tree size %d but different root (fork)", cp.TreeSize)
			}
		default:
			cproof, err := c.ConsistencyProof(ctx, cp.TreeID, prev.TreeSize, cp.TreeSize)
			if err != nil {
				return nil, fmt.Errorf("fetch consistency proof: %w", err)
			}
			if err := VerifyConsistency(prev.TreeSize, cp.TreeSize, prevRoot, cp.RootHash, cproof); err != nil {
				return nil, err
			}
			res.ConsistencyChecked = true
		}
	} else {
		res.FirstUse = true
	}
	store.put(cp.TreeID, cp.TreeSize, cp.RootHash)
	if err := store.save(cfg.StorePath); err != nil {
		return nil, err
	}
	return res, nil
}

// resolveShardKey returns the Rekor public key (PEM) whose logID matches the entry's shard. If a
// key was pinned via config it is used and must match; otherwise it is fetched (active shard,
// then by treeID) and bound by logID == sha256(SPKI).
func (c *Client) resolveShardKey(ctx context.Context, pinned []byte, entry *Entry) ([]byte, error) {
	if len(pinned) > 0 {
		id, err := LogIDFromPEM(pinned)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(id, entry.LogID) {
			return nil, fmt.Errorf("pinned Rekor key logID %s != entry logID %s", id, entry.LogID)
		}
		return pinned, nil
	}
	// Try the active-shard key first, then the entry's specific shard.
	candidates := []string{""}
	if treeID := peekCheckpointTreeID(entry.Verification.InclusionProof.Checkpoint); treeID != "" {
		candidates = append(candidates, treeID)
	}
	var lastErr error
	for _, treeID := range candidates {
		pem, err := c.PublicKeyPEM(ctx, treeID)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := LogIDFromPEM(pem)
		if err != nil {
			lastErr = err
			continue
		}
		if strings.EqualFold(id, entry.LogID) {
			return pem, nil
		}
		lastErr = fmt.Errorf("fetched Rekor key logID %s != entry logID %s", id, entry.LogID)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("could not resolve a Rekor key matching entry shard")
	}
	return nil, lastErr
}

// peekCheckpointTreeID extracts the treeID from a checkpoint origin line WITHOUT verifying the
// signature (used only to pick which shard key to fetch; the key is then bound by logID).
func peekCheckpointTreeID(checkpoint string) string {
	line := checkpoint
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if i := strings.LastIndex(line, " - "); i >= 0 {
		return strings.TrimSpace(line[i+3:])
	}
	return ""
}
