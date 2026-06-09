package translog

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TreeHead is a persisted, previously-verified signed tree head for one log shard.
type TreeHead struct {
	TreeSize    int64  `json:"tree_size"`
	RootHashHex string `json:"root_hash_hex"`
}

// treeHeadStore maps shard treeID -> last verified tree head. It is the client's append-only
// memory: a later pin proves consistency from the stored head to the current one, so a forked
// or rewound log is detected. Stored on disk so the guarantee survives sidecar restarts.
type treeHeadStore struct {
	Heads map[string]TreeHead `json:"heads"`
}

func loadTreeHeadStore(path string) (*treeHeadStore, error) {
	s := &treeHeadStore{Heads: map[string]TreeHead{}}
	if strings.TrimSpace(path) == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read tree-head store: %w", err)
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parse tree-head store: %w", err)
	}
	if s.Heads == nil {
		s.Heads = map[string]TreeHead{}
	}
	return s, nil
}

func (s *treeHeadStore) save(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create tree-head store dir: %w", err)
		}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write tree-head store: %w", err)
	}
	return os.Rename(tmp, path)
}

func (s *treeHeadStore) get(treeID string) (TreeHead, bool) {
	th, ok := s.Heads[treeID]
	return th, ok
}

func (s *treeHeadStore) put(treeID string, size int64, root []byte) {
	s.Heads[treeID] = TreeHead{TreeSize: size, RootHashHex: hex.EncodeToString(root)}
}
