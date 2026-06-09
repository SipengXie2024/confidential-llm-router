package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/sidecar/translog"
)

// manifestMaterial carries the bytes a transparency-log audit needs to bind the Rekor entry to
// THIS signed manifest. It is nil when the measurement came from raw -pcr* flags (which have no
// published manifest and therefore cannot be transparency-audited).
type manifestMaterial struct {
	bytes          []byte
	sig            []byte
	operatorPubPEM []byte
}

// translogFlags holds the transparency-log configuration (flags, with env fallbacks wired in main).
type translogFlags struct {
	bundlePath    string
	rekorURL      string
	rekorPubFile  string
	storePath     string
	entryOverride string
	require       bool
}

func (f translogFlags) configured() bool {
	return strings.TrimSpace(f.bundlePath) != "" || strings.TrimSpace(f.entryOverride) != ""
}

// runTranslogAudit enforces the append-only transparency-log check at pin time. It returns a
// non-nil error whenever the sidecar must fail closed:
//   - -require-translog is set but no entry/bundle is configured, or the audit fails;
//   - a bundle/entry IS configured (even without -require) but the audit fails.
//
// When nothing is configured and -require is off, it logs a legacy-mode warning and returns nil
// (gradual rollout). The audit itself (inclusion + SET + signed checkpoint + consistency) lives
// in internal/sidecar/translog and talks to Rekor only here, once, never on the data path.
func runTranslogAudit(ctx context.Context, f translogFlags, mat *manifestMaterial) error {
	if !f.require && !f.configured() {
		log.Printf("client-sidecar: WARNING transparency-log audit not configured (legacy offline-signature trust); set -require-translog to enforce public accountability")
		return nil
	}
	if mat == nil {
		return fmt.Errorf("transparency-log audit requires a signed -manifest (raw -pcr* has no published manifest to audit)")
	}

	var b translog.Bundle
	if p := strings.TrimSpace(f.bundlePath); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read transparency bundle: %w", err)
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("parse transparency bundle: %w", err)
		}
	}

	entryUUID := b.EntryUUID
	if o := strings.TrimSpace(f.entryOverride); o != "" {
		entryUUID = o
	}
	if entryUUID == "" {
		return fmt.Errorf("no Rekor entry to audit (need -translog-bundle or -translog-entry)")
	}

	rekorURL := firstNonEmpty(f.rekorURL, b.RekorURL)
	var rekorPubPEM []byte
	if p := strings.TrimSpace(f.rekorPubFile); p != "" {
		pem, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read rekor public key: %w", err)
		}
		rekorPubPEM = pem
	} else if strings.TrimSpace(b.RekorPublicKeyPEM) != "" {
		rekorPubPEM = []byte(b.RekorPublicKeyPEM)
	}

	cfg := translog.AuditConfig{
		RekorURL:    rekorURL,
		RekorPubPEM: rekorPubPEM,
		EntryUUID:   entryUUID,
		StorePath:   f.storePath,
	}
	res, err := translog.Audit(ctx, cfg, mat.bytes, mat.sig, mat.operatorPubPEM)
	if err != nil {
		return fmt.Errorf("transparency-log audit failed (refusing to pin): %w", err)
	}
	log.Printf("client-sidecar: transparency-log verified — rekor entry %s (globalLogIndex=%d, shard=%s, treeSize=%d, consistencyChecked=%v, firstUse=%v)",
		res.EntryUUID, res.GlobalLogIndex, res.ShardTreeID, res.TreeSize, res.ConsistencyChecked, res.FirstUse)
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// env returns the environment variable value or a default (used as flag defaults so deploy/.env
// can configure the transparency-log audit without editing the run scripts' flags).
func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(env(key, "")))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
