// Package translog adds a real append-only transparency-log anchor (Sigstore Rekor)
// to the ARPA measurement flow. The operator publishes the signed measurement
// manifest as a Rekor entry; the client-sidecar, at pin time (one-shot, NOT on the
// per-request data path), verifies that the entry is included in the public log
// under a signed tree head, that the per-entry Signed Entry Timestamp (SET) is valid,
// and that the log is consistent with previously observed state (append-only). Any
// failure makes the sidecar fail closed and refuse to pin / release plaintext.
//
// This package lives under internal/sidecar and is imported ONLY by the client-sidecar
// and the operator's measure-sign tool. It MUST NOT be pulled into cmd/enclave-core
// (the enclave data plane). It depends only on the Go standard library — the Merkle
// proof math (RFC 6962) and the SET/checkpoint ECDSA verification are implemented
// inline, so no Sigstore/Rekor client library enters the module's TCB.
package translog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultRekorURL is the public Sigstore Rekor instance. Override via config to point
// at a private Rekor (the verification logic is identical).
const DefaultRekorURL = "https://rekor.sigstore.dev"

// Entry mirrors the fields of a Rekor log entry that we verify. Rekor returns entries
// keyed by UUID; callers unwrap the single value.
type Entry struct {
	Body           string       `json:"body"`           // base64 of the canonical entry body
	IntegratedTime int64        `json:"integratedTime"` // unix seconds Rekor integrated the entry
	LogID          string       `json:"logID"`          // hex sha256 of the shard public key
	LogIndex       int64        `json:"logIndex"`       // global (cross-shard) index
	Verification   Verification `json:"verification"`
}

// Verification holds the inclusion proof and the Signed Entry Timestamp.
type Verification struct {
	InclusionProof       InclusionProof `json:"inclusionProof"`
	SignedEntryTimestamp string         `json:"signedEntryTimestamp"` // base64 ECDSA sig over JCS(entry)
}

// InclusionProof is an RFC 6962 inclusion proof plus the signed checkpoint (tree head)
// the proof chains to. LogIndex/TreeSize here are the per-shard leaf index and tree size
// (distinct from Entry.LogIndex, which is global).
type InclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

// Client is a minimal Rekor REST client (stdlib http only).
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client with a sane timeout. baseURL defaults to the public instance.
func NewClient(baseURL string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultRekorURL
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) get(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, err
}

// SubmitRekord submits a proposed ed25519/rekord entry and returns the created entry
// (with its UUID). On a 409 (entry already exists) it resolves and fetches the existing
// entry so publishing is idempotent.
func (c *Client) SubmitRekord(ctx context.Context, proposed map[string]any) (string, *Entry, error) {
	body, err := json.Marshal(proposed)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusConflict {
		// Entry already in the log: the Location header carries its UUID path.
		if loc := resp.Header.Get("Location"); loc != "" {
			uuid := loc[strings.LastIndex(loc, "/")+1:]
			e, err := c.GetEntry(ctx, uuid)
			return uuid, e, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("rekor submit: HTTP %d: %s", resp.StatusCode, truncate(raw, 300))
	}
	uuid, e, err := decodeEntryMap(raw)
	return uuid, e, err
}

// GetEntry fetches a log entry by UUID. Rekor returns a fresh inclusion proof and signed
// checkpoint against the CURRENT tree on every call.
func (c *Client) GetEntry(ctx context.Context, uuid string) (*Entry, error) {
	raw, code, err := c.get(ctx, "/api/v1/log/entries/"+url.PathEscape(uuid))
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("rekor get entry %s: HTTP %d: %s", uuid, code, truncate(raw, 200))
	}
	_, e, err := decodeEntryMap(raw)
	return e, err
}

// ConsistencyProof fetches an RFC 6962 consistency proof between two tree sizes on a shard.
func (c *Client) ConsistencyProof(ctx context.Context, treeID string, first, last int64) ([][]byte, error) {
	q := fmt.Sprintf("/api/v1/log/proof?firstSize=%d&lastSize=%d", first, last)
	if treeID != "" {
		q += "&treeID=" + url.QueryEscape(treeID)
	}
	raw, code, err := c.get(ctx, q)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("rekor consistency proof %d->%d: HTTP %d: %s", first, last, code, truncate(raw, 200))
	}
	var p struct {
		Hashes []string `json:"hashes"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("decode consistency proof: %w", err)
	}
	return decodeHexAll(p.Hashes)
}

// PublicKeyPEM fetches the shard public key (PEM). Used to pin-on-first-use when the
// caller did not supply a pinned Rekor key.
func (c *Client) PublicKeyPEM(ctx context.Context, treeID string) ([]byte, error) {
	path := "/api/v1/log/publicKey"
	if treeID != "" {
		path += "?treeID=" + url.QueryEscape(treeID)
	}
	raw, code, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("rekor publicKey: HTTP %d", code)
	}
	return raw, nil
}

func decodeEntryMap(raw []byte) (string, *Entry, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", nil, fmt.Errorf("decode entry map: %w", err)
	}
	for uuid, v := range m {
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return "", nil, fmt.Errorf("decode entry: %w", err)
		}
		return uuid, &e, nil
	}
	return "", nil, fmt.Errorf("rekor returned no entry")
}

// BuildRekordEd25519 builds a proposed ed25519/rekord entry binding the manifest content
// (uploaded inline; the manifest is public by design) to the operator's ed25519 signature
// and public key. Rekor verifies the signature at submission. We use rekord (not
// hashedrekord) because hashedrekord cannot verify PureEdDSA signatures from a digest.
func BuildRekordEd25519(manifest, sig []byte, operatorPub ed25519.PublicKey) (map[string]any, error) {
	pubPEM, err := Ed25519PubToPKIXPEM(operatorPub)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "rekord",
		"spec": map[string]any{
			"data": map[string]any{"content": base64.StdEncoding.EncodeToString(manifest)},
			"signature": map[string]any{
				"format":    "x509",
				"content":   base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	}, nil
}

// Ed25519PubToPKIXPEM encodes an ed25519 public key as a PKIX/SPKI PEM block, the form
// Rekor's x509 verifier accepts. Deterministic, so operator and client derive the same bytes.
func Ed25519PubToPKIXPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 PKIX: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func decodeHexAll(hexes []string) ([][]byte, error) {
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

// parseInt is a small helper used by checkpoint parsing.
func parseInt(s string) (int64, error) { return strconv.ParseInt(strings.TrimSpace(s), 10, 64) }
