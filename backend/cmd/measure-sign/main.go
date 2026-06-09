// Command measure-sign is the operator-side ARPA tool. It (1) generates an Ed25519 keypair,
// (2) signs an enclave measurement manifest (deploy/enclave/measurements.json), and (3) publishes
// the signed manifest to a Sigstore Rekor transparency log, writing a bundle (entry UUID, log
// index, inclusion proof, SET, pinned Rekor key) alongside the manifest. The client-sidecar later
// verifies that bundle against the live log before pinning the measurement. The detached Ed25519
// signature is what the sidecar checks (with the published public key); the Rekor entry is what
// makes the published (manifest, measurement) PUBLIC and fork-evident. The private key is
// operator-held and must NOT be committed; publish only the public key.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/sidecar/translog"
)

func main() {
	var genkey, publish bool
	var priv, pub, in, sig, rekorURL, bundle string
	flag.BoolVar(&genkey, "genkey", false, "generate an Ed25519 keypair (writes -priv and -pub as hex)")
	flag.BoolVar(&publish, "publish", false, "publish a signed manifest to a Rekor transparency log and write a bundle")
	flag.StringVar(&priv, "priv", "", "private key file (hex)")
	flag.StringVar(&pub, "pub", "", "public key file (hex)")
	flag.StringVar(&in, "in", "", "manifest file to sign / publish")
	flag.StringVar(&sig, "sig", "", "detached signature file (base64): output for sign, input for publish")
	flag.StringVar(&rekorURL, "rekor-url", translog.DefaultRekorURL, "Rekor transparency-log endpoint")
	flag.StringVar(&bundle, "bundle", "", "publish: output bundle file (default <manifest>.rekor.json)")
	flag.Parse()

	switch {
	case genkey:
		doGenkey(priv, pub)
	case publish:
		doPublish(in, sig, pub, rekorURL, bundle)
	default:
		doSign(priv, in, sig)
	}
}

func doGenkey(priv, pub string) {
	if priv == "" || pub == "" {
		fatal("-genkey requires -priv and -pub")
	}
	pk, sk, err := ed25519.GenerateKey(nil)
	must(err)
	must(os.WriteFile(priv, []byte(hex.EncodeToString(sk)), 0o600))
	must(os.WriteFile(pub, []byte(hex.EncodeToString(pk)), 0o644))
	fmt.Printf("wrote private key %s (keep secret) and public key %s\n", priv, pub)
	fmt.Printf("public key (hex, pass to client-sidecar -manifest-pubkey): %s\n", hex.EncodeToString(pk))
}

func doSign(priv, in, sig string) {
	if priv == "" || in == "" || sig == "" {
		fatal("sign mode requires -priv, -in and -sig")
	}
	skBytes := readHex(priv)
	if len(skBytes) != ed25519.PrivateKeySize {
		fatal(fmt.Sprintf("private key must be %d-byte ed25519 hex", ed25519.PrivateKeySize))
	}
	manifest, err := os.ReadFile(in)
	must(err)
	signature := ed25519.Sign(ed25519.PrivateKey(skBytes), manifest)
	//nolint:gosec // G703: -sig is an operator-controlled output path for a local CLI signing tool
	must(os.WriteFile(sig, []byte(base64.StdEncoding.EncodeToString(signature)), 0o644))
	fmt.Printf("signed %s -> %s\n", in, sig)
}

func doPublish(in, sig, pub, rekorURL, bundle string) {
	if in == "" || sig == "" || pub == "" {
		fatal("publish mode requires -in (manifest), -sig (signature) and -pub (operator public key)")
	}
	if bundle == "" {
		bundle = in + ".rekor.json"
	}
	manifest, err := os.ReadFile(in)
	must(err)
	sigB64, err := os.ReadFile(sig)
	must(err)
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	must(err)
	pubBytes := readHex(pub)
	if len(pubBytes) != ed25519.PublicKeySize {
		fatal(fmt.Sprintf("public key must be %d-byte ed25519 hex", ed25519.PublicKeySize))
	}
	operatorPub := ed25519.PublicKey(pubBytes)

	// Sanity: refuse to publish a signature that does not verify against the operator key.
	if !ed25519.Verify(operatorPub, manifest, sigBytes) {
		fatal("operator signature does not verify over the manifest (refusing to publish)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := translog.NewClient(rekorURL)
	proposed, err := translog.BuildRekordEd25519(manifest, sigBytes, operatorPub)
	must(err)
	uuid, entry, err := c.SubmitRekord(ctx, proposed)
	must(err)

	// Pin the Rekor shard key (bound by logID = sha256(SPKI) == entry.LogID).
	rekorPubPEM := resolveRekorKey(ctx, c, entry)

	b := translog.Bundle{
		SchemaVersion:     1,
		RekorURL:          strings.TrimRight(rekorURL, "/"),
		EntryUUID:         uuid,
		LogID:             entry.LogID,
		LogIndex:          entry.LogIndex,
		IntegratedTime:    entry.IntegratedTime,
		RekorPublicKeyPEM: string(rekorPubPEM),
		Entry:             entry,
	}
	out, err := json.MarshalIndent(b, "", "  ")
	must(err)
	must(os.WriteFile(bundle, out, 0o644))
	fmt.Printf("published to Rekor: uuid=%s logIndex=%d\n", uuid, entry.LogIndex)
	fmt.Printf("wrote transparency bundle: %s\n", bundle)
}

func resolveRekorKey(ctx context.Context, c *translog.Client, entry *translog.Entry) []byte {
	pem, err := c.PublicKeyPEM(ctx, "")
	must(err)
	id, err := translog.LogIDFromPEM(pem)
	must(err)
	if !strings.EqualFold(id, entry.LogID) {
		fatal(fmt.Sprintf("active Rekor key logID %s != entry logID %s (shard rotation; rerun)", id, entry.LogID))
	}
	return pem
}

func readHex(path string) []byte {
	raw, err := os.ReadFile(path)
	must(err)
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	must(err)
	return b
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "measure-sign: "+msg)
	os.Exit(1)
}
