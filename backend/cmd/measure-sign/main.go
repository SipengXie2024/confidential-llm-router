// Command measure-sign generates an Ed25519 keypair and signs an enclave measurement manifest
// (deploy/enclave/measurements.json). The detached, base64 signature is what the client-sidecar
// verifies (with the published public key) before pinning the manifest's PCR0/1/2 — the ARPA
// "trusted key -> manifest -> PCR" anchor. The private key is operator-held and must NOT be
// committed; publish only the public key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	var genkey bool
	var priv, pub, in, sig string
	flag.BoolVar(&genkey, "genkey", false, "generate an Ed25519 keypair (writes -priv and -pub as hex)")
	flag.StringVar(&priv, "priv", "", "private key file (hex)")
	flag.StringVar(&pub, "pub", "", "public key file (hex)")
	flag.StringVar(&in, "in", "", "manifest file to sign")
	flag.StringVar(&sig, "sig", "", "output detached signature file (base64)")
	flag.Parse()

	if genkey {
		if priv == "" || pub == "" {
			fatal("-genkey requires -priv and -pub")
		}
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		must(os.WriteFile(priv, []byte(hex.EncodeToString(sk)), 0o600))
		must(os.WriteFile(pub, []byte(hex.EncodeToString(pk)), 0o644))
		fmt.Printf("wrote private key %s (keep secret) and public key %s\n", priv, pub)
		fmt.Printf("public key (hex, pass to client-sidecar -manifest-pubkey): %s\n", hex.EncodeToString(pk))
		return
	}

	if priv == "" || in == "" || sig == "" {
		fatal("sign mode requires -priv, -in and -sig")
	}
	skHex, err := os.ReadFile(priv)
	must(err)
	skBytes, err := hex.DecodeString(strings.TrimSpace(string(skHex)))
	must(err)
	if len(skBytes) != ed25519.PrivateKeySize {
		fatal(fmt.Sprintf("private key must be %d-byte ed25519 hex", ed25519.PrivateKeySize))
	}
	manifest, err := os.ReadFile(in)
	must(err)
	signature := ed25519.Sign(ed25519.PrivateKey(skBytes), manifest)
	must(os.WriteFile(sig, []byte(base64.StdEncoding.EncodeToString(signature)), 0o644))
	fmt.Printf("signed %s -> %s\n", in, sig)
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
