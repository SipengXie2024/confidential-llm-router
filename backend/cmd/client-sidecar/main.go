// Command client-sidecar is the local proxy a coding agent points its base URL at. On
// startup it verifies the enclave's Nitro attestation (AWS signature + pinned PCR0/1/2 +
// TLS-cert binding) and FAILS CLOSED if anything is off; only then does it proxy the
// agent's HTTPS to the attested enclave, pinning the verified leaf certificate.
//
// Trusted-time limitation ([NEEDS-EVIDENCE #3]): the enclave has no trusted wall clock, so
// attestation freshness is established once at startup via a fresh random nonce, and the
// ephemeral leaf cert is pinned for the session. If the enclave reboots (new cert), pinned
// connections fail and the operator restarts the sidecar. There is no continuous re-attestation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/sidecar"
	"github.com/Wei-Shaw/sub2api/internal/sidecar/translog"
)

const nonceLen = 20

// Sidecar verifies the enclave attestation, then proxies to it. verify is injected so the
// proxy wiring is testable without a live enclave; in production it is attestedTransport.
type Sidecar struct {
	enclaveURL string
	verify     func(ctx context.Context) (http.RoundTripper, error)
}

// handler runs verification (fail closed on error) and returns a reverse proxy to the
// enclave over the verified, cert-pinned transport.
func (s *Sidecar) handler(ctx context.Context) (http.Handler, error) {
	target, err := url.Parse(s.enclaveURL)
	if err != nil {
		return nil, fmt.Errorf("bad enclave url %q: %w", s.enclaveURL, err)
	}
	// Reject a path-bearing origin: fetchLeafCert/fetchAttestation and the proxy all assume
	// an origin (scheme://host[:port]); a path would produce /enclave/enclave and misroute.
	if target.Path != "" && target.Path != "/" {
		return nil, fmt.Errorf("enclave-url must be an origin (scheme://host[:port]) with no path, got %q", s.enclaveURL)
	}
	rt, err := s.verify(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation failed, refusing to proxy: %w", err)
	}
	// Rewrite (not the deprecated Director) routes every request to the attested enclave origin
	// and forces req.Host to the enclave's host — the enclave must see its own host, not the
	// sidecar-facing host the agent sent. target has no path (guarded above), so SetURL just
	// carries the agent's path through unchanged.
	proxy := &httputil.ReverseProxy{
		Transport: rt,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
		},
	}
	return proxy, nil
}

// attestedTransport performs the one-shot attestation handshake against the enclave and, on
// success, returns a transport that pins the attested leaf certificate for all later
// connections. Ported from the verified spike (/home/ubuntu/nitriding-spike/verify-attestation).
func attestedTransport(ctx context.Context, enclaveURL, serverName string, expectedPCR map[int]string) (http.RoundTripper, error) {
	probe := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}}, //nolint:gosec // verified via attestation, not PKI
		Timeout:   15 * time.Second,
	}

	certDER, err := fetchLeafCert(ctx, probe, enclaveURL)
	if err != nil {
		return nil, fmt.Errorf("fetch enclave certificate: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	doc, err := fetchAttestation(ctx, probe, enclaveURL, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation: %w", err)
	}
	if err := sidecar.Verify(doc, expectedPCR, nonce, certDER); err != nil {
		return nil, err // fail closed
	}

	return pinnedEnclaveTransport(serverName, certDER), nil
}

func pinnedEnclaveTransport(serverName string, certDER []byte) http.RoundTripper {
	want := sha256.Sum256(certDER)
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed enclave cert; trust is pinned below
			ServerName:         serverName,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("enclave presented no certificate")
				}
				got := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if got != want {
					return fmt.Errorf("enclave certificate changed since attestation (pin mismatch)")
				}
				return nil
			},
		},
	}
}

func fetchLeafCert(ctx context.Context, c *http.Client, enclaveURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(enclaveURL, "/")+"/enclave", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return resp.TLS.PeerCertificates[0].Raw, nil
}

func fetchAttestation(ctx context.Context, c *http.Client, enclaveURL string, nonce []byte) ([]byte, error) {
	u := strings.TrimRight(enclaveURL, "/") + "/enclave/attestation?nonce=" + hex.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
}

// resolveExpectedPCR sources the pinned measurement either from a signed manifest (preferred:
// verify the Ed25519 signature against the trusted public key, then extract PCR0/1/2) or from the
// -pcr* flags. Fails closed if neither is usable. On the manifest path it also returns the
// manifest material (bytes + signature + operator public key as PKIX PEM) so a transparency-log
// audit can bind the Rekor entry to exactly this manifest; the -pcr* path returns nil material.
func resolveExpectedPCR(manifestPath, manifestSig, manifestPub, pcr0, pcr1, pcr2 string) (map[int]string, *manifestMaterial, error) {
	if manifestPath != "" {
		if manifestPub == "" {
			return nil, nil, fmt.Errorf("-manifest requires -manifest-pubkey")
		}
		if manifestSig == "" {
			manifestSig = manifestPath + ".sig"
		}
		mBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read manifest: %w", err)
		}
		sigB64, err := os.ReadFile(manifestSig)
		if err != nil {
			return nil, nil, fmt.Errorf("read manifest signature: %w", err)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
		if err != nil {
			return nil, nil, fmt.Errorf("decode manifest signature: %w", err)
		}
		m, err := sidecar.LoadVerifiedManifest(mBytes, sig, manifestPub)
		if err != nil {
			return nil, nil, err
		}
		pubBytes, err := hex.DecodeString(strings.TrimSpace(manifestPub))
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("manifest public key must be %d-byte ed25519 hex", ed25519.PublicKeySize)
		}
		pubPEM, err := translog.Ed25519PubToPKIXPEM(ed25519.PublicKey(pubBytes))
		if err != nil {
			return nil, nil, err
		}
		log.Printf("client-sidecar: pinned measurement from signed manifest (tag=%s commit=%s)", m.Tag, m.SourceCommit)
		mat := &manifestMaterial{bytes: mBytes, sig: sig, operatorPubPEM: pubPEM}
		return m.ExpectedPCR(), mat, nil
	}
	if pcr0 == "" {
		return nil, nil, fmt.Errorf("either -manifest (signed) or -pcr0 must be provided")
	}
	e := map[int]string{0: pcr0}
	if pcr1 != "" {
		e[1] = pcr1
	}
	if pcr2 != "" {
		e[2] = pcr2
	}
	return e, nil, nil
}

func main() {
	var enclaveURL, serverName, listen, pcr0, pcr1, pcr2 string
	var manifestPath, manifestSig, manifestPub string
	flag.StringVar(&enclaveURL, "enclave-url", "https://127.0.0.1:10443", "attested enclave HTTPS origin")
	flag.StringVar(&serverName, "servername", "router.local", "enclave TLS SNI name")
	flag.StringVar(&listen, "listen", "127.0.0.1:8788", "local address the agent points its base URL at")
	flag.StringVar(&pcr0, "pcr0", "", "pinned PCR0 hex (required unless -manifest is set)")
	flag.StringVar(&pcr1, "pcr1", "", "pinned PCR1 hex")
	flag.StringVar(&pcr2, "pcr2", "", "pinned PCR2 hex")
	flag.StringVar(&manifestPath, "manifest", "", "signed measurement manifest (JSON); pins PCR0/1/2 from it instead of -pcr*")
	flag.StringVar(&manifestSig, "manifest-sig", "", "detached base64 signature for -manifest (default: <manifest>.sig)")
	flag.StringVar(&manifestPub, "manifest-pubkey", "", "trusted Ed25519 public key (hex) for -manifest")

	var auditOnly bool
	flag.BoolVar(&auditOnly, "audit-only", false, "run the manifest + transparency-log verification and exit (no enclave attestation/proxy); for offline accountability evidence")

	var tl translogFlags
	flag.StringVar(&tl.bundlePath, "translog-bundle", env("TRANSLOG_BUNDLE", ""), "transparency-log bundle (from measure-sign -publish); enables the Rekor inclusion/consistency audit")
	flag.StringVar(&tl.rekorURL, "rekor-url", env("REKOR_URL", ""), "Rekor endpoint override (default: from bundle, else public instance)")
	flag.StringVar(&tl.rekorPubFile, "rekor-pubkey", env("REKOR_PUBKEY_FILE", ""), "pinned Rekor public key PEM file (default: from bundle, else fetched and bound by logID)")
	flag.StringVar(&tl.storePath, "treehead-store", env("TREEHEAD_STORE", ""), "path to persist verified tree heads (enables append-only consistency across restarts)")
	flag.StringVar(&tl.entryOverride, "translog-entry", "", "Rekor entry UUID override (advanced; normally read from the bundle)")
	flag.BoolVar(&tl.require, "require-translog", envBool("REKOR_REQUIRE", false), "fail closed unless the measurement is verified present in the transparency log")
	flag.Parse()

	expectedPCR, material, err := resolveExpectedPCR(manifestPath, manifestSig, manifestPub, pcr0, pcr1, pcr2)
	if err != nil {
		log.Fatalf("client-sidecar: %v", err)
	}

	// One-shot, pre-pin transparency-log audit (NOT on the per-request data path). Fail closed.
	auditCtx, cancelAudit := context.WithTimeout(context.Background(), 60*time.Second)
	if err := runTranslogAudit(auditCtx, tl, material); err != nil {
		cancelAudit()
		log.Fatalf("client-sidecar: %v", err)
	}
	cancelAudit()

	if auditOnly {
		log.Printf("client-sidecar: audit-only mode — manifest and transparency-log checks passed; exiting before attestation/proxy")
		return
	}

	s := &Sidecar{
		enclaveURL: enclaveURL,
		verify: func(ctx context.Context) (http.RoundTripper, error) {
			return attestedTransport(ctx, enclaveURL, serverName, expectedPCR)
		},
	}
	h, err := s.handler(context.Background())
	if err != nil {
		log.Fatalf("client-sidecar: %v", err)
	}
	log.Printf("client-sidecar: attestation verified; proxying %s -> %s", listen, enclaveURL)
	srv := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatalf("client-sidecar: %v", srv.ListenAndServe())
}
