// Command bench-handshake measures the RA-TLS attested-handshake segment in isolation,
// excluding sidecar process startup. Each iteration performs a COLD handshake against the
// live enclave: open a fresh probe TLS connection, fetch the leaf cert (GET /enclave),
// draw a fresh nonce, fetch the attestation document (GET /enclave/attestation?nonce=...),
// and run the production verification (sidecar.Verify: AWS COSE signature + cert chain,
// nonce freshness, pinned PCRs, and the TLS-cert binding). The verification code path is
// reused verbatim from internal/sidecar; only the two trivial HTTP GET evidence-fetch
// helpers are duplicated here (they are evidence transport, not verification logic).
//
// Output: one per-handshake duration in milliseconds per line to -out. A single Verify
// failure aborts the run (the measurement is only meaningful against a real, attested
// enclave). This is a host-side benchmark tool; it is NOT part of the enclave TCB.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/sidecar"
)

const nonceLen = 20

func main() {
	var enclaveURL, serverName, pcr0, pcr1, pcr2, out string
	var k int
	flag.StringVar(&enclaveURL, "enclave-url", "https://127.0.0.1:10443", "attested enclave HTTPS origin")
	flag.StringVar(&serverName, "servername", "router.local", "enclave TLS SNI name")
	flag.StringVar(&pcr0, "pcr0", "", "pinned PCR0 hex (required)")
	flag.StringVar(&pcr1, "pcr1", "", "pinned PCR1 hex")
	flag.StringVar(&pcr2, "pcr2", "", "pinned PCR2 hex")
	flag.IntVar(&k, "k", 50, "number of cold handshakes to time")
	flag.StringVar(&out, "out", "exp5-handshake.txt", "output file: one per-handshake duration (ms) per line")
	flag.Parse()

	if pcr0 == "" {
		log.Fatal("bench-handshake: -pcr0 is required")
	}
	expectedPCR := map[int]string{0: pcr0}
	if pcr1 != "" {
		expectedPCR[1] = pcr1
	}
	if pcr2 != "" {
		expectedPCR[2] = pcr2
	}

	durMS := make([]float64, 0, k)
	for i := 0; i < k; i++ {
		d, err := oneHandshake(context.Background(), enclaveURL, serverName, expectedPCR)
		if err != nil {
			log.Fatalf("bench-handshake: iteration %d failed: %v", i, err)
		}
		durMS = append(durMS, float64(d.Microseconds())/1000.0)
	}

	if err := writeLines(out, durMS); err != nil {
		log.Fatalf("bench-handshake: write %s: %v", out, err)
	}

	report(durMS, k, out)
}

// oneHandshake performs and times a single cold RA-TLS attested handshake + verification.
// A fresh probe client (and thus a fresh enclave TLS connection) is used each call so the
// timing reflects the full per-handshake cost a sidecar pays at startup, not a warmed pool.
func oneHandshake(ctx context.Context, enclaveURL, serverName string, expectedPCR map[int]string) (time.Duration, error) {
	start := time.Now()
	probe := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec // verified via attestation, not PKI
			DisableKeepAlives: false,
		},
		Timeout: 15 * time.Second,
	}
	defer probe.CloseIdleConnections()

	certDER, err := fetchLeafCert(ctx, probe, enclaveURL)
	if err != nil {
		return 0, fmt.Errorf("fetch enclave certificate: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	doc, err := fetchAttestation(ctx, probe, enclaveURL, nonce)
	if err != nil {
		return 0, fmt.Errorf("fetch attestation: %w", err)
	}
	if err := sidecar.Verify(doc, expectedPCR, nonce, certDER); err != nil {
		return 0, fmt.Errorf("verify: %w", err)
	}
	return time.Since(start), nil
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
}

func writeLines(path string, vals []float64) error {
	var b strings.Builder
	for _, v := range vals {
		fmt.Fprintf(&b, "%.3f\n", v)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func report(vals []float64, k int, out string) {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	pct := func(p float64) float64 {
		if len(s) == 0 {
			return 0
		}
		idx := int(p / 100 * float64(len(s)-1))
		return s[idx]
	}
	fmt.Printf("bench-handshake: K=%d wrote %s\n", k, out)
	fmt.Printf("  min=%.2f p50=%.2f p95=%.2f p99=%.2f max=%.2f (ms)\n",
		s[0], pct(50), pct(95), pct(99), s[len(s)-1])
}
