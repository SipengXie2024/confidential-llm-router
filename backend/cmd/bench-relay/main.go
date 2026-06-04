// Command bench-relay is a steady-state, keep-alive load client for the relay-overhead
// experiments. It issues N sequential POST /v1/responses requests over a SINGLE reused
// http.Client (connection pooling, like a production router), times each request end to end
// (send body -> read full response body), and writes one per-request latency in milliseconds
// per line to -out.
//
// Two targets share this client:
//   - baseline: client -> mock (one local TLS hop), -cacert pins the private CA.
//   - aegis:    client -> sidecar (plaintext) -> host ciphertext relay -> enclave -> mock.
//
// Overhead = aegis - baseline, compared per percentile downstream. Host-side benchmark tool;
// not part of the enclave TCB.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	var target, out, cacert, auth, model string
	var n, warmup, payloadBytes int
	flag.StringVar(&target, "target", "", "full URL, e.g. https://172.31.33.65:8443/v1/responses or http://127.0.0.1:8788/v1/responses")
	flag.IntVar(&n, "n", 300, "number of timed requests")
	flag.IntVar(&warmup, "warmup", 10, "number of untimed warm-up requests")
	flag.IntVar(&payloadBytes, "payload-bytes", 256, "approx size of the JSON 'input' field in bytes")
	flag.StringVar(&cacert, "cacert", "", "PEM CA file to trust (for https targets)")
	flag.StringVar(&auth, "auth", "", "bearer token for Authorization header (aegis path)")
	flag.StringVar(&model, "model", "gpt-4o-mini", "model field in the request body")
	flag.StringVar(&out, "out", "bench-relay.txt", "output file: one per-request latency (ms) per line")
	flag.Parse()

	if target == "" {
		log.Fatal("bench-relay: -target is required")
	}

	body := buildBody(model, payloadBytes)
	client := buildClient(cacert)

	// Warm up: establish the keep-alive connection(s) and let the path reach steady state.
	for i := 0; i < warmup; i++ {
		if _, err := doOne(client, target, body, auth); err != nil {
			log.Fatalf("bench-relay: warmup %d failed: %v", i, err)
		}
	}

	durMS := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		d, err := doOne(client, target, body, auth)
		if err != nil {
			log.Fatalf("bench-relay: request %d failed: %v", i, err)
		}
		durMS = append(durMS, float64(d.Microseconds())/1000.0)
	}

	if err := writeLines(out, durMS); err != nil {
		log.Fatalf("bench-relay: write %s: %v", out, err)
	}
	report(durMS, n, payloadBytes, out)
}

// doOne sends one request over the shared client and times until the full response body is
// read. Returns an error if the status is not 200 or the stream lacks a terminal completion,
// so a broken path fails loud instead of producing meaningless fast timings.
func doOne(client *http.Client, target string, body []byte, auth string) (time.Duration, error) {
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}
	d := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if !bytes.Contains(respBody, []byte("response.completed")) {
		return 0, fmt.Errorf("no terminal completion in response (len=%d): %.200s", len(respBody), respBody)
	}
	return d, nil
}

func buildBody(model string, payloadBytes int) []byte {
	// JSON-escaped padding via a run of 'a'; the 'input' field carries the bulk of the body.
	pad := payloadBytes
	if pad < 1 {
		pad = 1
	}
	input := strings.Repeat("a", pad)
	return []byte(fmt.Sprintf(`{"model":%q,"input":%q,"stream":true}`, model, input))
}

func buildClient(cacert string) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false, // keep HTTP/1.1 keep-alive, matching the enclave relay path
	}
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			log.Fatalf("bench-relay: read cacert: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("bench-relay: cacert %s has no usable certificate", cacert)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func writeLines(path string, vals []float64) error {
	var b strings.Builder
	for _, v := range vals {
		fmt.Fprintf(&b, "%.3f\n", v)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func report(vals []float64, n, payloadBytes int, out string) {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	pct := func(p float64) float64 {
		idx := int(p / 100 * float64(len(s)-1))
		return s[idx]
	}
	fmt.Printf("bench-relay: N=%d payload=%dB wrote %s\n", n, payloadBytes, out)
	fmt.Printf("  min=%.3f p50=%.3f p95=%.3f p99=%.3f max=%.3f (ms)\n",
		s[0], pct(50), pct(95), pct(99), s[len(s)-1])
}
