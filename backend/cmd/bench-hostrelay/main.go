// Command bench-hostrelay is a benchmark-only host process that runs the
// confidential router's faithful relay path without Nitro Enclaves or vsock.
// It terminates ordinary TLS on the host, calls the untrusted-host orchestrator
// over the confidential RPC carried on TCP, forwards to a configured HTTPS mock
// upstream, and records usage back over the same RPC. It is a benchmark artifact,
// not a security artifact.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/tidwall/gjson"
)

const (
	maxRequestBody     = 64 << 20
	maxForwardAttempts = 3
	maxSSELine         = 1 << 20
	maxResponseBody    = 64 << 20
)

var allowedPassthroughHeaders = map[string]bool{
	"accept":                true,
	"accept-language":       true,
	"content-type":          true,
	"conversation_id":       true,
	"openai-beta":           true,
	"user-agent":            true,
	"originator":            true,
	"session_id":            true,
	"x-codex-turn-state":    true,
	"x-codex-turn-metadata": true,
}

type rpcClient interface {
	AuthorizeAndSelect(ctx context.Context, apiKey string, n confidential.RoutingNeeds, priorFailures []int64) (confidential.AuthorizeResult, error)
	RecordUsage(ctx context.Context, u confidential.UsageTelemetry) error
}

type forwardFunc func(context.Context, confidential.SelectedForwardRequest, responseSink) (confidential.UsageTelemetry, error)

type app struct {
	platform string
	maxBody  int
	dial     func(ctx context.Context) (rpcClient, func(), error)
	forward  forwardFunc
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	limit := a.maxBody
	if limit <= 0 {
		limit = maxRequestBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body")
		return
	}
	if len(body) > limit {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
		return
	}
	needs := confidential.RoutingNeeds{
		Model:     gjson.GetBytes(body, "model").String(),
		Platform:  a.platform,
		SessionID: r.Header.Get("session_id"),
	}

	client, cleanup, err := a.dial(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "orchestrator unavailable")
		return
	}
	defer cleanup()

	apiKey := extractAPIKey(r.Header)
	stream := gjson.GetBytes(body, "stream").Bool()
	var priorFailures []int64
	var lastForwardErr error
	for attempt := 1; attempt <= maxForwardAttempts; attempt++ {
		auth, err := client.AuthorizeAndSelect(r.Context(), apiKey, needs, priorFailures)
		if err != nil {
			writeError(w, http.StatusBadGateway, "authorize: "+err.Error())
			return
		}
		if !auth.Allowed {
			reason := auth.DenyReason
			if reason == "" {
				reason = "request denied"
			}
			writeError(w, http.StatusForbidden, reason)
			return
		}

		req := confidential.SelectedForwardRequest{
			ProviderID:       auth.ProviderID,
			EndpointPolicyID: auth.EndpointPolicyID,
			AccountID:        auth.AccountID,
			Model:            auth.Model,
			Stream:           stream,
			Credential:       auth.Credential,
			Body:             body,
			Headers:          r.Header,
		}
		tw := &headerTracker{ResponseWriter: w}
		usage, ferr := a.forward(r.Context(), req, newHTTPSink(tw))
		if ferr != nil && !tw.wrote {
			lastForwardErr = ferr
			if auth.AccountID > 0 {
				priorFailures = append(priorFailures, auth.AccountID)
			}
			if attempt < maxForwardAttempts {
				log.Printf("bench-hostrelay: pre-dispatch forward error (account=%d attempt=%d/%d): %v; reselecting account",
					auth.AccountID, attempt, maxForwardAttempts, ferr)
				continue
			}
			writeError(w, http.StatusBadGateway, "upstream: "+ferr.Error())
			return
		}
		if ferr != nil {
			log.Printf("bench-hostrelay: forward error after headers (account=%d): %v", auth.AccountID, ferr)
		}
		if err := client.RecordUsage(r.Context(), usage); err != nil {
			log.Printf("bench-hostrelay: record usage failed (account=%d): %v", auth.AccountID, err)
		}
		return
	}
	if lastForwardErr != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+lastForwardErr.Error())
	}
}

type headerTracker struct {
	http.ResponseWriter
	wrote bool
}

func (t *headerTracker) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *headerTracker) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *headerTracker) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func extractAPIKey(h http.Header) string {
	if v := strings.TrimSpace(h.Get("Authorization")); v != "" {
		return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	}
	return strings.TrimSpace(h.Get("x-api-key"))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"message":%q,"type":"confidential_router_error"}}`, msg)
}

type responseSink interface {
	WriteHeader(status int, headers map[string][]string)
	WriteChunk(p []byte) error
	Close()
}

type httpSink struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newHTTPSink(w http.ResponseWriter) responseSink {
	f, _ := w.(http.Flusher)
	return &httpSink{w: w, flusher: f}
}

func (s *httpSink) WriteHeader(status int, headers map[string][]string) {
	h := s.w.Header()
	for k, vs := range headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	s.w.WriteHeader(status)
}

func (s *httpSink) WriteChunk(p []byte) error {
	if _, err := s.w.Write(p); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

func (s *httpSink) Close() {}

type providerPolicy struct {
	ProviderID       confidential.ProviderID
	EndpointPolicyID confidential.EndpointPolicyID
	BaseURL          string
	Path             string
	AllowedHosts     []string
}

func (p providerPolicy) allowsHost(h string) bool {
	for _, a := range p.AllowedHosts {
		if a == h {
			return true
		}
	}
	return false
}

type forwarder struct {
	policy providerPolicy
	client *http.Client
}

func (f *forwarder) forwardSelected(ctx context.Context, req confidential.SelectedForwardRequest, sink responseSink) (confidential.UsageTelemetry, error) {
	start := time.Now()
	tel := confidential.UsageTelemetry{AccountID: req.AccountID, Model: req.Model}

	policy, err := f.resolvePolicy(req)
	if err != nil {
		return tel, err
	}

	target, err := url.Parse(policy.BaseURL)
	if err != nil {
		return tel, fmt.Errorf("bad policy base url %q: %w", policy.BaseURL, err)
	}
	target.Path = policy.Path
	if !policy.allowsHost(target.Hostname()) {
		return tel, fmt.Errorf("destination host %q not in policy allowlist", target.Hostname())
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		return tel, err
	}
	httpReq.Header.Set("authorization", "Bearer "+req.Credential)
	for key, values := range req.Headers {
		if !allowedPassthroughHeaders[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}
	if httpReq.Header.Get("content-type") == "" {
		httpReq.Header.Set("content-type", "application/json")
	}

	resp, err := f.client.Do(httpReq)
	if err != nil {
		return tel, fmt.Errorf("upstream dispatch: %w", err)
	}
	defer resp.Body.Close()
	tel.Status = resp.StatusCode

	relayResponseHeaders(resp, sink)
	usage, relayErr := relayResponse(resp, sink)
	sink.Close()

	tel.InputTokens = usage.input
	tel.OutputTokens = usage.output
	tel.LatencyMS = time.Since(start).Milliseconds()
	return tel, relayErr
}

func (f *forwarder) resolvePolicy(req confidential.SelectedForwardRequest) (providerPolicy, error) {
	if req.ProviderID != f.policy.ProviderID || req.EndpointPolicyID != f.policy.EndpointPolicyID {
		return providerPolicy{}, fmt.Errorf("unknown provider policy %s/%s", req.ProviderID, req.EndpointPolicyID)
	}
	return f.policy, nil
}

func relayResponseHeaders(resp *http.Response, sink responseSink) {
	headers := make(map[string][]string, len(resp.Header))
	for k, v := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding":
			continue
		}
		headers[k] = v
	}
	sink.WriteHeader(resp.StatusCode, headers)
}

type usageCounts struct {
	input  int64
	output int64
}

func relayResponse(resp *http.Response, sink responseSink) (usageCounts, error) {
	if isEventStream(resp.Header) {
		return relaySSE(resp.Body, sink)
	}
	return relayVerbatim(resp.Body, sink)
}

func isEventStream(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
}

func relaySSE(body io.Reader, sink responseSink) (usageCounts, error) {
	var usage usageCounts
	clientGone := false
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSELine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if !clientGone {
			out := make([]byte, 0, len(line)+1)
			out = append(out, line...)
			out = append(out, '\n')
			if err := sink.WriteChunk(out); err != nil {
				clientGone = true
			}
		}
		if data, ok := extractSSEData(line); ok {
			parseSSEUsage(data, &usage)
		}
	}
	if err := scanner.Err(); err != nil {
		return usage, fmt.Errorf("upstream stream read: %w", err)
	}
	return usage, nil
}

func relayVerbatim(body io.Reader, sink responseSink) (usageCounts, error) {
	buf, err := io.ReadAll(io.LimitReader(body, maxResponseBody))
	var usage usageCounts
	if len(buf) > 0 {
		_ = sink.WriteChunk(buf)
		extractUsageInto(buf, &usage)
	}
	if err != nil {
		return usage, fmt.Errorf("upstream body read: %w", err)
	}
	return usage, nil
}

func extractSSEData(line []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return nil, false
	}
	return bytes.TrimLeft(line[len("data:"):], " \t"), true
}

func parseSSEUsage(data []byte, usage *usageCounts) {
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}
	switch gjson.GetBytes(data, "type").String() {
	case "response.completed", "response.done", "response.incomplete", "response.cancelled", "response.canceled":
	default:
		return
	}
	extractUsageInto(data, usage)
}

func extractUsageInto(data []byte, usage *usageCounts) {
	if !gjson.ValidBytes(data) {
		return
	}
	if v := gjson.GetBytes(data, "usage"); v.IsObject() {
		setUsage(v, usage)
		return
	}
	if v := gjson.GetBytes(data, "response.usage"); v.IsObject() {
		setUsage(v, usage)
	}
}

func setUsage(v gjson.Result, usage *usageCounts) {
	in := v.Get("input_tokens").Int()
	if in == 0 {
		in = v.Get("prompt_tokens").Int()
	}
	out := v.Get("output_tokens").Int()
	if out == 0 {
		out = v.Get("completion_tokens").Int()
	}
	usage.input = in
	usage.output = out
}

func main() {
	var listen, cert, key, rpcAddr, upstreamBase, upstreamPath, upstreamCA, allowedHosts string
	flag.StringVar(&listen, "listen", "127.0.0.1:19443", "TLS listen address")
	flag.StringVar(&cert, "cert", "perf-results/ca/hostrelay.pem", "server certificate (PEM)")
	flag.StringVar(&key, "key", "perf-results/ca/hostrelay.key", "server private key (PEM)")
	flag.StringVar(&rpcAddr, "rpc-addr", "127.0.0.1:19001", "host-orchestrator confidential RPC TCP address")
	flag.StringVar(&upstreamBase, "upstream-base", "https://172.31.33.65:18443", "benchmark upstream base URL")
	flag.StringVar(&upstreamPath, "upstream-path", "/v1/responses", "benchmark upstream path")
	flag.StringVar(&upstreamCA, "upstream-cacert", "perf-results/ca/ca.pem", "PEM CA file to trust for upstream TLS")
	flag.StringVar(&allowedHosts, "upstream-allowed-hosts", "172.31.33.65", "comma-separated exact upstream host allowlist")
	flag.Parse()

	client, err := buildUpstreamClient(upstreamCA)
	if err != nil {
		log.Fatalf("bench-hostrelay: upstream client: %v", err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	policy, err := buildPolicy(upstreamBase, upstreamPath, allowedHosts)
	if err != nil {
		log.Fatalf("bench-hostrelay: policy: %v", err)
	}
	fwd := &forwarder{policy: policy, client: client}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	handler := &app{
		platform: "openai",
		dial: func(ctx context.Context) (rpcClient, func(), error) {
			conn, err := dialer.DialContext(ctx, "tcp", rpcAddr)
			if err != nil {
				return nil, nil, err
			}
			return confidential.NewCaller(conn), func() { _ = conn.Close() }, nil
		},
		forward: fwd.forwardSelected,
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("bench-hostrelay: serving TLS on %s, rpc=%s, upstream=%s%s", listen, rpcAddr, upstreamBase, upstreamPath)
	log.Fatal(srv.ListenAndServeTLS(cert, key))
}

func buildPolicy(baseURL, path, allowedHosts string) (providerPolicy, error) {
	target, err := url.Parse(baseURL)
	if err != nil {
		return providerPolicy{}, err
	}
	if target.Scheme != "https" || target.Hostname() == "" {
		return providerPolicy{}, fmt.Errorf("upstream-base must be an https URL with a host")
	}
	hosts := splitCSV(allowedHosts)
	if len(hosts) == 0 {
		hosts = []string{target.Hostname()}
	}
	return providerPolicy{
		ProviderID:       "openai",
		EndpointPolicyID: "openai-responses",
		BaseURL:          baseURL,
		Path:             path,
		AllowedHosts:     hosts,
	}, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func buildUpstreamClient(cacert string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cacert != "" {
		pem, err := os.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("cacert %s has no usable certificate", cacert)
		}
		tlsConfig.RootCAs = pool
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 0,
	}
	return &http.Client{Transport: tr}, nil
}
