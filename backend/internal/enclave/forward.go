package enclave

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
	"github.com/tidwall/gjson"
)

// allowedPassthroughHeaders mirrors openaiPassthroughAllowedHeaders in internal/service:
// only these low-risk client headers are forwarded upstream. It is kept here as baked-in
// enclave data because internal/enclave must not import internal/service (TCB size).
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

// maxSSELine bounds a single SSE line; maxResponseBody bounds a buffered non-SSE body.
const (
	maxSSELine      = 1 << 20
	maxResponseBody = 64 << 20
)

// forwardConfig injects test seams. In production both fields are zero: ForwardSelected
// resolves the baked-in policy and builds an SSRF-guarded client. Tests inject a client
// that can reach 127.0.0.1 and a policy pointed at an httptest server.
type forwardConfig struct {
	client         *http.Client
	policyOverride *confidential.ProviderPolicy
}

// ForwardSelected runs the OpenAI passthrough inside the enclave: resolve the baked-in
// ProviderPolicy, build the upstream request with the host-supplied credential, dispatch,
// relay the response to sink verbatim, and return usage telemetry. It deliberately does
// NOT do model transforms, tool correction, cross-protocol conversion, websearch/image
// emulation, failover, or billing persistence — those stay on the host (findings.md).
func ForwardSelected(ctx context.Context, req confidential.SelectedForwardRequest, sink ResponseSink) (confidential.UsageTelemetry, error) {
	return forwardSelected(ctx, req, sink, forwardConfig{})
}

func forwardSelected(ctx context.Context, req confidential.SelectedForwardRequest, sink ResponseSink, cfg forwardConfig) (confidential.UsageTelemetry, error) {
	start := time.Now()
	tel := confidential.UsageTelemetry{AccountID: req.AccountID, Model: req.Model}

	policy, err := resolvePolicy(req, cfg)
	if err != nil {
		return tel, err
	}

	target, err := url.Parse(policy.BaseURL)
	if err != nil {
		return tel, fmt.Errorf("bad policy base url %q: %w", policy.BaseURL, err)
	}
	target.Path = policy.Path
	// goal①: the destination is policy-fixed. Refuse any host outside the allowlist so a
	// malicious host cannot redirect the client's plaintext off-policy.
	if !policy.AllowsHost(target.Hostname()) {
		return tel, fmt.Errorf("destination host %q not in policy allowlist", target.Hostname())
	}

	client, err := resolveClient(cfg)
	if err != nil {
		return tel, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		return tel, err
	}
	// The credential is set by the enclave, never taken from a client header.
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

	resp, err := client.Do(httpReq)
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

func resolvePolicy(req confidential.SelectedForwardRequest, cfg forwardConfig) (confidential.ProviderPolicy, error) {
	if cfg.policyOverride != nil {
		return *cfg.policyOverride, nil
	}
	p, ok := confidential.ResolvePolicy(req.ProviderID, req.EndpointPolicyID)
	if !ok {
		return confidential.ProviderPolicy{}, fmt.Errorf("unknown provider policy %s/%s", req.ProviderID, req.EndpointPolicyID)
	}
	return p, nil
}

func resolveClient(cfg forwardConfig) (*http.Client, error) {
	base := cfg.client
	if base == nil {
		// Streaming responses: no overall client timeout. ValidateResolvedIP guards
		// against DNS-rebinding even though the host is policy-pinned.
		c, err := httpclient.GetClient(httpclient.Options{
			ValidateResolvedIP: true,
			AllowPrivateHosts:  false,
		})
		if err != nil {
			return nil, err
		}
		base = c
	}
	// Shallow-copy so CheckRedirect can be pinned without mutating the shared pooled
	// client (the Transport is intentionally still shared for connection reuse). The
	// destination is policy-fixed; following a redirect would replay the plaintext body
	// to an off-policy host (goal①), so refuse to follow and pass the 3xx through.
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client, nil
}

func relayResponseHeaders(resp *http.Response, sink ResponseSink) {
	headers := make(map[string][]string, len(resp.Header))
	for k, v := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding":
			// Body framing is re-derived by the sink's HTTP server; the relayed body
			// length may differ from upstream (SSE) so a copied Content-Length would lie.
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

// relayResponse streams the upstream response to the sink and extracts usage. SSE
// (text/event-stream) is relayed line-by-line with usage taken from terminal events;
// any other content type (JSON errors, or stream:false responses) is copied byte-for-byte
// and usage is parsed from the whole body. A non-nil error means the upstream stream
// failed mid-flight — the client may already have received a partial 200 response, so the
// caller should treat the telemetry as incomplete.
func relayResponse(resp *http.Response, sink ResponseSink) (usageCounts, error) {
	if isEventStream(resp.Header) {
		return relaySSE(resp.Body, sink)
	}
	return relayVerbatim(resp.Body, sink)
}

func isEventStream(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
}

func relaySSE(body io.Reader, sink ResponseSink) (usageCounts, error) {
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

func relayVerbatim(body io.Reader, sink ResponseSink) (usageCounts, error) {
	buf, err := io.ReadAll(io.LimitReader(body, maxResponseBody))
	var usage usageCounts
	if len(buf) > 0 {
		_ = sink.WriteChunk(buf) // client disconnect is non-fatal; still parse usage for billing
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

// parseSSEUsage reads usage only from OpenAI terminal SSE events. It follows
// OpenAIGatewayService.parseSSEUsageBytes for the gating + field paths, but deliberately
// omits that function's len(data) < 72 fast-path (a perf shortcut, not semantics) and its
// cache/image token fields (not part of MVP UsageTelemetry).
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

// extractUsageInto reads the usage object (top-level "usage" then "response.usage") from
// a JSON document, used for both terminal SSE events and non-SSE response bodies.
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
