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

// maxSSELine bounds a single SSE line read from the upstream response.
const maxSSELine = 1 << 20

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
	parsedUsage := relayBody(resp.Body, sink)
	sink.Close()

	tel.InputTokens = parsedUsage.input
	tel.OutputTokens = parsedUsage.output
	tel.LatencyMS = time.Since(start).Milliseconds()
	return tel, nil
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
	if cfg.client != nil {
		return cfg.client, nil
	}
	// Streaming responses: no overall client timeout. ValidateResolvedIP guards against
	// DNS-rebinding even though the host is policy-pinned.
	return httpclient.GetClient(httpclient.Options{
		ValidateResolvedIP: true,
		AllowPrivateHosts:  false,
	})
}

func relayResponseHeaders(resp *http.Response, sink ResponseSink) {
	headers := make(map[string][]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = v
	}
	sink.WriteHeader(resp.StatusCode, headers)
}

type usageCounts struct {
	input  int64
	output int64
}

// relayBody streams the upstream response to the sink line-by-line (verbatim for
// LF-delimited SSE, matching the host gateway's relay) and extracts usage from terminal
// events. A sink write error means the client disconnected; we keep draining upstream so
// usage telemetry is still collected for the host's billing.
func relayBody(body io.Reader, sink ResponseSink) usageCounts {
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
	return usage
}

func extractSSEData(line []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return nil, false
	}
	return bytes.TrimLeft(line[len("data:"):], " \t"), true
}

// parseSSEUsage mirrors OpenAIGatewayService.parseSSEUsageBytes: usage is only read from
// terminal events, trying the top-level "usage" then "response.usage" object, and
// input_tokens/output_tokens with prompt_tokens/completion_tokens fallbacks.
func parseSSEUsage(data []byte, usage *usageCounts) {
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}
	switch gjson.GetBytes(data, "type").String() {
	case "response.completed", "response.done", "response.incomplete", "response.cancelled", "response.canceled":
	default:
		return
	}
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
