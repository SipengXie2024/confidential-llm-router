//go:build unit

package enclave

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
)

const fakeOpenAISSE = "event: response.output_text.delta\n" +
	"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n" +
	"\n" +
	"event: response.completed\n" +
	"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":12,\"output_tokens\":7}}}\n" +
	"\n"

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}

type recordingSink struct {
	status  int
	headers map[string][]string
	chunks  [][]byte
	closed  bool
}

func (s *recordingSink) WriteHeader(status int, headers map[string][]string) {
	s.status = status
	s.headers = headers
}

func (s *recordingSink) WriteChunk(p []byte) error {
	s.chunks = append(s.chunks, append([]byte(nil), p...))
	return nil
}

func (s *recordingSink) Close() {
	s.closed = true
}

func TestForwardSelectedOpenAIPassthrough(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, fakeOpenAISSE)
	}))
	defer ts.Close()

	reqBody := []byte(`{"model":"gpt-5.3-codex","input":"hi","stream":true}`)
	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		AccountID: 42, Model: "gpt-5.3-codex", Stream: true,
		Credential: "sk-test", Body: reqBody,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
	}
	rec := httptest.NewRecorder()
	cfg := forwardConfig{
		client: ts.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: ts.URL, Path: "/v1/responses",
			AllowedHosts: []string{mustHost(t, ts.URL)},
		},
	}

	tel, err := forwardSelected(context.Background(), req, NewHTTPSink(rec), cfg)
	if err != nil {
		t.Fatalf("forwardSelected: %v", err)
	}
	// (a) upstream received the credential and the body verbatim.
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("upstream auth = %q, want Bearer sk-test", gotAuth)
	}
	if !bytes.Equal(gotBody, reqBody) {
		t.Fatalf("upstream body mismatch:\n got %q\nwant %q", gotBody, reqBody)
	}
	// (b) the sink received the SSE stream verbatim.
	if rec.Body.String() != fakeOpenAISSE {
		t.Fatalf("sink body not verbatim:\n got %q\nwant %q", rec.Body.String(), fakeOpenAISSE)
	}
	// (c) usage telemetry extracted from the response.completed event.
	if tel.InputTokens != 12 || tel.OutputTokens != 7 {
		t.Fatalf("usage = %+v, want input=12 output=7", tel)
	}
	if tel.AccountID != 42 || tel.Status != http.StatusOK {
		t.Fatalf("telemetry account/status wrong: %+v", tel)
	}
}

func TestRelaySSEObservationBoundary(t *testing.T) {
	input := "event: response.output_text.delta\r\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"alpha\"}\r\n" +
		"\r\n" +
		"event: response.completed\r\n" +
		"data: {\"type\":\"response.completed\",\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}\r\n" +
		"\r\n"
	sink := &recordingSink{}

	usage, err := relaySSE(strings.NewReader(input), sink)
	if err != nil {
		t.Fatalf("relaySSE: %v", err)
	}
	want := []string{
		"event: response.output_text.delta\r\n",
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"alpha\"}\r\n",
		"\r\n",
		"event: response.completed\r\n",
		"data: {\"type\":\"response.completed\",\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}\r\n",
		"\r\n",
	}
	if len(sink.chunks) != len(want) {
		t.Fatalf("SSE chunks = %d, want one chunk per SSE line (%d): %#q", len(sink.chunks), len(want), sink.chunks)
	}
	for i, chunk := range sink.chunks {
		if string(chunk) != want[i] {
			t.Fatalf("chunk %d = %q, want %q", i, chunk, want[i])
		}
	}
	if usage.input != 2 || usage.output != 3 {
		t.Fatalf("usage = %+v, want input=2 output=3", usage)
	}
}

func TestForwardSelectedProviderAuthSchemes(t *testing.T) {
	cases := []struct {
		name       string
		policy     confidential.ProviderPolicy
		wantHeader string
		wantValue  string
	}{
		{
			name: "openrouter bearer",
			policy: confidential.ProviderPolicy{
				ProviderID: "openrouter", EndpointPolicyID: "chat-completions",
			},
			wantHeader: "Authorization",
			wantValue:  "Bearer sk-provider",
		},
		{
			name: "gemini api key",
			policy: confidential.ProviderPolicy{
				ProviderID: "gemini", EndpointPolicyID: "generate-content-gemini-2.5-flash",
			},
			wantHeader: "X-Goog-Api-Key",
			wantValue:  "sk-provider",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotHeader http.Header
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{}`)
			}))
			defer ts.Close()

			policy := tc.policy
			policy.BaseURL = ts.URL
			policy.Path = "/v1/test"
			policy.AllowedHosts = []string{mustHost(t, ts.URL)}
			req := confidential.SelectedForwardRequest{
				ProviderID: policy.ProviderID, EndpointPolicyID: policy.EndpointPolicyID,
				Credential: "sk-provider", Body: []byte("{}"),
				Headers: map[string][]string{
					"Authorization":  {"Bearer client"},
					"X-Goog-Api-Key": {"client"},
				},
			}
			cfg := forwardConfig{client: ts.Client(), policyOverride: &policy}
			if _, err := forwardSelected(context.Background(), req, NewHTTPSink(httptest.NewRecorder()), cfg); err != nil {
				t.Fatalf("forwardSelected: %v", err)
			}
			if got := gotHeader.Get(tc.wantHeader); got != tc.wantValue {
				t.Fatalf("%s = %q, want %q", tc.wantHeader, got, tc.wantValue)
			}
			if tc.wantHeader != "Authorization" && gotHeader.Get("Authorization") != "" {
				t.Fatalf("client Authorization leaked to %s policy: %q", tc.name, gotHeader.Get("Authorization"))
			}
			if tc.wantHeader != "X-Goog-Api-Key" && gotHeader.Get("X-Goog-Api-Key") != "" {
				t.Fatalf("client X-Goog-Api-Key leaked to %s policy: %q", tc.name, gotHeader.Get("X-Goog-Api-Key"))
			}
		})
	}
}

func TestProviderUsageParsing(t *testing.T) {
	openRouterBody := []byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":13}}`)
	openRouterUsage, err := relayVerbatim(bytes.NewReader(openRouterBody), &recordingSink{})
	if err != nil {
		t.Fatalf("openrouter relay: %v", err)
	}
	if openRouterUsage.input != 11 || openRouterUsage.output != 13 {
		t.Fatalf("openrouter usage = %+v, want input=11 output=13", openRouterUsage)
	}

	geminiBody := []byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":17,"candidatesTokenCount":19,"totalTokenCount":36}}`)
	geminiUsage, err := relayVerbatim(bytes.NewReader(geminiBody), &recordingSink{})
	if err != nil {
		t.Fatalf("gemini relay: %v", err)
	}
	if geminiUsage.input != 17 || geminiUsage.output != 19 {
		t.Fatalf("gemini usage = %+v, want input=17 output=19", geminiUsage)
	}
}

func TestRelayVerbatimObservationBoundary(t *testing.T) {
	body := []byte(`{"id":"resp","usage":{"input_tokens":5,"output_tokens":8},"output_text":"synthetic"}`)
	sink := &recordingSink{}

	usage, err := relayVerbatim(bytes.NewReader(body), sink)
	if err != nil {
		t.Fatalf("relayVerbatim: %v", err)
	}
	if len(sink.chunks) != 1 {
		t.Fatalf("non-SSE relay emitted %d chunks, want one full-body chunk", len(sink.chunks))
	}
	if !bytes.Equal(sink.chunks[0], body) {
		t.Fatalf("non-SSE chunk not verbatim:\n got %q\nwant %q", sink.chunks[0], body)
	}
	if usage.input != 5 || usage.output != 8 {
		t.Fatalf("usage = %+v, want input=5 output=8", usage)
	}
}

// Guard for goal①: even if a (malicious) host steers the base URL at a server whose
// host is not in the policy allowlist, ForwardSelected must refuse to dispatch.
func TestForwardSelectedRejectsDisallowedHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must never be reached for a disallowed host")
	}))
	defer ts.Close()

	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		Model: "gpt-5.3-codex", Credential: "sk-test", Body: []byte("{}"),
	}
	cfg := forwardConfig{
		client: ts.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: ts.URL, Path: "/v1/responses",
			AllowedHosts: []string{"api.openai.com"}, // does NOT include the ts host
		},
	}
	if _, err := forwardSelected(context.Background(), req, NewHTTPSink(httptest.NewRecorder()), cfg); err == nil {
		t.Fatal("expected rejection: target host not in policy allowlist")
	} else if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected allowlist error, got: %v", err)
	}
}

func TestForwardSelectedNonSSEVerbatim(t *testing.T) {
	const jsonBody = `{"id":"resp_1","usage":{"input_tokens":3,"output_tokens":4}}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, jsonBody)
	}))
	defer ts.Close()

	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		AccountID: 7, Model: "gpt-5.3-codex", Credential: "sk-test", Body: []byte("{}"),
	}
	rec := httptest.NewRecorder()
	cfg := forwardConfig{
		client: ts.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: ts.URL, Path: "/v1/responses",
			AllowedHosts: []string{mustHost(t, ts.URL)},
		},
	}
	tel, err := forwardSelected(context.Background(), req, NewHTTPSink(rec), cfg)
	if err != nil {
		t.Fatalf("forwardSelected: %v", err)
	}
	if rec.Body.String() != jsonBody {
		t.Fatalf("non-SSE body not verbatim:\n got %q\nwant %q", rec.Body.String(), jsonBody)
	}
	if tel.InputTokens != 3 || tel.OutputTokens != 4 {
		t.Fatalf("usage = %+v, want input=3 output=4", tel)
	}
}

func TestForwardSelectedStreamErrorPropagates(t *testing.T) {
	// A single SSE line larger than maxSSELine must surface as an error, not a silent
	// success with partial telemetry.
	huge := "data: " + strings.Repeat("a", maxSSELine+16) + "\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, huge)
	}))
	defer ts.Close()

	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		Model: "gpt-5.3-codex", Credential: "sk-test", Body: []byte("{}"),
	}
	cfg := forwardConfig{
		client: ts.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: ts.URL, Path: "/v1/responses",
			AllowedHosts: []string{mustHost(t, ts.URL)},
		},
	}
	if _, err := forwardSelected(context.Background(), req, NewHTTPSink(httptest.NewRecorder()), cfg); err == nil {
		t.Fatal("expected error when upstream SSE line exceeds the scan limit")
	}
}

// Header-allowlist conformance: only allowedPassthroughHeaders reach the upstream, the
// credential is enclave-set, and a client-supplied Authorization can neither override it
// nor leak. This mechanizes the ARPA Phase-1 "faithful passthrough" audit for headers.
func TestForwardSelectedHeaderAllowlist(t *testing.T) {
	var gotHeader http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer ts.Close()

	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		Model: "gpt-5.3-codex", Credential: "sk-enclave", Body: []byte("{}"),
		Headers: map[string][]string{
			// allowlisted — must pass through:
			"Content-Type": {"application/json"},
			"Openai-Beta":  {"responses=v1"},
			"Session_Id":   {"sess-1"},
			"User-Agent":   {"codex/1.0"},
			// NOT allowlisted — must be dropped:
			"Authorization":    {"Bearer client-supplied"},
			"Cookie":           {"secret=leak"},
			"Host":             {"attacker.example"},
			"X-Evil":           {"1"},
			"X-Forwarded-Host": {"attacker.example"},
			"X-Original-URL":   {"https://attacker.example/v1/responses"},
		},
	}
	cfg := forwardConfig{
		client: ts.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: ts.URL, Path: "/v1/responses",
			AllowedHosts: []string{mustHost(t, ts.URL)},
		},
	}
	if _, err := forwardSelected(context.Background(), req, NewHTTPSink(httptest.NewRecorder()), cfg); err != nil {
		t.Fatalf("forwardSelected: %v", err)
	}
	if got := gotHeader.Get("Authorization"); got != "Bearer sk-enclave" {
		t.Fatalf("upstream Authorization = %q, want enclave Bearer (client header must not override/leak)", got)
	}
	for k, want := range map[string]string{"Openai-Beta": "responses=v1", "Session_Id": "sess-1", "User-Agent": "codex/1.0"} {
		if got := gotHeader.Get(k); got != want {
			t.Fatalf("allowlisted header %s = %q, want %q", k, got, want)
		}
	}
	for _, k := range []string{"Cookie", "Host", "X-Evil", "X-Forwarded-Host", "X-Original-URL"} {
		if got := gotHeader.Get(k); got != "" {
			t.Fatalf("non-allowlisted header %s leaked upstream: %q", k, got)
		}
	}
}

func TestForwardSelectedDoesNotFollowOffPolicyRedirect(t *testing.T) {
	attackerReached := false
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerReached = true
		t.Fatal("redirect target must not receive the client body")
	}))
	defer attacker.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", attacker.URL+"/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, "redirect refused")
	}))
	defer upstream.Close()

	req := confidential.SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		Model: "gpt-5.3-codex", Credential: "sk-test", Body: []byte(`{"input":"secret"}`),
	}
	rec := httptest.NewRecorder()
	cfg := forwardConfig{
		client: upstream.Client(),
		policyOverride: &confidential.ProviderPolicy{
			ProviderID: "openai", EndpointPolicyID: "openai-responses",
			BaseURL: upstream.URL, Path: "/v1/responses",
			AllowedHosts: []string{mustHost(t, upstream.URL)},
		},
	}
	tel, err := forwardSelected(context.Background(), req, NewHTTPSink(rec), cfg)
	if err != nil {
		t.Fatalf("forwardSelected: %v", err)
	}
	if attackerReached {
		t.Fatal("redirect target was reached")
	}
	if rec.Code != http.StatusTemporaryRedirect || tel.Status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect should be returned, not followed: rec=%d tel=%d body=%q", rec.Code, tel.Status, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got == "" {
		t.Fatal("redirect response should be relayed to the client for visibility")
	}
}

// Body byte-fidelity across tricky inputs: the enclave forwards the client's body to the
// upstream verbatim (no transform), unlike a rewriting gateway. Covers the AC-1.a/AC-1
// "the signed/forwarded request must equal what the client sent" property.
func TestForwardSelectedBodyFidelityTable(t *testing.T) {
	cases := map[string]string{
		"multimodal":          `{"model":"gpt-5.3-codex","input":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}`,
		"tool_calls":          `{"model":"gpt-5.3-codex","tools":[{"type":"function","function":{"name":"bash","parameters":{"type":"object"}}}],"tool_choice":"auto"}`,
		"json_object_no_json": `{"model":"gpt-5.3-codex","input":"summarize","response_format":{"type":"json_object"}}`,
		"exotic_fields":       `{"model":"gpt-5.3-codex","input":"hi","frequency_penalty":0.5,"logit_bias":{"1":2},"seed":7,"weird":{"x":[1,2,3]}}`,
		"large":               `{"model":"gpt-5.3-codex","input":"` + strings.Repeat("x", 200000) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			reqBody := []byte(body)
			var gotBody []byte
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer ts.Close()
			req := confidential.SelectedForwardRequest{
				ProviderID: "openai", EndpointPolicyID: "openai-responses",
				Model: "gpt-5.3-codex", Credential: "sk-test", Body: reqBody,
			}
			cfg := forwardConfig{
				client: ts.Client(),
				policyOverride: &confidential.ProviderPolicy{
					ProviderID: "openai", EndpointPolicyID: "openai-responses",
					BaseURL: ts.URL, Path: "/v1/responses",
					AllowedHosts: []string{mustHost(t, ts.URL)},
				},
			}
			if _, err := forwardSelected(context.Background(), req, NewHTTPSink(httptest.NewRecorder()), cfg); err != nil {
				t.Fatalf("forwardSelected: %v", err)
			}
			if !bytes.Equal(gotBody, reqBody) {
				t.Fatalf("upstream body not verbatim for %s:\n got %q\nwant %q", name, gotBody, reqBody)
			}
		})
	}
}

// Seam-off-in-production: ForwardSelected passes an empty forwardConfig{}, so the destination
// is resolved ONLY from the measured ProviderPolicy. A host may name a policy key but cannot
// supply a URL/client; an unknown key errors with no host-URL fallback (fail closed).
func TestForwardSelectedProductionPolicyPin(t *testing.T) {
	known := confidential.SelectedForwardRequest{ProviderID: "openai", EndpointPolicyID: "openai-responses"}
	p, err := resolvePolicy(known, forwardConfig{})
	if err != nil {
		t.Fatalf("resolvePolicy(known): %v", err)
	}
	if p.BaseURL != "https://api.openai.com" || !p.AllowsHost("api.openai.com") {
		t.Fatalf("production policy not pinned to api.openai.com: %+v", p)
	}
	unknown := confidential.SelectedForwardRequest{ProviderID: "evil", EndpointPolicyID: "x"}
	if _, err := resolvePolicy(unknown, forwardConfig{}); err == nil {
		t.Fatal("resolvePolicy(unknown) must error (no host-URL fallback)")
	}
	if _, err := ForwardSelected(context.Background(), unknown, NewHTTPSink(httptest.NewRecorder())); err == nil {
		t.Fatal("ForwardSelected(unknown) must fail closed before reaching the network")
	}
}
