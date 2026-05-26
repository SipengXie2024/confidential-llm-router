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
