//go:build unit

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/Wei-Shaw/sub2api/internal/enclave"
)

type stubOrchestrator struct {
	auth          confidential.AuthorizeResult
	auths         []confidential.AuthorizeResult
	authCalls     int
	priorFailures [][]int64
	lastUsage     confidential.UsageTelemetry
	recordCalls   int
}

func (s *stubOrchestrator) AuthorizeAndSelect(_ context.Context, _ string, _ confidential.RoutingNeeds, priorFailures []int64) (confidential.AuthorizeResult, error) {
	s.priorFailures = append(s.priorFailures, append([]int64(nil), priorFailures...))
	s.authCalls++
	if len(s.auths) == 0 {
		return s.auth, nil
	}
	idx := s.authCalls - 1
	if idx >= len(s.auths) {
		idx = len(s.auths) - 1
	}
	return s.auths[idx], nil
}

func (s *stubOrchestrator) RecordUsage(_ context.Context, u confidential.UsageTelemetry) error {
	s.lastUsage = u
	s.recordCalls++
	return nil
}

func TestEnclaveCoreServeHTTP(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auth: confidential.AuthorizeResult{
		Allowed: true, AccountID: 5, ProviderID: "openai",
		EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-acct",
	}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	var gotReq confidential.SelectedForwardRequest
	fakeForward := func(_ context.Context, req confidential.SelectedForwardRequest, sink enclave.ResponseSink) (confidential.UsageTelemetry, error) {
		gotReq = req
		sink.WriteHeader(http.StatusOK, map[string][]string{"Content-Type": {"text/event-stream"}})
		_ = sink.WriteChunk([]byte("data: hi\n\n"))
		return confidential.UsageTelemetry{AccountID: req.AccountID, OutputTokens: 9}, nil
	}

	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		forward:  fakeForward,
	}

	const reqBody = `{"model":"gpt-5.3-codex","stream":true}`
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(reqBody))
	r.Header.Set("Authorization", "Bearer sk-userkey")
	r.Header.Set("session_id", "sess1")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: hi") {
		t.Fatalf("bad response: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotReq.Credential != "sk-acct" || gotReq.AccountID != 5 || gotReq.Model != "gpt-5.3-codex" {
		t.Fatalf("bad forward req: %+v", gotReq)
	}
	if string(gotReq.Body) != reqBody || !gotReq.Stream {
		t.Fatalf("body/stream not passed through: body=%q stream=%v", gotReq.Body, gotReq.Stream)
	}
	if stub.lastUsage.OutputTokens != 9 {
		t.Fatalf("RecordUsage not received by orchestrator: %+v", stub.lastUsage)
	}
}

func TestEnclaveCoreHostChosenModelDoesNotRewriteClientBody(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auth: confidential.AuthorizeResult{
		Allowed: true, AccountID: 5, ProviderID: "openai",
		EndpointPolicyID: "openai-responses", Model: "host-telemetry-model", Credential: "sk-acct",
	}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	var gotReq confidential.SelectedForwardRequest
	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		forward: func(_ context.Context, req confidential.SelectedForwardRequest, sink enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			gotReq = req
			sink.WriteHeader(http.StatusOK, map[string][]string{"Content-Type": {"application/json"}})
			_ = sink.WriteChunk([]byte(`{"ok":true}`))
			return confidential.UsageTelemetry{AccountID: req.AccountID, Model: req.Model, OutputTokens: 1}, nil
		},
	}

	const reqBody = `{"model":"client-requested-model","input":"synthetic","stream":false}`
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(reqBody))
	r.Header.Set("Authorization", "Bearer sk-userkey")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("bad response: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotReq.Model != "host-telemetry-model" {
		t.Fatalf("forward telemetry model = %q, want host-selected metadata model", gotReq.Model)
	}
	if string(gotReq.Body) != reqBody {
		t.Fatalf("host-selected model rewrote body:\n got %q\nwant %q", gotReq.Body, reqBody)
	}
	if strings.Contains(string(gotReq.Body), "host-telemetry-model") {
		t.Fatalf("host-selected model leaked into client body: %q", gotReq.Body)
	}
}

func TestEnclaveCoreDeniesUnauthorized(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auth: confidential.AuthorizeResult{Allowed: false, DenyReason: "invalid api key"}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	forwardCalled := false
	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		forward: func(_ context.Context, _ confidential.SelectedForwardRequest, _ enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			forwardCalled = true
			return confidential.UsageTelemetry{}, nil
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m"}`))
	r.Header.Set("Authorization", "Bearer bad")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code == http.StatusOK {
		t.Fatalf("denied request must not return 200, got %d", rec.Code)
	}
	if forwardCalled {
		t.Fatal("forward must not run when authorization is denied")
	}
}

func TestExtractAPIKey(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-abc")
	if got := extractAPIKey(h); got != "sk-abc" {
		t.Fatalf("bearer: got %q", got)
	}
	h2 := http.Header{}
	h2.Set("x-api-key", "sk-xyz")
	if got := extractAPIKey(h2); got != "sk-xyz" {
		t.Fatalf("x-api-key: got %q", got)
	}
}

func TestEnclaveCorePreDispatchErrorReturns502(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auth: confidential.AuthorizeResult{
		Allowed: true, AccountID: 5, ProviderID: "openai",
		EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-acct",
	}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		// forward fails before writing any header/body (e.g. policy or dispatch error).
		forward: func(_ context.Context, _ confidential.SelectedForwardRequest, _ enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			return confidential.UsageTelemetry{}, errors.New("dispatch failed")
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m"}`))
	r.Header.Set("Authorization", "Bearer sk-userkey")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("pre-dispatch forward error must return 502, got %d", rec.Code)
	}
	if stub.recordCalls != 0 {
		t.Fatalf("RecordUsage must not run on a pre-dispatch failure, calls=%d", stub.recordCalls)
	}
}

func TestEnclaveCoreRetriesPreDispatchFailureWithExcludedAccount(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auths: []confidential.AuthorizeResult{
		{Allowed: true, AccountID: 5, ProviderID: "openai", EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-first"},
		{Allowed: true, AccountID: 6, ProviderID: "openai", EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-second"},
	}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	var attempts []int64
	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		forward: func(_ context.Context, req confidential.SelectedForwardRequest, sink enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			attempts = append(attempts, req.AccountID)
			if req.AccountID == 5 {
				return confidential.UsageTelemetry{}, errors.New("connect failed")
			}
			sink.WriteHeader(http.StatusOK, map[string][]string{"Content-Type": {"text/event-stream"}})
			_ = sink.WriteChunk([]byte("data: ok\n\n"))
			return confidential.UsageTelemetry{AccountID: req.AccountID, OutputTokens: 11}, nil
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.3-codex","stream":true}`))
	r.Header.Set("Authorization", "Bearer sk-userkey")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: ok") {
		t.Fatalf("bad response after retry: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if len(attempts) != 2 || attempts[0] != 5 || attempts[1] != 6 {
		t.Fatalf("forward attempts = %v, want [5 6]", attempts)
	}
	if stub.authCalls != 2 {
		t.Fatalf("AuthorizeAndSelect calls = %d, want 2", stub.authCalls)
	}
	if len(stub.priorFailures) != 2 || len(stub.priorFailures[0]) != 0 || len(stub.priorFailures[1]) != 1 || stub.priorFailures[1][0] != 5 {
		t.Fatalf("prior failures = %+v, want [[], [5]]", stub.priorFailures)
	}
	if stub.recordCalls != 1 || stub.lastUsage.AccountID != 6 || stub.lastUsage.OutputTokens != 11 {
		t.Fatalf("usage after retry = calls=%d usage=%+v", stub.recordCalls, stub.lastUsage)
	}
}

func TestEnclaveCoreDoesNotRetryAfterResponseStarts(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	stub := &stubOrchestrator{auths: []confidential.AuthorizeResult{
		{Allowed: true, AccountID: 5, ProviderID: "openai", EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-first"},
		{Allowed: true, AccountID: 6, ProviderID: "openai", EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-second"},
	}}
	go confidential.Serve(c2, stub)
	caller := confidential.NewCaller(c1)

	app := &App{
		platform: "openai",
		dial:     func(context.Context) (rpcClient, func(), error) { return caller, func() {}, nil },
		forward: func(_ context.Context, req confidential.SelectedForwardRequest, sink enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			sink.WriteHeader(http.StatusOK, map[string][]string{"Content-Type": {"text/event-stream"}})
			_ = sink.WriteChunk([]byte("data: partial\n\n"))
			return confidential.UsageTelemetry{AccountID: req.AccountID, OutputTokens: 3}, errors.New("stream broke")
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.3-codex","stream":true}`))
	r.Header.Set("Authorization", "Bearer sk-userkey")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: partial") {
		t.Fatalf("partial stream should be returned without replay: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if stub.authCalls != 1 {
		t.Fatalf("mid-stream failure must not reselect/replay, auth calls=%d", stub.authCalls)
	}
	if stub.recordCalls != 1 || stub.lastUsage.AccountID != 5 || stub.lastUsage.OutputTokens != 3 {
		t.Fatalf("partial usage not recorded once: calls=%d usage=%+v", stub.recordCalls, stub.lastUsage)
	}
}

func TestEnclaveCoreRejectsOversizeBody(t *testing.T) {
	app := &App{
		platform: "openai",
		maxBody:  10,
		dial: func(context.Context) (rpcClient, func(), error) {
			t.Fatal("dial must not run for an oversize body")
			return nil, nil, nil
		},
		forward: func(_ context.Context, _ confidential.SelectedForwardRequest, _ enclave.ResponseSink) (confidential.UsageTelemetry, error) {
			t.Fatal("forward must not run for an oversize body")
			return confidential.UsageTelemetry{}, nil
		},
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(strings.Repeat("x", 20)))
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body must return 413, got %d", rec.Code)
	}
}
