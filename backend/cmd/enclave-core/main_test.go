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
	auth        confidential.AuthorizeResult
	lastUsage   confidential.UsageTelemetry
	recordCalls int
}

func (s *stubOrchestrator) AuthorizeAndSelect(_ context.Context, _ string, _ confidential.RoutingNeeds, _ []int64) (confidential.AuthorizeResult, error) {
	return s.auth, nil
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
