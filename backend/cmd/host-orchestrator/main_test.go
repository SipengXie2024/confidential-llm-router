//go:build unit

package main

import (
	"context"
	"net"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/Wei-Shaw/sub2api/internal/orchestrator"
)

type stubKeyAuthenticator struct{}

func (stubKeyAuthenticator) Authenticate(_ context.Context, _ string) (orchestrator.KeyAuth, bool, error) {
	return orchestrator.KeyAuth{Platform: "openai"}, true, nil
}

type stubAccountSelector struct{}

func (stubAccountSelector) Select(_ context.Context, in orchestrator.SelectionInput) (orchestrator.Selection, error) {
	return orchestrator.Selection{
		AccountID:  42,
		Credential: "sk-account",
		Model:      in.Model,
	}, nil
}

type stubUsageRecorder struct{}

func (stubUsageRecorder) RecordUsage(_ context.Context, _ confidential.UsageTelemetry) error {
	return nil
}

func TestServeLoopSmoke(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	svc := orchestrator.NewService(stubKeyAuthenticator{}, stubAccountSelector{}, stubUsageRecorder{})
	go func() {
		_ = confidential.Serve(c2, svc)
	}()

	caller := confidential.NewCaller(c1)
	res, err := caller.AuthorizeAndSelect(
		context.Background(),
		"sk-user",
		confidential.RoutingNeeds{Platform: "openai", Model: "gpt-5.3-codex", SessionID: "sess"},
		nil,
	)
	if err != nil {
		t.Fatalf("AuthorizeAndSelect failed: %v", err)
	}
	if !res.Allowed || res.AccountID != 42 || res.Credential != "sk-account" || res.Model != "gpt-5.3-codex" {
		t.Fatalf("bad authorize result: %+v", res)
	}

	if err := caller.RecordUsage(context.Background(), confidential.UsageTelemetry{
		AccountID:    42,
		Model:        "gpt-5.3-codex",
		InputTokens:  3,
		OutputTokens: 5,
		Status:       200,
		LatencyMS:    17,
	}); err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}
}
