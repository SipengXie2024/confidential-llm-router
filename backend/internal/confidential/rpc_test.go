//go:build unit

package confidential

import (
	"context"
	"net"
	"testing"
)

type stubHandler struct {
	auth      AuthorizeResult
	lastUsage UsageTelemetry
}

func (h *stubHandler) AuthorizeAndSelect(_ context.Context, _ string, _ RoutingNeeds, _ []int64) (AuthorizeResult, error) {
	return h.auth, nil
}

func (h *stubHandler) RecordUsage(_ context.Context, u UsageTelemetry) error {
	h.lastUsage = u
	return nil
}

func TestRPCRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	h := &stubHandler{auth: AuthorizeResult{Allowed: true, AccountID: 7, ProviderID: "openai", EndpointPolicyID: "openai-responses", Model: "gpt-5.3-codex", Credential: "sk-x"}}
	go Serve(c2, h)
	caller := NewCaller(c1)
	res, err := caller.AuthorizeAndSelect(context.Background(), "sk-userkey", RoutingNeeds{Model: "gpt-5.3-codex", Platform: "openai"}, nil)
	if err != nil || !res.Allowed || res.AccountID != 7 || res.Credential != "sk-x" {
		t.Fatalf("auth result wrong: %+v err=%v", res, err)
	}
	if err := caller.RecordUsage(context.Background(), UsageTelemetry{AccountID: 7, OutputTokens: 11}); err != nil {
		t.Fatal(err)
	}
	if h.lastUsage.OutputTokens != 11 {
		t.Fatalf("usage not received: %+v", h.lastUsage)
	}
}
