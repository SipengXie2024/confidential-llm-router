//go:build unit

package orchestrator

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
)

type stubKeys struct {
	auth KeyAuth
	ok   bool
	err  error
}

func (s stubKeys) Authenticate(_ context.Context, _ string) (KeyAuth, bool, error) {
	return s.auth, s.ok, s.err
}

type stubSelector struct {
	sel      Selection
	err      error
	gotInput SelectionInput
}

func (s *stubSelector) Select(_ context.Context, in SelectionInput) (Selection, error) {
	s.gotInput = in
	return s.sel, s.err
}

type stubUsage struct {
	last confidential.UsageTelemetry
}

func (s *stubUsage) RecordUsage(_ context.Context, u confidential.UsageTelemetry) error {
	s.last = u
	return nil
}

func TestAuthorizeAndSelectValid(t *testing.T) {
	gid := int64(9)
	keys := stubKeys{auth: KeyAuth{Platform: "openai", GroupID: &gid}, ok: true}
	sel := &stubSelector{sel: Selection{AccountID: 5, Credential: "sk-acct", Model: "gpt-5.3-codex"}}
	svc := NewService(keys, sel, &stubUsage{})

	res, err := svc.AuthorizeAndSelect(context.Background(), "sk-userkey",
		confidential.RoutingNeeds{Model: "gpt-5.3-codex", SessionID: "sess1"}, []int64{7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed || res.AccountID != 5 || res.Credential != "sk-acct" {
		t.Fatalf("bad result: %+v", res)
	}
	if res.ProviderID != "openai" || res.EndpointPolicyID != "openai-responses" || res.Model != "gpt-5.3-codex" {
		t.Fatalf("bad routing fields: %+v", res)
	}
	if _, excluded := sel.gotInput.ExcludedIDs[7]; !excluded {
		t.Fatalf("priorFailures not passed as excluded: %+v", sel.gotInput.ExcludedIDs)
	}
	if sel.gotInput.SessionHash != "sess1" || sel.gotInput.GroupID == nil || *sel.gotInput.GroupID != 9 {
		t.Fatalf("selection input wrong: %+v", sel.gotInput)
	}
}

func TestAuthorizeAndSelectUnknownKey(t *testing.T) {
	svc := NewService(stubKeys{ok: false}, &stubSelector{}, &stubUsage{})
	res, err := svc.AuthorizeAndSelect(context.Background(), "bad", confidential.RoutingNeeds{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Fatal("unknown key must not be allowed")
	}
}

func TestAuthorizeAndSelectWrongPlatform(t *testing.T) {
	svc := NewService(stubKeys{auth: KeyAuth{Platform: "anthropic"}, ok: true}, &stubSelector{}, &stubUsage{})
	res, _ := svc.AuthorizeAndSelect(context.Background(), "sk", confidential.RoutingNeeds{}, nil)
	if res.Allowed {
		t.Fatal("non-openai platform must be denied in the MVP")
	}
}

func TestRecordUsageDelegates(t *testing.T) {
	u := &stubUsage{}
	svc := NewService(stubKeys{}, &stubSelector{}, u)
	if err := svc.RecordUsage(context.Background(), confidential.UsageTelemetry{AccountID: 5, OutputTokens: 3}); err != nil {
		t.Fatal(err)
	}
	if u.last.OutputTokens != 3 {
		t.Fatalf("usage not delegated: %+v", u.last)
	}
}
