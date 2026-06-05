//go:build unit

package confidential

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
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

func TestAuthorizeArgsAreMetadataOnly(t *testing.T) {
	args := authorizeArgs{
		APIKey:        "sk-userkey",
		Needs:         RoutingNeeds{Model: "gpt-5.3-codex", Platform: "openai", SessionID: "sess1"},
		PriorFailures: []int64{7, 9},
	}
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal authorizeArgs: %v", err)
	}
	got := string(b)
	for _, forbidden := range []string{"body", "messages", "input", "tool_calls", "Authorization"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("authorize_and_select RPC carried request material %q in %s", forbidden, got)
		}
	}
	for _, want := range []string{"sk-userkey", "gpt-5.3-codex", "sess1", "prior_failures"} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize_and_select RPC missing metadata %q in %s", want, got)
		}
	}
}

func TestControlChannelSchemasExcludeBodyAndDestinationFields(t *testing.T) {
	forbidden := map[string]bool{
		"authorization":  true,
		"base_url":       true,
		"body":           true,
		"destination":    true,
		"headers":        true,
		"host":           true,
		"input":          true,
		"messages":       true,
		"path":           true,
		"request_body":   true,
		"response_body":  true,
		"tool_calls":     true,
		"url":            true,
		"upstream_url":   true,
		"upstream_host":  true,
		"upstream_path":  true,
		"provider_url":   true,
		"provider_host":  true,
		"provider_path":  true,
		"transform_body": true,
	}
	for _, tc := range []struct {
		name string
		v    any
	}{
		{name: "authorizeArgs", v: authorizeArgs{}},
		{name: "RoutingNeeds", v: RoutingNeeds{}},
		{name: "AuthorizeResult", v: AuthorizeResult{}},
		{name: "UsageTelemetry", v: UsageTelemetry{}},
	} {
		for _, field := range jsonFields(t, tc.v) {
			if forbidden[field] {
				t.Fatalf("%s exposes forbidden control-channel field %q", tc.name, field)
			}
		}
	}
}

func jsonFields(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		out = append(out, name)
	}
	return out
}
