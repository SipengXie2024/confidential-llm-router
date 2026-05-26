//go:build unit

package confidential

import "testing"

func TestProviderPolicyResolveOpenAI(t *testing.T) {
	p, ok := ResolvePolicy("openai", "openai-responses")
	if !ok {
		t.Fatal("expected openai-responses policy")
	}
	if p.BaseURL != "https://api.openai.com" {
		t.Fatalf("bad base url %q", p.BaseURL)
	}
	if p.Path != "/v1/responses" {
		t.Fatalf("bad path %q", p.Path)
	}
	if !p.AllowsHost("api.openai.com") || p.AllowsHost("evil.example.com") {
		t.Fatal("host allowlist wrong")
	}
	if _, ok := ResolvePolicy("openai", "attacker"); ok {
		t.Fatal("unknown policy must be rejected")
	}
}
