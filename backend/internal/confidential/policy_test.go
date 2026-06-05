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

func TestProviderPolicyResolveProviderDiversity(t *testing.T) {
	openrouter, ok := ResolvePolicy("openrouter", "chat-completions")
	if !ok {
		t.Fatal("expected openrouter chat-completions policy")
	}
	if openrouter.BaseURL != "https://openrouter.ai" || openrouter.Path != "/api/v1/chat/completions" {
		t.Fatalf("bad openrouter destination: %+v", openrouter)
	}
	gemini, ok := ResolvePolicy("gemini", "generate-content-gemini-2.5-flash")
	if !ok {
		t.Fatal("expected gemini generateContent policy")
	}
	if gemini.BaseURL != "https://generativelanguage.googleapis.com" ||
		gemini.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("bad gemini destination: %+v", gemini)
	}
}

func TestDefaultPolicyForPlatform(t *testing.T) {
	cases := map[string]struct {
		provider string
		endpoint string
	}{
		"openai":     {"openai", "openai-responses"},
		"openrouter": {"openrouter", "chat-completions"},
		"gemini":     {"gemini", "generate-content-gemini-2.5-flash"},
	}
	for platform, want := range cases {
		provider, endpoint, ok := DefaultPolicyForPlatform(platform)
		if !ok || provider != want.provider || endpoint != want.endpoint {
			t.Fatalf("DefaultPolicyForPlatform(%q) = %q/%q ok=%v, want %q/%q",
				platform, provider, endpoint, ok, want.provider, want.endpoint)
		}
	}
	if _, _, ok := DefaultPolicyForPlatform("anthropic"); ok {
		t.Fatal("unsupported platform must not map to a measured policy")
	}
}
