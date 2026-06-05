//go:build unit

package confidential

import (
	"encoding/json"
	"testing"
)

func TestSelectedForwardRequestRoundTrip(t *testing.T) {
	r := SelectedForwardRequest{
		ProviderID: "openai", EndpointPolicyID: "openai-responses",
		AccountID: 42, Model: "gpt-5.3-codex", Stream: true,
		Credential: "sk-secret", Body: []byte(`{"model":"x"}`),
		Headers: map[string][]string{"Anthropic-Version": {"2023-06-01"}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got SelectedForwardRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ProviderID != r.ProviderID || got.AccountID != r.AccountID || string(got.Body) != string(r.Body) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
