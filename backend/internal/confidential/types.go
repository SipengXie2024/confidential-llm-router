package confidential

type ProviderID = string
type EndpointPolicyID = string

type RoutingNeeds struct {
	Model     string `json:"model"`
	Platform  string `json:"platform"`
	SessionID string `json:"session_id,omitempty"`
}

type SelectedForwardRequest struct {
	ProviderID       ProviderID          `json:"provider_id"`
	EndpointPolicyID EndpointPolicyID    `json:"endpoint_policy_id"`
	AccountID        int64               `json:"account_id"`
	Model            string              `json:"model"` // effective upstream model (post host-side mapping)
	Stream           bool                `json:"stream"`
	Credential       string              `json:"credential"` // plaintext (MVP; goal③ credential-isolation deferred)
	Body             []byte              `json:"body"`
	Headers          map[string][]string `json:"headers"`
}

type UsageTelemetry struct {
	AccountID    int64  `json:"account_id"`
	Model        string `json:"model"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	Status       int    `json:"status"`
	LatencyMS    int64  `json:"latency_ms"`
}

type AuthorizeResult struct {
	Allowed          bool             `json:"allowed"`
	DenyReason       string           `json:"deny_reason,omitempty"`
	AccountID        int64            `json:"account_id"`
	ProviderID       ProviderID       `json:"provider_id"`
	EndpointPolicyID EndpointPolicyID `json:"endpoint_policy_id"`
	Model            string           `json:"model"`
	Credential       string           `json:"credential"`
}
