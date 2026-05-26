package confidential

// ProviderPolicy is the enclave-owned, baked-in routing table. The untrusted host
// can only name a (ProviderID, EndpointPolicyID) pair; it can never supply a base_url
// or host, so it cannot redirect the client's plaintext to an off-policy destination
// (goal ①). request_transform is CODE in internal/enclave (never host-supplied);
// only model-mapping is DATA passed from the host.
type ProviderPolicy struct {
	ProviderID       ProviderID
	EndpointPolicyID EndpointPolicyID
	BaseURL          string
	Path             string   // canonical upstream path; the host/client cannot choose it (goal①)
	AllowedHosts     []string // exact SNI/host pins
}

func (p ProviderPolicy) AllowsHost(h string) bool {
	for _, a := range p.AllowedHosts {
		if a == h {
			return true
		}
	}
	return false
}

var policies = map[string]ProviderPolicy{
	"openai/openai-responses": {
		ProviderID:       "openai",
		EndpointPolicyID: "openai-responses",
		BaseURL:          "https://api.openai.com",
		Path:             "/v1/responses",
		AllowedHosts:     []string{"api.openai.com"},
	},
}

func ResolvePolicy(pid ProviderID, eid EndpointPolicyID) (ProviderPolicy, bool) {
	p, ok := policies[pid+"/"+eid]
	return p, ok
}
