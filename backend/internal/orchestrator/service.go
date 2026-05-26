package orchestrator

import (
	"context"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
)

// KeyAuthenticator authenticates a gateway-issued user API key and resolves its group.
// The real implementation (cmd/host-orchestrator) wraps service.APIKeyService.ValidateKey;
// the key is relayed verbatim because the host issued and stores it.
type KeyAuthenticator interface {
	Authenticate(ctx context.Context, apiKey string) (KeyAuth, bool, error)
}

type KeyAuth struct {
	Platform string
	GroupID  *int64
}

// AccountSelector runs the host's account scheduler on non-secret routing metadata and
// returns the chosen account. The real implementation wraps the OpenAI scheduler and owns
// the concurrency-slot lifecycle.
type AccountSelector interface {
	Select(ctx context.Context, in SelectionInput) (Selection, error)
}

type SelectionInput struct {
	GroupID     *int64
	Model       string
	SessionHash string
	ExcludedIDs map[int64]struct{}
}

type Selection struct {
	AccountID  int64
	Credential string
	Model      string // effective upstream model (post host-side mapping)
}

// UsageRecorder persists token usage for billing on the host.
type UsageRecorder interface {
	RecordUsage(ctx context.Context, u confidential.UsageTelemetry) error
}

// Service implements confidential.Handler on the host: authenticate the relayed user key,
// enforce the MVP single-platform constraint, select an account on non-secret metadata,
// and record usage. It holds no gin and no datastore — those live behind the injected
// interfaces, wired to the real services in cmd/host-orchestrator.
type Service struct {
	keys     KeyAuthenticator
	selector AccountSelector
	usage    UsageRecorder
}

var _ confidential.Handler = (*Service)(nil)

func NewService(keys KeyAuthenticator, selector AccountSelector, usage UsageRecorder) *Service {
	return &Service{keys: keys, selector: selector, usage: usage}
}

func (s *Service) AuthorizeAndSelect(ctx context.Context, apiKey string, n confidential.RoutingNeeds, priorFailures []int64) (confidential.AuthorizeResult, error) {
	auth, ok, err := s.keys.Authenticate(ctx, apiKey)
	if err != nil {
		return confidential.AuthorizeResult{}, err
	}
	if !ok {
		return confidential.AuthorizeResult{Allowed: false, DenyReason: "invalid api key"}, nil
	}
	if auth.Platform != "openai" {
		return confidential.AuthorizeResult{Allowed: false, DenyReason: "unsupported platform: " + auth.Platform}, nil
	}

	excluded := make(map[int64]struct{}, len(priorFailures))
	for _, id := range priorFailures {
		excluded[id] = struct{}{}
	}
	sel, err := s.selector.Select(ctx, SelectionInput{
		GroupID:     auth.GroupID,
		Model:       n.Model,
		SessionHash: n.SessionID,
		ExcludedIDs: excluded,
	})
	if err != nil {
		return confidential.AuthorizeResult{}, err
	}
	return confidential.AuthorizeResult{
		Allowed:          true,
		AccountID:        sel.AccountID,
		ProviderID:       "openai",
		EndpointPolicyID: "openai-responses",
		Model:            sel.Model,
		Credential:       sel.Credential,
	}, nil
}

func (s *Service) RecordUsage(ctx context.Context, u confidential.UsageTelemetry) error {
	return s.usage.RecordUsage(ctx, u)
}
