//go:build wireinject
// +build wireinject

package main

//go:generate go run github.com/google/wire/cmd/wire

import (
	"context"
	"log"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/orchestrator"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
)

func initializeOrchestrator() (*orchestrator.Service, func(), error) {
	wire.Build(
		config.ProviderSet,
		repository.ProviderSet,
		service.ProviderSet,
		provideKeyAuthenticator,
		provideAccountSelector,
		provideUsageRecorderWithCleanup,
		orchestrator.NewService,
		provideCleanup,
	)
	return nil, nil, nil
}

type cleanupAnchor struct{}

func provideUsageRecorderWithCleanup(_ *cleanupAnchor) orchestrator.UsageRecorder {
	return provideUsageRecorder()
}

func provideCleanup(
	entClient *ent.Client,
	rdb *redis.Client,
	timingWheel *service.TimingWheelService,
	schedulerSnapshot *service.SchedulerSnapshotService,
	deferred *service.DeferredService,
	pricing *service.PricingService,
	billingCache *service.BillingCacheService,
	openAIGateway *service.OpenAIGatewayService,
	openAIOAuth *service.OpenAIOAuthService,
) (*cleanupAnchor, func(), error) {
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		steps := []struct {
			name string
			fn   func() error
		}{
			{"OpenAIWSPool", func() error {
				if openAIGateway != nil {
					openAIGateway.CloseOpenAIWSPool()
				}
				return nil
			}},
			{"SchedulerSnapshotService", func() error {
				if schedulerSnapshot != nil {
					schedulerSnapshot.Stop()
				}
				return nil
			}},
			{"DeferredService", func() error {
				if deferred != nil {
					deferred.Stop()
				}
				return nil
			}},
			{"PricingService", func() error {
				if pricing != nil {
					pricing.Stop()
				}
				return nil
			}},
			{"BillingCacheService", func() error {
				if billingCache != nil {
					billingCache.Stop()
				}
				return nil
			}},
			{"OpenAIOAuthService", func() error {
				if openAIOAuth != nil {
					openAIOAuth.Stop()
				}
				return nil
			}},
			{"TimingWheelService", func() error {
				if timingWheel != nil {
					timingWheel.Stop()
				}
				return nil
			}},
			{"Redis", func() error {
				if rdb == nil {
					return nil
				}
				return rdb.Close()
			}},
			{"Ent", func() error {
				if entClient == nil {
					return nil
				}
				return entClient.Close()
			}},
		}

		for _, step := range steps {
			if err := step.fn(); err != nil {
				log.Printf("[Cleanup] %s failed: %v", step.name, err)
				continue
			}
			log.Printf("[Cleanup] %s succeeded", step.name)
		}

		select {
		case <-ctx.Done():
			log.Printf("[Cleanup] Warning: cleanup timed out after 10 seconds")
		default:
			log.Printf("[Cleanup] All cleanup steps completed")
		}
	}
	return &cleanupAnchor{}, cleanup, nil
}
