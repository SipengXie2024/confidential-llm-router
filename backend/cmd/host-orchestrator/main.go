// Command host-orchestrator serves the untrusted-host orchestrator for the
// confidential router data plane over vsock.
package main

//go:generate go run github.com/google/wire/cmd/wire

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/Wei-Shaw/sub2api/internal/orchestrator"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/mdlayher/vsock"
)

type keyAuth struct {
	keys *service.APIKeyService
}

func (a keyAuth) Authenticate(ctx context.Context, apiKey string) (orchestrator.KeyAuth, bool, error) {
	key, _, err := a.keys.ValidateKey(ctx, apiKey)
	if err != nil {
		// MVP: infra errors are intentionally conflated with auth failures and denied.
		return orchestrator.KeyAuth{}, false, nil
	}
	platform := ""
	if key.Group != nil {
		platform = key.Group.Platform
	}
	return orchestrator.KeyAuth{Platform: platform, GroupID: key.GroupID}, true, nil
}

type accountSelector struct {
	gw *service.OpenAIGatewayService
}

func (s accountSelector) Select(ctx context.Context, in orchestrator.SelectionInput) (orchestrator.Selection, error) {
	sel, _, err := s.gw.SelectAccountWithScheduler(
		ctx,
		in.GroupID,
		"",
		in.SessionHash,
		in.Model,
		in.ExcludedIDs,
		service.OpenAIUpstreamTransportHTTPSSE,
		false,
	)
	if err != nil {
		return orchestrator.Selection{}, err
	}
	if sel == nil || sel.Account == nil || sel.Account.ID <= 0 {
		return orchestrator.Selection{}, errors.New("openai account scheduler returned no account")
	}
	if sel.ReleaseFunc != nil {
		// MVP: confidential-path account concurrency limiting is relaxed after selection.
		sel.ReleaseFunc()
	}

	credential, _, err := s.gw.GetAccessToken(ctx, sel.Account)
	if err != nil {
		return orchestrator.Selection{}, fmt.Errorf("get openai credential: %w", err)
	}
	return orchestrator.Selection{
		AccountID:  sel.Account.ID,
		Credential: credential,
		// MVP: host-side model mapping for the confidential path is future work.
		Model: in.Model,
	}, nil
}

type usageLogger struct{}

func (usageLogger) RecordUsage(_ context.Context, u confidential.UsageTelemetry) error {
	// MVP: billing/quota persistence is deferred; host side records telemetry only in logs.
	log.Printf("host-orchestrator: usage account_id=%d model=%q input_tokens=%d output_tokens=%d status=%d latency_ms=%d",
		u.AccountID, u.Model, u.InputTokens, u.OutputTokens, u.Status, u.LatencyMS)
	return nil
}

func provideKeyAuthenticator(keys *service.APIKeyService) orchestrator.KeyAuthenticator {
	return keyAuth{keys: keys}
}

func provideAccountSelector(gw *service.OpenAIGatewayService) orchestrator.AccountSelector {
	return accountSelector{gw: gw}
}

func provideUsageRecorder() orchestrator.UsageRecorder {
	return usageLogger{}
}

func main() {
	// 9001, not 9000: nitro-cli reserves parent CID 3 port 9000 for the enclave-ready
	// heartbeat for the enclave's whole lifetime, so the RPC must use a different port.
	port := flag.Uint("vsock-port", 9001, "vsock port for enclave orchestrator RPC")
	flag.Parse()
	if *port > math.MaxUint32 {
		log.Fatalf("host-orchestrator: vsock port out of range: %d", *port)
	}

	svc, cleanup, err := initializeOrchestrator()
	if err != nil {
		log.Fatalf("host-orchestrator: initialize: %v", err)
	}
	defer cleanup()

	ln, err := vsock.Listen(uint32(*port), nil)
	if err != nil {
		log.Fatalf("host-orchestrator: listen vsock port %d: %v", *port, err)
	}
	defer ln.Close()

	quit := make(chan os.Signal, 1)
	closed := make(chan struct{})
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("host-orchestrator: shutting down")
		close(closed)
		_ = ln.Close()
	}()

	log.Printf("host-orchestrator: serving confidential RPC on vsock port %d", *port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-closed:
				return
			default:
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("host-orchestrator: accept: %v", err)
			continue
		}
		go func(c io.ReadWriteCloser) {
			if err := confidential.Serve(c, svc); err != nil {
				log.Printf("host-orchestrator: serve connection: %v", err)
			}
		}(conn)
	}
}
