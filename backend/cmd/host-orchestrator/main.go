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
	"net"
	"os"
	"os/signal"
	"strings"
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
	if in.Platform != "" && in.Platform != service.PlatformOpenAI {
		return selectEnvProvider(in)
	}
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

type staticKeyAuth struct {
	keys map[string]string
}

func (a staticKeyAuth) Authenticate(_ context.Context, apiKey string) (orchestrator.KeyAuth, bool, error) {
	platform, ok := a.keys[apiKey]
	if !ok {
		return orchestrator.KeyAuth{}, false, nil
	}
	return orchestrator.KeyAuth{Platform: platform}, true, nil
}

type envAccountSelector struct{}

func (envAccountSelector) Select(_ context.Context, in orchestrator.SelectionInput) (orchestrator.Selection, error) {
	return selectEnvProvider(in)
}

func selectEnvProvider(in orchestrator.SelectionInput) (orchestrator.Selection, error) {
	var credential, model string
	switch in.Platform {
	case service.PlatformOpenAI:
		credential = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
		model = firstNonEmpty(in.Model, os.Getenv("OPENAI_MODEL"), "gpt-4o-mini")
	case "openrouter":
		credential = strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
		model = firstNonEmpty(in.Model, os.Getenv("OPENROUTER_MODEL"), "openai/gpt-4o-mini")
	case service.PlatformGemini:
		credential = strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
		model = firstNonEmpty(in.Model, os.Getenv("GEMINI_MODEL"), "gemini-2.5-flash")
	default:
		return orchestrator.Selection{}, fmt.Errorf("unsupported eval platform: %s", in.Platform)
	}
	if credential == "" {
		return orchestrator.Selection{}, fmt.Errorf("missing provider credential for platform %s", in.Platform)
	}
	return orchestrator.Selection{AccountID: 0, Credential: credential, Model: model}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
	tcpRPCListen := flag.String("tcp-rpc-listen", "", "optional bench-only TCP listen address for confidential RPC")
	flag.Parse()
	if *port > math.MaxUint32 {
		log.Fatalf("host-orchestrator: vsock port out of range: %d", *port)
	}
	if *port == 0 && *tcpRPCListen == "" {
		log.Fatal("host-orchestrator: at least one of -vsock-port or -tcp-rpc-listen is required")
	}

	svc, cleanup, err := initializeEvalOrchestratorFromEnv()
	if err != nil {
		log.Fatalf("host-orchestrator: initialize eval mode: %v", err)
	}
	if svc == nil {
		svc, cleanup, err = initializeOrchestrator()
	}
	if err != nil {
		log.Fatalf("host-orchestrator: initialize: %v", err)
	}
	defer cleanup()

	if *tcpRPCListen == "" {
		serveDefaultVsock(uint32(*port), svc)
		return
	}
	serveWithTCP(uint32(*port), *tcpRPCListen, svc)
}

func initializeEvalOrchestratorFromEnv() (*orchestrator.Service, func(), error) {
	if strings.TrimSpace(os.Getenv("CONFIDENTIAL_EVAL_MODE")) == "" {
		return nil, nil, nil
	}
	keys := make(map[string]string)
	add := func(envName, platform string) {
		if key := strings.TrimSpace(os.Getenv(envName)); key != "" {
			keys[key] = platform
		}
	}
	if key := strings.TrimSpace(os.Getenv("CONFIDENTIAL_EVAL_GATEWAY_KEY")); key != "" {
		platform := firstNonEmpty(os.Getenv("CONFIDENTIAL_EVAL_PLATFORM"), service.PlatformOpenAI)
		keys[key] = platform
	}
	add("CONFIDENTIAL_EVAL_OPENAI_GATEWAY_KEY", service.PlatformOpenAI)
	add("CONFIDENTIAL_EVAL_OPENROUTER_GATEWAY_KEY", "openrouter")
	add("CONFIDENTIAL_EVAL_GEMINI_GATEWAY_KEY", service.PlatformGemini)
	if len(keys) == 0 {
		return nil, nil, errors.New("CONFIDENTIAL_EVAL_MODE is set but no eval gateway key is configured")
	}
	log.Printf("host-orchestrator: confidential eval mode enabled with %d gateway key(s)", len(keys))
	return orchestrator.NewService(staticKeyAuth{keys: keys}, envAccountSelector{}, usageLogger{}), func() {}, nil
}

func serveDefaultVsock(port uint32, svc confidential.Handler) {
	ln, err := vsock.Listen(port, nil)
	if err != nil {
		log.Fatalf("host-orchestrator: listen vsock port %d: %v", port, err)
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

	log.Printf("host-orchestrator: serving confidential RPC on vsock port %d", port)
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

func serveWithTCP(port uint32, tcpRPCListen string, svc confidential.Handler) {
	var vsockLn net.Listener
	if port != 0 {
		ln, err := vsock.Listen(port, nil)
		if err != nil {
			log.Fatalf("host-orchestrator: listen vsock port %d: %v", port, err)
		}
		vsockLn = ln
		defer ln.Close()
		go serveVsock(port, ln, svc)
	}

	tcpLn, err := net.Listen("tcp", tcpRPCListen)
	if err != nil {
		log.Fatalf("host-orchestrator: listen TCP %s: %v", tcpRPCListen, err)
	}
	defer tcpLn.Close()
	go serveTCP(tcpLn.Addr().String(), tcpLn, svc)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("host-orchestrator: shutting down")
	_ = tcpLn.Close()
	if vsockLn != nil {
		_ = vsockLn.Close()
	}
}

func serveVsock(port uint32, ln net.Listener, svc confidential.Handler) {
	log.Printf("host-orchestrator: serving confidential RPC on vsock port %d", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
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

func serveTCP(addr string, ln net.Listener, svc confidential.Handler) {
	log.Printf("host-orchestrator: serving confidential RPC on TCP %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("host-orchestrator: accept TCP: %v", err)
			continue
		}
		go func(c io.ReadWriteCloser) {
			if err := confidential.Serve(c, svc); err != nil {
				log.Printf("host-orchestrator: serve TCP connection: %v", err)
			}
		}(conn)
	}
}
