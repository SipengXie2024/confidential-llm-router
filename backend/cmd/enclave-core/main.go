// Command enclave-core is the nitriding -appwebsrv application that runs inside the Nitro
// enclave. Per request it authorizes + selects an account on the untrusted host orchestrator
// over vsock, runs the in-enclave OpenAI passthrough, and reports usage back. It must never
// import internal/service (TCB minimization) — only internal/enclave + internal/confidential.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/confidential"
	"github.com/Wei-Shaw/sub2api/internal/enclave"
	"github.com/mdlayher/vsock"
	"github.com/tidwall/gjson"
)

const maxRequestBody = 64 << 20

// rpcClient is the subset of confidential.Caller the app needs; an interface so tests can
// inject a net.Pipe-backed caller instead of a real vsock connection.
type rpcClient interface {
	AuthorizeAndSelect(ctx context.Context, apiKey string, n confidential.RoutingNeeds, priorFailures []int64) (confidential.AuthorizeResult, error)
	RecordUsage(ctx context.Context, u confidential.UsageTelemetry) error
}

type forwardFunc func(context.Context, confidential.SelectedForwardRequest, enclave.ResponseSink) (confidential.UsageTelemetry, error)

// App is the enclave-core HTTP application. dial and forward are injected so the request
// path is testable without a live vsock connection or a real upstream.
type App struct {
	platform string
	dial     func(ctx context.Context) (rpcClient, func(), error)
	forward  forwardFunc
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body")
		return
	}
	needs := confidential.RoutingNeeds{
		Model:     gjson.GetBytes(body, "model").String(),
		Platform:  a.platform,
		SessionID: r.Header.Get("session_id"),
	}

	client, cleanup, err := a.dial(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "orchestrator unavailable")
		return
	}
	defer cleanup()

	auth, err := client.AuthorizeAndSelect(r.Context(), extractAPIKey(r.Header), needs, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authorize: "+err.Error())
		return
	}
	if !auth.Allowed {
		reason := auth.DenyReason
		if reason == "" {
			reason = "request denied"
		}
		writeError(w, http.StatusForbidden, reason)
		return
	}

	req := confidential.SelectedForwardRequest{
		ProviderID:       auth.ProviderID,
		EndpointPolicyID: auth.EndpointPolicyID,
		AccountID:        auth.AccountID,
		Model:            auth.Model,
		Stream:           gjson.GetBytes(body, "stream").Bool(),
		Credential:       auth.Credential,
		Body:             body,
		Headers:          r.Header,
	}
	usage, ferr := a.forward(r.Context(), req, enclave.NewHTTPSink(w))
	if ferr != nil {
		// Status + partial body are already on the wire; only logging is left.
		log.Printf("enclave-core: forward error (account=%d): %v", auth.AccountID, ferr)
	}
	if err := client.RecordUsage(r.Context(), usage); err != nil {
		log.Printf("enclave-core: record usage failed (account=%d): %v", auth.AccountID, err)
	}
}

// extractAPIKey pulls the gateway-issued user key from the inbound request. It is relayed
// verbatim to the host (which issued it); the enclave does not hash or transform it.
func extractAPIKey(h http.Header) string {
	if v := strings.TrimSpace(h.Get("Authorization")); v != "" {
		return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	}
	return strings.TrimSpace(h.Get("x-api-key"))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"message":%q,"type":"confidential_router_error"}}`, msg)
}

func main() {
	var (
		listenAddr string
		vsockCID   uint
		vsockPort  uint
		intPort    uint
	)
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8081", "appwebsrv listen address")
	flag.UintVar(&vsockCID, "vsock-cid", 3, "host orchestrator vsock context id (Nitro parent = 3)")
	flag.UintVar(&vsockPort, "vsock-port", 9000, "host orchestrator vsock port")
	flag.UintVar(&intPort, "intport", 8080, "nitriding internal port for readiness signal")
	flag.Parse()

	app := &App{
		platform: "openai",
		dial: func(context.Context) (rpcClient, func(), error) {
			conn, err := vsock.Dial(uint32(vsockCID), uint32(vsockPort), nil)
			if err != nil {
				return nil, nil, err
			}
			return confidential.NewCaller(conn), func() { _ = conn.Close() }, nil
		},
		forward: enclave.ForwardSelected,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("enclave-core: listen %s: %v", listenAddr, err)
	}
	go signalReady(intPort)

	log.Printf("enclave-core: serving on %s, orchestrator vsock %d:%d", listenAddr, vsockCID, vsockPort)
	srv := &http.Server{Handler: app, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("enclave-core: serve: %v", err)
	}
}

// signalReady tells nitriding (on the internal port) the app is up, so it starts
// terminating client RA-TLS and proxying to this app.
func signalReady(intPort uint) {
	url := fmt.Sprintf("http://127.0.0.1:%d/enclave/ready", intPort)
	client := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < 30; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			log.Printf("enclave-core: signaled nitriding ready (%d)", resp.StatusCode)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("enclave-core: could not signal nitriding ready at %s", url)
}
