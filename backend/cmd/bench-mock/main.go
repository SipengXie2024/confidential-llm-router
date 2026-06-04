// Command bench-mock is a local HTTPS echo/SSE upstream used only for relay-overhead
// benchmarking. It stands in for api.openai.com so Aegis's machinery cost can be isolated
// from provider compute + network variance. It serves real TLS from a private-CA cert and
// returns immediately (no artificial latency) with a small fixed OpenAI-style Responses SSE
// stream whose terminal event carries a usage object, so the enclave relay exercises its
// real SSE relay + usage-extraction path.
//
// It deliberately does NOT log request headers or bodies: the Authorization header carries
// the real upstream credential selected by the host, and must never be written anywhere.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

// fixedSSE mirrors an OpenAI Responses streamed completion closely enough for the relay's
// parseSSEUsage (terminal type + response.usage) and the client's response.completed check.
const fixedSSE = "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_bench\"}}\n\n" +
	"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n" +
	"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n\n" +
	"data: [DONE]\n\n"

func main() {
	var listen, cert, key string
	flag.StringVar(&listen, "listen", "0.0.0.0:8443", "HTTPS listen address")
	flag.StringVar(&cert, "cert", "mock.pem", "server certificate (PEM)")
	flag.StringVar(&key, "key", "mock.key", "server private key (PEM)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		// Drain and discard the request body without logging it (it is the relayed prompt).
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, fixedSSE)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("bench-mock: serving HTTPS on %s (cert=%s)", listen, cert)
	log.Fatal(srv.ListenAndServeTLS(cert, key))
}
