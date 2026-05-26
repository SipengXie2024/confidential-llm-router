//go:build unit

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSidecarProxiesAfterVerify(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "from enclave: "+r.URL.Path)
	}))
	defer backend.Close()

	s := &Sidecar{
		enclaveURL: backend.URL,
		verify: func(context.Context) (http.RoundTripper, error) {
			return http.DefaultTransport, nil // attestation "passed" in the test
		},
	}
	h, err := s.handler(context.Background())
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("{}"))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "from enclave: /v1/responses") {
		t.Fatalf("proxy failed: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestSidecarFailsClosedOnVerifyError(t *testing.T) {
	s := &Sidecar{
		enclaveURL: "https://127.0.0.1:1",
		verify: func(context.Context) (http.RoundTripper, error) {
			return nil, errors.New("PCR0 mismatch")
		},
	}
	if _, err := s.handler(context.Background()); err == nil {
		t.Fatal("must fail closed (no proxy) when attestation verification fails")
	}
}
