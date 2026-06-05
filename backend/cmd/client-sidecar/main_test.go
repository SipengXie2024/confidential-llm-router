//go:build unit

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSidecarProxiesAfterVerify(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = io.WriteString(w, "from enclave: "+r.URL.Path)
	}))
	defer backend.Close()

	wantHost := ""
	if u, err := url.Parse(backend.URL); err == nil {
		wantHost = u.Host
	}

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
	if gotHost != wantHost {
		t.Fatalf("Host not rewritten to enclave host: got %q want %q", gotHost, wantHost)
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

func TestSidecarRejectsPathInEnclaveURL(t *testing.T) {
	s := &Sidecar{
		enclaveURL: "https://enclave.example/some/path",
		verify: func(context.Context) (http.RoundTripper, error) {
			t.Fatal("verify must not run when the enclave-url is invalid")
			return nil, nil
		},
	}
	if _, err := s.handler(context.Background()); err == nil {
		t.Fatal("path-bearing enclave-url must be rejected")
	}
}

func TestPinnedTransportRejectsCertificateRotationBeforeRequest(t *testing.T) {
	rotatedReached := false
	rotated := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rotatedReached = true
		t.Fatal("rotated enclave certificate must fail the pin before HTTP request handling")
	}))
	defer rotated.Close()

	attestedCertDER := []byte("synthetic attested certificate hash source, different from rotated server cert")
	client := &http.Client{Transport: pinnedEnclaveTransport("router.local", attestedCertDER)}
	req, err := http.NewRequest(http.MethodPost, rotated.URL+"/v1/responses", strings.NewReader(`{"input":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "certificate changed") {
		t.Fatalf("rotated cert must fail closed with pin mismatch, got resp=%v err=%v", resp, err)
	}
	if rotatedReached {
		t.Fatal("rotated server received request body despite pin mismatch")
	}
}
