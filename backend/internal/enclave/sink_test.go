//go:build unit

package enclave

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPSinkStreams(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewHTTPSink(rec)
	s.WriteHeader(200, map[string][]string{"Content-Type": {"text/event-stream"}})
	s.WriteChunk([]byte("data: a\n\n"))
	s.WriteChunk([]byte("data: b\n\n"))
	if rec.Code != 200 || rec.Body.String() != "data: a\n\ndata: b\n\n" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}
