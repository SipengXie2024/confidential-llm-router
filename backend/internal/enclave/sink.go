package enclave

import "net/http"

// ResponseSink receives an upstream response (status, headers, then streamed body
// chunks) and relays it verbatim to the client. It is the only way ForwardSelected
// emits bytes, which keeps the enclave forwarding path transport-agnostic and testable.
type ResponseSink interface {
	WriteHeader(status int, headers map[string][]string)
	WriteChunk(p []byte) error
	Close()
}

type httpSink struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func NewHTTPSink(w http.ResponseWriter) ResponseSink {
	f, _ := w.(http.Flusher)
	return &httpSink{w: w, flusher: f}
}

func (s *httpSink) WriteHeader(status int, headers map[string][]string) {
	h := s.w.Header()
	for k, vs := range headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	s.w.WriteHeader(status)
}

func (s *httpSink) WriteChunk(p []byte) error {
	if _, err := s.w.Write(p); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

func (s *httpSink) Close() {}
