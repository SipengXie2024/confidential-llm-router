package enclave

import (
	"bytes"
	"testing"
)

type fuzzSink struct {
	chunks [][]byte
}

func (s *fuzzSink) WriteHeader(int, map[string][]string) {}

func (s *fuzzSink) WriteChunk(p []byte) error {
	s.chunks = append(s.chunks, append([]byte(nil), p...))
	return nil
}

func (s *fuzzSink) Close() {}

func FuzzRelayVerbatimFaithfulness(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"model":"gpt-5.3-codex","input":"hi"}`),
		[]byte(`{"tools":[{"type":"function","function":{"name":"bash","parameters":{"type":"object"}}}]}`),
		[]byte(`{"input":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}`),
		bytes.Repeat([]byte("x"), 4096),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip("bounded fuzz input")
		}
		sink := &fuzzSink{}
		if _, err := relayVerbatim(bytes.NewReader(body), sink); err != nil {
			t.Fatalf("relayVerbatim: %v", err)
		}
		if got := bytes.Join(sink.chunks, nil); !bytes.Equal(got, body) {
			t.Fatalf("verbatim relay changed body:\n got %q\nwant %q", got, body)
		}
	})
}

func FuzzRelaySSEFaithfulness(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n"),
		[]byte("event: response.output_text.delta\r\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\r\n\r\n"),
		[]byte("data: {\"type\":\"response.completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}\n\n"),
		[]byte("data: [DONE]\n\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 || hasOversizeSSELine(body) {
			t.Skip("bounded fuzz input")
		}
		sink := &fuzzSink{}
		if _, err := relaySSE(bytes.NewReader(body), sink); err != nil {
			t.Fatalf("relaySSE: %v", err)
		}
		if got := bytes.Join(sink.chunks, nil); !bytes.Equal(got, body) {
			t.Fatalf("SSE relay changed body:\n got %q\nwant %q", got, body)
		}
	})
}

func hasOversizeSSELine(body []byte) bool {
	lineLen := 0
	for _, b := range body {
		lineLen++
		if lineLen > maxSSELine {
			return true
		}
		if b == '\n' {
			lineLen = 0
		}
	}
	return false
}
