package confidential

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const (
	methodAuthorizeAndSelect = "authorize_and_select"
	methodRecordUsage        = "record_usage"

	// maxFrameLen caps a single RPC frame. The enclave (Caller) reads replies from the
	// UNTRUSTED host, so this bound is a real defense: it stops a malicious host from
	// announcing a huge length prefix to exhaust enclave memory.
	maxFrameLen = 16 << 20
)

// Handler is implemented on the host side (orchestrator) and invoked over vsock by the
// enclave. apiKey is the gateway-issued user key relayed verbatim (the host issued it and
// stores it, so there is nothing to hide); the host authenticates it and returns the
// selected account + plaintext provider credential (goal③ credential-isolation deferred).
type Handler interface {
	AuthorizeAndSelect(ctx context.Context, apiKey string, n RoutingNeeds, priorFailures []int64) (AuthorizeResult, error)
	RecordUsage(ctx context.Context, u UsageTelemetry) error
}

type rpcRequest struct {
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload"`
}

type rpcReply struct {
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type authorizeArgs struct {
	APIKey        string       `json:"api_key"`
	Needs         RoutingNeeds `json:"needs"`
	PriorFailures []int64      `json:"prior_failures,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrameLen {
		return fmt.Errorf("rpc frame too large: %d bytes", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameLen {
		return fmt.Errorf("rpc frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// Caller is the enclave-side RPC client. It is safe for concurrent use; calls are
// serialized so request/reply frames never interleave on the single connection.
type Caller struct {
	mu   sync.Mutex
	conn io.ReadWriteCloser
}

func NewCaller(conn io.ReadWriteCloser) *Caller {
	return &Caller{conn: conn}
}

func (c *Caller) call(method string, args any, out any) error {
	payload, err := json.Marshal(args)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFrame(c.conn, rpcRequest{Method: method, Payload: payload}); err != nil {
		return err
	}
	var rep rpcReply
	if err := readFrame(c.conn, &rep); err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("rpc %s: %s", method, rep.Error)
	}
	if out != nil {
		return json.Unmarshal(rep.Payload, out)
	}
	return nil
}

func (c *Caller) AuthorizeAndSelect(_ context.Context, apiKey string, n RoutingNeeds, priorFailures []int64) (AuthorizeResult, error) {
	var res AuthorizeResult
	err := c.call(methodAuthorizeAndSelect, authorizeArgs{APIKey: apiKey, Needs: n, PriorFailures: priorFailures}, &res)
	return res, err
}

func (c *Caller) RecordUsage(_ context.Context, u UsageTelemetry) error {
	return c.call(methodRecordUsage, u, nil)
}

// Serve runs the host-side RPC loop on a single connection until it closes or errors.
// One goroutine per connection; the caller starts it (e.g. per vsock Accept).
func Serve(conn io.ReadWriteCloser, h Handler) error {
	defer conn.Close()
	for {
		var req rpcRequest
		if err := readFrame(conn, &req); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := writeFrame(conn, dispatch(context.Background(), h, req)); err != nil {
			return err
		}
	}
}

func dispatch(ctx context.Context, h Handler, req rpcRequest) rpcReply {
	switch req.Method {
	case methodAuthorizeAndSelect:
		var args authorizeArgs
		if err := json.Unmarshal(req.Payload, &args); err != nil {
			return rpcReply{Error: err.Error()}
		}
		res, err := h.AuthorizeAndSelect(ctx, args.APIKey, args.Needs, args.PriorFailures)
		if err != nil {
			return rpcReply{Error: err.Error()}
		}
		b, err := json.Marshal(res)
		if err != nil {
			return rpcReply{Error: err.Error()}
		}
		return rpcReply{OK: true, Payload: b}
	case methodRecordUsage:
		var u UsageTelemetry
		if err := json.Unmarshal(req.Payload, &u); err != nil {
			return rpcReply{Error: err.Error()}
		}
		if err := h.RecordUsage(ctx, u); err != nil {
			return rpcReply{Error: err.Error()}
		}
		return rpcReply{OK: true}
	default:
		return rpcReply{Error: fmt.Sprintf("unknown method %q", req.Method)}
	}
}
