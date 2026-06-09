#!/usr/bin/env python3
"""Per-event SSE timing client for the Aegis TTFT experiment.

Sends ONE streaming request (OpenAI Responses API shape) and records, on a
monotonic clock, the wall-time of the request being sent and the arrival of
every SSE event. Emits a single JSON line describing the timing.

It deliberately uses only the Python stdlib (http.client + ssl) so there is no
dependency surface, and so that no buffering library sits between us and the
socket and distorts the per-chunk arrival timestamps.

TTFT  = request-sent -> first event carrying output-text increment
        (Responses API: type == "response.output_text.delta").
first_event = request-sent -> first SSE data event of ANY type (kept for cross-check).
inter_chunk = differences between consecutive output-text delta arrivals.

Secrets: the prompt text, request body, and Authorization headers are NEVER
printed. Only timing/shape metrics go to stdout.
"""
import argparse
import http.client
import json
import ssl
import sys
import time
from urllib.parse import urlsplit

OUTPUT_DELTA = "response.output_text.delta"
# A capped stream terminates as "incomplete" (max_output_tokens hit) rather than
# "completed"; both carry response.usage, so treat both as the terminal event.
TERMINAL = ("response.completed", "response.incomplete")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--header", action="append", default=[],
                   help="Header as 'Name: value'. Repeatable. Not echoed.")
    p.add_argument("--body-file", required=True,
                   help="Path to a file holding the raw JSON request body.")
    p.add_argument("--arm", required=True)
    p.add_argument("--provider", required=True)
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--wall-ts", default="")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--debug-events", action="store_true",
                   help="Print the set of SSE event types seen to stderr.")
    return p.parse_args()


def make_conn(url, timeout):
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme == "https":
        port = parts.port or 443
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        port = parts.port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return conn, path, host


def main():
    a = parse_args()
    with open(a.body_file, "rb") as f:
        body = f.read()

    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    for h in a.header:
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    rec = {
        "arm": a.arm,
        "provider": a.provider,
        "index": a.index,
        "model": a.model,
        "wall_ts": a.wall_ts,
        "ttft_ms": None,
        "first_event_ms": None,
        "total_stream_ms": None,
        "n_chunks": 0,
        "n_output_tokens": None,
        "inter_chunk_ms": [],
        "http_code": None,
        "ok": False,
        "error": None,
    }

    conn, path, host = make_conn(a.url, a.timeout)
    delta_times = []
    first_event_t = None
    last_event_t = None
    event_types = {}
    cur_event = None  # from "event:" line, fallback when data has no "type"

    try:
        conn.request("POST", path, body=body, headers=headers)
        t0 = time.monotonic()
        resp = conn.getresponse()
        rec["http_code"] = resp.status

        if resp.status < 200 or resp.status >= 300:
            # Drain a little for diagnostics; do not echo secrets/full body.
            snippet = resp.read(512)
            rec["error"] = "http_%d" % resp.status
            try:
                ej = json.loads(snippet)
                code = (ej.get("error") or {}).get("code") or (ej.get("error") or {}).get("type")
                if code:
                    rec["error"] = "http_%d:%s" % (resp.status, code)
            except Exception:
                pass
            print(json.dumps(rec))
            return

        while True:
            raw = resp.readline()
            if not raw:
                break
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            if line.startswith(b"event:"):
                cur_event = line[6:].strip().decode("utf-8", "replace")
                continue
            if not line.startswith(b"data:"):
                continue
            t = time.monotonic()
            payload = line[5:].strip()
            if payload == b"[DONE]":
                last_event_t = t
                continue
            etype = cur_event
            usage = None
            try:
                j = json.loads(payload)
                etype = j.get("type", cur_event)
                if etype in TERMINAL:
                    usage = (((j.get("response") or {}).get("usage")) or {})
            except Exception:
                pass

            if first_event_t is None:
                first_event_t = t
                rec["first_event_ms"] = (t - t0) * 1000.0
            last_event_t = t
            if etype:
                event_types[etype] = event_types.get(etype, 0) + 1

            if etype == OUTPUT_DELTA:
                delta_times.append(t)
                if rec["ttft_ms"] is None:
                    rec["ttft_ms"] = (t - t0) * 1000.0
            if etype in TERMINAL and usage is not None:
                ot = usage.get("output_tokens")
                if ot is not None:
                    rec["n_output_tokens"] = ot

        rec["n_chunks"] = len(delta_times)
        if last_event_t is not None:
            rec["total_stream_ms"] = (last_event_t - t0) * 1000.0
        if len(delta_times) >= 2:
            rec["inter_chunk_ms"] = [
                (delta_times[i] - delta_times[i - 1]) * 1000.0
                for i in range(1, len(delta_times))
            ]
        rec["ok"] = (
            rec["http_code"] == 200
            and rec["ttft_ms"] is not None
            and rec["n_chunks"] > 0
        )
    except Exception as e:
        rec["error"] = "%s:%s" % (type(e).__name__, str(e)[:80])
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if a.debug_events:
        sys.stderr.write("event_types=%s\n" % json.dumps(event_types, sort_keys=True))

    print(json.dumps(rec))


if __name__ == "__main__":
    main()
