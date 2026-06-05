# Provider Workloads

This directory holds P0-3 evidence for provider diversity and real-provider
latency.

## Support Boundary

AEGIS now has measured enclave policies for three provider-native paths:

- `openai/openai-responses`
- `openrouter/chat-completions`
- `gemini/generate-content-gemini-2.5-flash`

The data plane remains faithful passthrough: callers must send each provider's
native request body. The enclave does not convert OpenAI Responses requests into
OpenRouter Chat Completions or Gemini `generateContent` requests.

## Direct Baseline

Run from the `sub2api` repository root:

```sh
./eval/provider-workloads/scripts/run-direct-baseline.sh
```

This calls Gemini and OpenRouter directly. It validates keys and captures a
baseline, but it is not AEGIS-through evidence.

## AEGIS-Through Workload

Run after the sidecar is already serving an attested AEGIS session:

```sh
AEGIS_SIDE_URL=http://127.0.0.1:8788 \
AEGIS_OPENAI_GATEWAY_KEY="$CONFIDENTIAL_EVAL_OPENAI_GATEWAY_KEY" \
AEGIS_OPENROUTER_GATEWAY_KEY="$CONFIDENTIAL_EVAL_OPENROUTER_GATEWAY_KEY" \
AEGIS_GEMINI_GATEWAY_KEY="$CONFIDENTIAL_EVAL_GEMINI_GATEWAY_KEY" \
N=100 ./eval/provider-workloads/scripts/run-aegis-provider-workload.sh
```

For local evaluation without database accounts, start `cmd/host-orchestrator`
with `CONFIDENTIAL_EVAL_MODE=1` and the matching
`CONFIDENTIAL_EVAL_*_GATEWAY_KEY` variables. Provider credentials still come
from `deploy/.env`. The script writes sanitized raw metrics under
`eval/provider-workloads/raw/<timestamp>/`.

## Completed AEGIS-Through Runs

Current paper numbers use these raw directories:

| Provider | Raw directory | Requests | Marker seen | Median total | P95 total |
| --- | --- | ---: | ---: | ---: | ---: |
| OpenAI Responses | `raw/20260605T160957Z` | 100/100 | 100/100 | 902 ms | 2422 ms |
| OpenRouter Chat Completions | `raw/20260605T155149Z` | 100/100 | 100/100 | 760 ms | 1496 ms |
| Gemini `generateContent` | `raw/20260605T155149Z` | 100/100 | 100/100 | 1175 ms | 1749 ms |

Failed stale-key and marker-mismatch dry runs are not kept in this tree. The
table above lists the AEGIS-through runs used for paper success claims.
