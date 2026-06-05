# Throughput and Concurrency

This directory implements P1-4. It measures an already-running AEGIS sidecar or
benchmark sidecar under concurrency.

Run:

```sh
AEGIS_SIDE_URL=http://127.0.0.1:8788 \
AEGIS_GATEWAY_KEY="$CONFIDENTIAL_EVAL_OPENAI_GATEWAY_KEY" \
./eval/throughput/scripts/load-aegis.sh
```

Set `PROVIDER=openai`, `PROVIDER=openrouter`, or `PROVIDER=gemini` and pass the
matching gateway key. The paper run used `TOTAL=50` and
`CONCURRENCY_SET='1 4 8 16'` for each provider.

Use the released/attested image when feasible. If the sidecar points to the
local benchmark image, report the result as a relay microbenchmark rather than
end-to-end provider latency.

## Completed AEGIS-Through Runs

| Provider | Raw directory | Per-tier result | Median at concurrency 16 | P95 at concurrency 16 |
| --- | --- | --- | ---: | ---: |
| OpenAI Responses | `raw/20260605T161207Z` | 50/50 ok at 1, 4, 8, 16 | 896 ms | 2476 ms |
| OpenRouter Chat Completions | `raw/20260605T155730Z` | 50/50 ok at 1, 4, 8, 16 | 698 ms | 1310 ms |
| Gemini `generateContent` | `raw/20260605T155849Z` | 50/50 ok at 1, 4, 8, 16 | 1199 ms | 1638 ms |
