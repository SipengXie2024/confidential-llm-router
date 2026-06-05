# Provider Adapter Table

| Provider path | AEGIS-through support | Auth scheme | Usage parser | AEGIS-through evidence |
| --- | --- | --- | --- | --- |
| OpenAI Responses | `openai/openai-responses` | `Authorization: Bearer` | `response.usage` / terminal Responses SSE | `raw/20260605T160957Z`: 100/100 ok, median 902 ms, p95 2422 ms. |
| OpenRouter Chat Completions | `openrouter/chat-completions` | `Authorization: Bearer` | top-level Chat Completions `usage` | `raw/20260605T155149Z`: 100/100 ok, median 760 ms, p95 1496 ms. |
| Gemini native `generateContent` | `gemini/generate-content-gemini-2.5-flash` | `x-goog-api-key` | `usageMetadata.promptTokenCount` / `candidatesTokenCount` | `raw/20260605T155149Z`: 100/100 ok, median 1175 ms, p95 1749 ms. |

This table describes native passthrough only. Adding a new Gemini model requires
a new measured policy ID so the path remains enclave-owned rather than
host-supplied.
