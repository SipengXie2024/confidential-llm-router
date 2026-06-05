# Faithfulness Fuzzing

This directory implements P1-2. The fuzz target lives with the relay code:

- `backend/internal/enclave/forward_fuzz_test.go`

Run:

```sh
./eval/faithfulness-fuzz/scripts/run-local.sh
```

The target checks that non-SSE and SSE relays emit exactly the bytes they read.
It also keeps corpus seeds for tool-call JSON, multimodal-like payloads,
unusual encodings, large bodies, and SSE chunk boundaries.
