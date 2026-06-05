# Adaptive and Coverage-Oriented Negative Tests

This is the P0-2 evaluation layer for the AEGIS paper. It turns the previous
Table 2 conformance evidence into explicit local negative tests and a bounded
channel analysis. All inputs are synthetic and local.

## Run

From the `sub2api` repository root:

```sh
./eval/adaptive-negative-tests/scripts/run-local.sh
```

The script writes raw logs under `eval/adaptive-negative-tests/raw/<timestamp>/`.
It does not require provider API keys.

## Evidence Produced

- `go-test-unit.log`: unit-level negative tests for:
  - control-channel schemas excluding body, URL/path, destination, and headers,
  - host-selected metadata model not rewriting the client request body,
  - sidecar fail-closed behavior and TLS certificate pin rotation,
  - SSE line-granularity relay and non-SSE full-body relay observation bounds.
- `control-channel-bound.md`: static field enumeration from the Go source and
  a per-request bound on host-variable control fields.
- `summary.md`: paper-facing summary of tested properties and residual leakage.

## Claim Mapping

- C16/C21/C22/C43: the host-facing control channel is metadata-only and cannot
  carry body bytes or host-chosen destinations.
- C23/C65: plaintext release is gated on sidecar verification, and a post-
  attestation certificate change fails closed before the rotated endpoint handles
  the request.
- C24/C63: streamed responses expose timing and size at SSE-line granularity;
  no padding is implemented, so this is reported as an explicit residual side
  channel rather than claimed away.

## Scope

These tests do not replace the existing Table 2 baseline harness; they are an
additional adaptive/coverage-oriented layer. P0-3 multi-provider and real-agent
workloads are separate because they require provider keys in `deploy/.env`.
