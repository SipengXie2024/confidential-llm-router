# Closest Open Gateway Comparison

This directory implements P1-3. The closest comparison target is the
OpenGradient open-source enclave gateway cited in the paper as `opengradient`.

Run with a checked-out comparison repository:

```sh
OPENGRADIENT_DIR=/path/to/opengradient \
  ./eval/open-gateway-comparison/scripts/compare-local.sh
```

The script does not download code. It computes reproducible local metrics and
produces a comparison table template. Manual review must fill verification
posture, receipt semantics, and provider coverage from the pinned comparison
revision.

The current filled comparison is `raw/20260605T160510Z/comparison-table.md`.
It compares AEGIS at `64cd0fab` with OpenGradient `tee-gateway` at `afa7966`.
The local source-LOC proxy is 1,236 lines for AEGIS and 10,434 lines for
OpenGradient. OpenGradient was inspected from source and documentation, not run
locally.
