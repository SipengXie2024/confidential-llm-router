# Formal Model

This directory implements P1-1 as a scoped ProVerif model. It models the five
AEGIS invariants at the protocol level; it does not model AWS Nitro internals,
TLS cipher suites, Go memory safety, provider honesty, or side channels.

Run:

```sh
./eval/formal-model/scripts/run-proverif.sh
```

If `proverif` is not installed, the script exits with a clear prerequisite
message and writes no proof claim.

The current successful run is `raw/20260605T154426Z`. It proves:

- plaintext release implies verification of the expected measurement,
- provider receipt implies enclave policy resolution,
- client receipt implies provider receipt at the allowed destination.
