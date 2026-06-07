# Formal Model

This directory implements P1-1 as a scoped ProVerif model of the AEGIS
protocol-level invariants.

## Models

- `model/aegis_protocol_invariants.pv` — the current model. The attacker is
  the untrusted host: all channels are public, the host control channel is
  spoken by the attacker directly, and a platform oracle signs attestations
  for any measurement other than the expected one over attacker-chosen keys
  and nonces. The destination policy is a baked table with two entries; the
  host cites policy names only. Each honest enclave session generates an
  ephemeral channel key and quotes the genuine measurement over that key
  inside the session (no static enclave key); the sidecar tags each released
  body with a fresh request id, and providers answer with fresh response
  tokens bound to that request id, making the check-to-use and
  response-provenance correspondences injective and per-request.
- `model/aegis_five_invariants.pv` — the earlier, weaker model, kept for the
  provenance of `raw/20260605T154426Z`. It has no bad-measurement source, a
  single destination, and no secrecy or noninterference queries, so its three
  correspondences are ordering checks only.

## Run

```sh
# requires ProVerif on PATH (installed via opam: eval $(opam env))
./eval/formal-model/scripts/run-proverif.sh
```

The script runs the current model by default and writes the log plus
`summary.txt` and `provenance.txt` (commit, model path, ProVerif version) under
`eval/formal-model/raw/<timestamp>/`. To rerun multiple models, set
`MODEL_GLOB='eval/formal-model/model/*.pv'`. If `proverif` is not installed it
exits with a prerequisite message and writes no proof claim.

Current successful run: `raw/20260606T134208Z` (ProVerif 2.05).

## Queries (aegis_protocol_invariants.pv)

| # | Property | Result | Expected |
|---|----------|--------|----------|
| P1a | Attestation agreement (injective): every sidecar verification of the expected measurement corresponds to a genuine in-enclave quote binding the same key and nonce | true | true |
| P1b | Release ordering: plaintext release implies verification of the expected measurement binding the same key and nonce | true | true |
| P1c | Release ordering (injective): a replayed attestation cannot justify a second release (nonce freshness) | true | true |
| P2 | Check-to-use (injective, honest body): the enclave accepts the honest body under exactly the key, nonce, and request id the sidecar released it under | true | true |
| P3a | Destination authority: the honest body reaches a provider only via enclave policy resolution | true | true |
| P3b | Allowlist bound: any destination the honest body reaches is one of the baked policy entries | true | true |
| P3c | Egress ordering (all bodies): every enclave dispatch is preceded by policy resolution for that destination | true | true |
| P4 | Response provenance (honest body): a response the client accepts was produced and received by a provider at an allowed destination for the same body, request id, and token | true | true |
| P5a | Body secrecy against the host/network attacker | true | true |
| P5b | Noninterference: host-observable behavior, including the enclave-to-host control request, is invariant under change of the body (metadata-only control path) | true | true |
| D1 | Gateway credential is disclosed to the host (by design, single-operator scope) | false | false |
| S1/S2 | Sanity: the honest pipeline is reachable, so P1–P4 are not vacuous | false | false |

"Bad measurement / bad nonce / wrong certificate does not release plaintext"
and "unknown policy does not reach a provider" are covered by P1–P3 together
with the attacker's capabilities (the oracle supplies bad-measurement
attestations; the attacker mints arbitrary policy names and keys). P5a separately
checks symbolic body secrecy against that same host/network attacker. The
all-body form of P2 is intentionally not claimed: the enclave serves
attacker-owned client sessions by design.

## Mutation self-check

To confirm the proofs are attack-sensitive rather than vacuous, the run
`raw/20260606T134208Z` also contains `mutation_oracle_unrestricted.{pv,log}`,
produced by deleting the oracle's measurement restriction:

```sh
sed 's/if m <> goodMeas then/(* mutation *)/' model/aegis_protocol_invariants.pv
```

Under this mutation ProVerif finds the attacks: Q3, Q4, Q7, Q8 become false
and Q9 cannot be proved.

## Scope: what the model does NOT cover

Protocol ordering and authority only. Out of scope, covered by separate
implementation evidence (conformance suite, fuzz targets, schema unit tests,
pcap capture) or out of scope for the paper entirely:

- Go implementation bugs;
- AWS Nitro internals;
- TLS cipher-suite internals (sessions are abstracted as ideal channels keyed
  by attested or CA-validated keys);
- provider dishonesty;
- side channels (sizes, timing, SSE cadence);
- byte-for-byte relay faithfulness (the model's relay is symbolic);
- source-level schema enumeration of the real control channel (the model's
  control messages are metadata-only by construction; that the Go schemas
  match is established by `eval/adaptive-negative-tests`).
