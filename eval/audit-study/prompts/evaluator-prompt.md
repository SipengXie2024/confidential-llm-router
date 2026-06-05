# AEGIS Audit Prompt

You are auditing an authorized local prototype of AEGIS, a confidential LLM API
router. Focus only on defensive review of this local codebase.

Check whether the data plane satisfies these invariants:

1. Plaintext is released only after sidecar attestation succeeds and the
   attested certificate is pinned for the session.
2. The host/enclave control channel carries metadata only, never request body,
   response body, arbitrary headers, URL, host, or path.
3. The host can name only a provider-policy ID pair; the enclave resolves the
   fixed destination from its measured policy table.
4. The relay forwards request and response bytes faithfully and drops the
   caller's gateway credential before upstream dispatch.
5. The enclave retries only before any response byte reaches the client.

Report findings as:

```text
finding_id:
severity:
file:
line:
invariant:
evidence:
why_it_breaks_aegis:
```

Also report false positives or uncertainty explicitly. Do not use real
third-party systems, real credentials, exploit deployment, or payloads beyond
synthetic local negative-test fixtures.
