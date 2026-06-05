# AEGIS Evaluation Artifacts

This directory contains repeatable evaluation code and raw outputs used by the
AEGIS paper. Each subdirectory maps to one paper-review work item and records:

- command lines and inputs,
- git commit and branch provenance,
- raw logs produced by the run,
- the paper claim or criticism the run addresses.

Current subdirectories:

- `adaptive-negative-tests/`: P0-2 local defensive tests for the control channel,
  attestation fail-closed behavior, and stream timing/size observation.
- `audit-study/`: P0-1 seeded-invariant audit study prompts, answer key, scoring
  script, and summary templates.
- `provider-workloads/`: P0-3 direct-provider and AEGIS-through provider workload
  runners for OpenAI, OpenRouter, and Gemini.
- `formal-model/`: P1-1 scoped ProVerif model of the five invariants.
- `faithfulness-fuzz/`: P1-2 fuzzing entrypoint for byte-fidelity checks.
- `open-gateway-comparison/`: P1-3 local comparison harness for the nearest open
  enclave gateway.
- `throughput/`: P1-4 concurrency and throughput load-test runner.

Provider keys are loaded from the gitignored `deploy/.env`. Evaluation scripts
must not print or store the raw keys.
