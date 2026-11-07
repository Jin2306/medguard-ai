# MedGuard architecture

MedGuard verifies a proposed Python change. It does not trust the coding agent that produced the change, and it does not treat a model severity label as a decision.

## Pipeline

```
CODE CHANGE
    → AI ANALYSIS          (advisory only)
    → SECURITY TEST GENERATION
    → TEST EXECUTION       (Docker sandbox)
    → EVIDENCE
    → DECISION             (deterministic Python)
```

`backend/app/engine.py` runs that sequence for `POST /api/verify`.

1. Hash the submitted source and load `policies/medical_security_policies.json` (`medguard-policy-2026.1`).
2. Search security memory for similar past failures. Hits are context for test generation. They are marked `evidence_against_new_changes: false` and are not passed into the decision function.
3. Ask Meta for an advisory review when `META_API_KEY`, `META_MODEL`, and `META_BASE_URL` are all set. The coding agent's reasoning is not an input. Without those variables the stage is labeled DEMO MODE and uses a deterministic checklist.
4. Build the baseline pytest suite from policy, then an adversarial layer. Meta may propose extra tests. Those tests are parsed and rejected if they import or call anything outside the allowlist. Invalid proposals are stored as rejected and are not executed. The deterministic adversarial tests still run.
5. Execute the combined suite in the sandbox. If Docker or `medguard-sandbox:latest` is unavailable, the code is not executed and the decision is REVIEW.
6. `backend/app/decision.py` chooses APPROVE, BLOCK, or REVIEW from executed results and confirmed static findings only.
7. Persist the run, an audit log, and confirmed failure strategies. Attach a JSON report.

A requested `policy_version` that does not match the loaded pack forces REVIEW. MedGuard does not pretend a different policy was applied.

## Independent verifier

The verifier receives the requirements, the policy pack, and the submitted source. It does not receive the coding agent's self-assessment. Model output is stored under `ai` with `advisory_only: true`. Confirmed evidence is the sandbox outcome and static findings whose `confirmed` flag is true. Heuristic leads stay unconfirmed and cannot block by themselves.

## Decision gate

Implemented in `backend/app/decision.py` and reused by `scripts/medguard_gate.py`.

| Decision | Condition |
| --- | --- |
| REVIEW | Sandbox did not execute, a mandatory evidence test errored or was skipped, Semgrep did not complete, or the requested policy version was not the one that ran. |
| BLOCK | After execution, an evidence test failed or a confirmed static finding exists. |
| APPROVE | Sandbox executed, every mandatory evidence test passed, Semgrep completed, and there are no confirmed static findings. |

Tests with `counts_as_evidence: false` cannot force a decision. An AI recommendation is not an argument to `decide()`.

The GitHub workflow `.github/workflows/medguard-verify.yml` runs the gate on one Python file. The job exits 0 only for APPROVE. It does not merge or deploy.

## Adversarial tests

`backend/app/adversarial.py` always contributes a validated deterministic layer. The featured mandatory test is `test_adv_cross_clinic_patient_leak`: a clinic-a clinician requests patient `p-200`, who belongs to clinic-b. Access must be denied. Returning the record fails the test.

Additional deterministic tests cover a sensitive field in the response, a non-clinician role, and unauthorized modification when `update_patient` exists. The modification test skips when the function is absent. A skip is not a pass and, because that test is not mandatory, it does not force REVIEW.

## Security memory

Documents follow the catalog in `backend/app/memory.py`: `vulnerability_type`, `severity`, `failure_pattern`, `successful_test_strategy`, `recommended_fix`, and `verified`. `verified` is true only after an executed evidence test fails, or after a full APPROVE records the passing strategy. A later submission searches those documents first, then generates and executes new tests.

Retrieval modes, labeled on the run and on `/api/health`:

| Mode | When |
| --- | --- |
| `local_keyword` | Atlas is not connected. Keyword match on `data/local_store.json`. |
| `mongodb_index` | Atlas is connected. Ordinary indexed query. |
| `atlas_vector` | `MONGODB_VECTOR_INDEX` and `EMBEDDING_URL` are set, Atlas is connected, and a real `$vectorSearch` aggregation returns. |

If the vector query is not configured or fails, the label says so and the fallback query is used. MedGuard does not invent embeddings or report a vector search that did not run.

## Evidence

`backend/app/report.py` stores, for each run:

- code SHA-256 and policy version
- model mode and identifier (`demo-deterministic` in DEMO MODE)
- generated test source and execution results
- static findings
- decision, timestamp, and memory references
- a reproducibility note: recorded settings and artifacts can be rerun; probabilistic model text is not guaranteed to match

`GET /api/verification/{run_id}/report` downloads that JSON. `POST /api/verification/{run_id}/rerun` submits the stored source and policy version again.

## Sandbox

`sandbox/Dockerfile` builds `medguard-sandbox:latest` (Python 3.11, pytest, non-root uid 65532). `backend/app/sandbox.py` runs it with `--network none`, dropped capabilities, no new privileges, a read-only root, tmpfs for `/tmp`, 256 MB memory, 0.5 CPU, a pid limit, and a 45 second timeout. Host Meta and Mongo credentials are not passed in. The work directory is under the project so Docker Desktop can mount it.

## ClinicOS

`integrations/clinicos_verification.schema.json` describes a future `POST /api/verify` body: Python source, requirements, policy version, and component metadata. MedGuard does not call ClinicOS and does not connect to a production patient database. Demo patients live in `examples/synthetic_patients.json`.

## Fallbacks

Missing Meta credentials stay in DEMO MODE. A failed live call is recorded as an error and verification continues from tests. Missing Mongo credentials, or an Atlas connection error, stay on the local file and the label says the records were not written to Atlas.
