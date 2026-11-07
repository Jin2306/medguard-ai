# MedGuard AI — The AI That Doesn't Trust AI

Track: Trust but Verify

## Problem

An AI coding assistant can ship a patient API that looks finished and still lets Clinic A read Clinic B's record. The assistant's own explanation is not evidence. A reviewer that only restates the model's confidence will approve the leak.

## Solution

MedGuard is an independent verifier. It takes the requirements, the medical software policy pack, and the proposed Python. It generates adversarial tests, runs them in a network-free sandbox, and stores the evidence. A deterministic gate then approves, blocks, or sends the change to review.

The featured failure is cross-clinic patient leakage. Clinic A asks for patient `p-200`. The vulnerable API returns Jordan Blake. MedGuard blocks that change. The clinic-scoped API denies the read, the same tests pass, and the gate approves.

## Technical innovation

- The verifier never sees the coding agent's reasoning or self-assessment.
- Hypotheses and confirmed results are separate. Model findings stay advisory. Only executed tests and confirmed static findings enter the decision.
- Deterministic adversarial tests always run. Meta-generated tests are added only after validation, and invalid output is rejected rather than executed.
- Security memory retrieves past strategies to shape the next suite. An old finding is never treated as proof that the new diff is vulnerable.
- Every run keeps a JSON report: code hash, policy version, model identifier, test source, execution results, and the decision. The same source and policy can be submitted again. Model prose is not claimed to be bit-for-bit reproducible.

## Why independent verification matters

The agent that wrote the bug is the wrong witness. MedGuard decides from a failed assertion in a locked container, or from a confirmed secret, log, or query finding. If the model says the code is safe and `test_adv_cross_clinic_patient_leak` fails, the decision stays BLOCK. If the sandbox cannot run, the decision is REVIEW, not APPROVE.

## How Meta AI is used

When `META_API_KEY`, `META_MODEL`, and `META_BASE_URL` are set, MedGuard sends an OpenAI-style chat request to that URL. One call is an advisory review. A second call proposes adversarial tests. The client does not invent a model id or a host. If the credentials are missing, the UI says DEMO MODE and the deterministic suite still decides. If a live call fails, the error is shown and verification continues from the tests.

## How MongoDB Atlas is used

Connected Atlas stores `verification_runs`, `security_memory`, and `audit_logs`. Retrieval is an ordinary indexed query unless both `MONGODB_VECTOR_INDEX` and `EMBEDDING_URL` are set and a real `$vectorSearch` aggregation succeeds. That path is labeled `atlas_vector`. Any other path is labeled `mongodb_index` or `local_keyword`. Local records say they were not written to Atlas. MedGuard does not simulate a successful vector search.

## Future medical software use

`integrations/clinicos_verification.schema.json` is the contract a later ClinicOS component can POST: Python source, security requirements, policy version, and component metadata. MedGuard stays outside ClinicOS and outside production patient databases. The same gate can sit on a pull request through `.github/workflows/medguard-verify.yml`, failing the job on BLOCK or REVIEW and passing only on APPROVE, without merging or deploying.

## Three-minute script

See `DEMO_GUIDE.md`.
