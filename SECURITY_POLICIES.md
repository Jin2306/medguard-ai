# MedGuard security policies

Policy pack: `medguard-policy-2026.1`

Source: `policies/medical_security_policies.json`

These checks are a hackathon verification pack for a synthetic patient-read API. A passing run is not a HIPAA determination. MedGuard uses the synthetic patients in `examples/synthetic_patients.json` and does not connect to a production patient database.

| Id | Requirement | Mandatory test |
| --- | --- | --- |
| POL-01 | A caller may read a patient only when that caller is allowed to see that record. | Own-record and unauthorized-read checks in the baseline suite. |
| POL-02 | A user from one clinic must not retrieve a patient assigned to another clinic. | Baseline cross-clinic test and `test_adv_cross_clinic_patient_leak`. |
| POL-03 | Patient reads require an authenticated caller. | Call with no authenticated actor. |
| POL-04 | Only a clinician role may read patient records. | Receptionist read, plus `test_adv_wrong_role_cannot_read`. |
| POL-05 | Passwords, API keys, and tokens must not be literals in source. | Confirmed static finding for a hardcoded secret. |
| POL-06 | Logs must not contain date of birth, medical record numbers, or credentials. | Confirmed static finding for sensitive logging. |
| POL-07 | SQL must not be built by formatting user input into the query string. | Confirmed static finding for an f-string query. |
| POL-08 | Patient ids must be validated before use. | Baseline input-validation test. |

`REQ-ALLOW` checks the safe path: an authenticated clinic-a clinician can still read patient `p-100`.

## Featured scenario

Clinic A requests Clinic B patient `p-200` (Jordan Blake).

- Expected: access denied.
- Vulnerable: the record is returned. `test_adv_cross_clinic_patient_leak` fails and the gate blocks.
- Corrected: the clinic comparison denies the read. The same test passes.

## What can block

The gate in `backend/app/decision.py` blocks only after the sandbox executes, and only when an evidence test fails or static analysis confirms a finding. Semgrep rules live in `policies/semgrep.yml`. Built-in AST checks confirm hardcoded secrets, string-built SQL, and sensitive log arguments.

A missing clinic comparison or a missing auth decorator is recorded as an unconfirmed lead until a test fails. Model severity text cannot block or approve on its own.

## What forces review

- The sandbox did not run.
- A mandatory evidence test errored or was skipped.
- Semgrep did not finish.
- The caller asked for a policy version other than the loaded pack.

## Adversarial additions

The deterministic layer also checks that a successful read does not return date of birth or MRN, and that `update_patient` rejects another clinic when that function exists. Those tests count as evidence if they fail. A skip, used when `update_patient` is absent, does not approve or block by itself.

Meta-proposed tests are an extra layer. They run only after AST validation. Rejected source is kept on the run and is not executed.
