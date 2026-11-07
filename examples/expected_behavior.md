# Expected authorization behavior

Synthetic endpoint: `GET /patients/{patient_id}`

Records:

| Patient | Id | Clinic |
| --- | --- | --- |
| Alex Rivera | p-100 | clinic-a |
| Jordan Blake | p-200 | clinic-b |

Callers:

- Clinician in clinic-a, authenticated, may read `p-100` only.
- Clinician in clinic-b, authenticated, may read `p-200` only.
- Missing authentication, missing clinician role, or a cross-clinic id is denied.

The vulnerable example returns Jordan Blake to a clinic-a clinician. MedGuard should **BLOCK** it.

The corrected example enforces the rules above. MedGuard should **APPROVE** it when static analysis and the sandbox tests pass.

The incomplete example imports a module that is not in the sandbox. MedGuard should **REVIEW** it because the tests cannot run to a conclusion.

These examples use invented people. Passing the checks does not establish HIPAA compliance.
