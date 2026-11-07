# Three-minute MedGuard demonstration

Synthetic patients only. Do not paste real records. About three minutes.

## Start

From `medguard-ai`:

```bash
source .venv/bin/activate
docker build -t medguard-sandbox:latest -f sandbox/Dockerfile sandbox
cd backend && ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Second terminal:

```bash
cd medguard-ai/frontend && npm run dev
```

Open http://127.0.0.1:5173

Read the chips before the story:

- Meta AI: **DEMO MODE** until `META_API_KEY`, `META_MODEL`, and `META_BASE_URL` are all set. With those set and a successful call, the chip names the configured model.
- Storage: **Local fallback, not Atlas** until `MONGODB_URI` connects. The label must not say Atlas when the file store is in use.
- Retrieval: **Local keyword** in that same fallback. It says Atlas Vector Search only after a real `$vectorSearch` succeeds.
- Semgrep: a version string.
- Sandbox: **Docker ready**.

If a chip says DEMO MODE or local fallback, say that out loud. Do not describe those runs as live Meta or Atlas.

## Script

**0:00 — Requirements.** The left panel states the rule: a clinic may read only its own patients. The table lists Alex Rivera (`p-100`, clinic-a) and Jordan Blake (`p-200`, clinic-b).

**0:20 — Hidden bug.** Click **1. Vulnerable change**. `get_patient` returns whichever record was asked for. The file also logs date of birth and MRN, embeds a key, and builds SQL with an f-string.

**0:40 — Run MedGuard.** Click **2. Run MedGuard**. The pipeline moves from code change through AI analysis, test generation, execution, evidence, and decision. In DEMO MODE, say the analysis is a deterministic advisory, not a Meta completion.

**1:10 — Independent test.** Open the generated pytest source and the result for `test_adv_cross_clinic_patient_leak`. A clinic-a clinician requested `p-200`. The test failed because the record came back. The origin line says `deterministic_fallback` unless Meta proposed a test that passed validation.

**1:30 — Block.** The banner is **BLOCK**. Point at the reason: a mandatory test failed, and AI severity was not the decision. Download the JSON report. It contains the code hash, policy version `medguard-policy-2026.1`, the test source, and the failed outcome.

**1:50 — The fix.** Click **3. Corrected change**. The handler authenticates the caller, checks the clinician role, validates the id, and compares `clinic_id`.

**2:10 — Approve.** Click **4. Verify the fix**. `test_adv_cross_clinic_patient_leak` passes. The banner is **APPROVE** only when the mandatory tests passed and Semgrep completed. `test_adv_unauthorized_modification` may be skipped because this API has no `update_patient`. A skip there does not approve the change by itself.

**2:40 — Memory.** Scroll to security memory retrieval. The mode is **local keyword** without Atlas, and the disclaimer says past hits are not proof about this change. The rows saved from the blocked run record Cross-Clinic Data Exposure and the strategy of asking as another clinic. Previous runs lists both the BLOCK and the APPROVE.

Optional closer: select **Incomplete patient read**, verify it, and show **REVIEW**. The import fails, so MedGuard does not approve.

## If Meta or Atlas is configured

Restart the API after editing `.env`. A live model can change the advisory text and, if its test proposal validates, add tests. The BLOCK and APPROVE above still have to match executed results. A vector chip appears only when the health or run label says the aggregation ran.

## Curl

```bash
curl -s http://127.0.0.1:8000/api/health
curl -s -X POST http://127.0.0.1:8000/api/verify \
  -H 'Content-Type: application/json' \
  -d @<(python -c 'import json,pathlib; print(json.dumps({"code":pathlib.Path("examples/vulnerable_patient_api.py").read_text(),"scenario_id":"vulnerable-cross-clinic"}))')
```

Run that from `medguard-ai`. Then download `/api/verification/<run_id>/report`.
