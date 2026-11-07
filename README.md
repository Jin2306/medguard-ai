# MedGuard AI

MedGuard checks AI-generated medical software instead of trusting the coding agent that wrote it. A run loads security policy, searches prior security memory, asks Meta for an advisory review when credentials exist, generates its own pytest suite plus an adversarial layer, and executes that suite in a locked-down container. The decision is APPROVE, BLOCK, or REVIEW.

Passing these checks does not establish HIPAA compliance. The patient records in this project are synthetic.

## Decisions

The gate is `backend/app/decision.py`. Model severity is not an input.

- **APPROVE** — the sandbox ran, every mandatory evidence test passed, Semgrep completed, and no confirmed static finding remains.
- **BLOCK** — after the sandbox ran, an evidence test failed or static analysis confirmed a policy violation.
- **REVIEW** — Docker could not run the tests, Semgrep did not finish, a mandatory test errored or was skipped, or the requested policy version was not the pack that ran.

In DEMO MODE the advisory text is a deterministic checklist, and the screen says so. Deterministic adversarial tests still run. Meta-proposed tests run only after validation.

## What you need later

Copy `.env.example` to `.env` when you have credentials. Leave the values empty until then.

| Variable | Purpose |
| --- | --- |
| `META_API_KEY` | Secret issued with your Meta model access. |
| `META_MODEL` | Model id issued with that access. MedGuard does not pick one. |
| `META_BASE_URL` | Full chat-completions URL. The client POSTs here and does not append a path. |
| `META_AUTH_SCHEME` | Optional. Defaults to `Bearer`. |
| `MONGODB_URI` | Atlas connection string. Empty means the local fallback. |
| `MONGODB_DB` | Database name. Defaults to `medguard`. |
| `MONGODB_VECTOR_INDEX` | Atlas Vector Search index name. Unused unless `EMBEDDING_URL` is also set. |
| `EMBEDDING_URL` | Endpoint that returns an embedding for a query. Both this and the index are required before vector search is attempted. |

The live Meta request is an OpenAI-style chat body (`model`, `temperature` 0, `messages`) sent to `META_BASE_URL`. If the call fails, the run continues from tests and static analysis and the error is shown.

Atlas collections: `verification_runs`, `security_memory`, `audit_logs`. If Atlas is not configured, or the connection fails, records stay in `data/local_store.json` and the UI says they were not written to Atlas.

Retrieval is labeled on the run:

- `local_keyword` — local file, no Atlas.
- `mongodb_index` — ordinary MongoDB query.
- `atlas_vector` — a real `$vectorSearch` aggregation succeeded.

MedGuard does not report vector search when that aggregation did not run.

## Run it

From `medguard-ai`:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
docker build -t medguard-sandbox:latest -f sandbox/Dockerfile sandbox
```

API:

```bash
cd backend
../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

UI, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173

Tests:

```bash
cd medguard-ai
.venv/bin/pytest
```

Optional gate for one file. Exit 0 only on APPROVE. It does not merge or deploy.

```bash
python scripts/medguard_gate.py examples/corrected_patient_api.py
```

The sandbox image has no network at runtime, a read-only root filesystem, dropped capabilities, no privileged mode, a 256 MB memory cap, a non-root user, and a 45 second timeout. Host credential env vars are not passed into the container. If Docker or the image is missing, generated code is not executed and the decision is REVIEW.

## Examples

| Example | Expected decision |
| --- | --- |
| `examples/vulnerable_patient_api.py` | BLOCK. Clinic A can read Clinic B patient `p-200`. |
| `examples/corrected_patient_api.py` | APPROVE, when Semgrep and the sandbox both pass. |
| `examples/incomplete_patient_api.py` | REVIEW. The import cannot be executed. |

## More

- `DEMO_GUIDE.md` — three-minute script.
- `ARCHITECTURE.md` — pipeline, memory, sandbox, ClinicOS contract.
- `SECURITY_POLICIES.md` — POL-01 through POL-08.
- `HACKATHON_PITCH.md` — problem, verifier, Meta, and Atlas.
- `integrations/clinicos_verification.schema.json` — future submit body. MedGuard does not call ClinicOS.
- `.github/workflows/medguard-verify.yml` — optional CI gate.
