"""HTTP API for MedGuard verification."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import DISCLAIMER, get_settings
from app.engine import execute, initial_stages
from app.meta_client import meta_status
from app.policies import load_policies
from app.report import build_report
from app.sandbox import ISOLATION_PROFILE, docker_available
from app.scenarios import list_scenarios
from app.schemas import ComponentMetadata, HealthResponse, HistoryItem, VerificationRunModel, VerifyRequest
from app.static_analysis import semgrep_available
from app.store import get_store

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("medguard.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store = get_store()
    meta = meta_status()
    logger.info("Storage: %s", store.label)
    logger.info("Meta AI: %s", meta["label"])
    yield


app = FastAPI(title="MedGuard AI", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_run(run: dict) -> dict:
    return VerificationRunModel.model_validate(run).model_dump()


@app.get("/")
def root() -> dict:
    return {
        "service": "medguard-ai",
        "verify": "POST /api/verify",
        "health": "GET /api/health",
        "ui": "http://127.0.0.1:5173",
    }


@app.get("/api/health")
def health() -> dict:
    store = get_store()
    policies = load_policies()
    docker = docker_available()
    semgrep = semgrep_available()
    meta = meta_status()
    payload = HealthResponse(
        status="ok",
        service="medguard-ai",
        policy_version=policies["version"],
        disclaimer=DISCLAIMER,
        meta_ai=meta,
        mongodb=store.status(),
        semgrep={
            "available": semgrep.get("available", False),
            "status": semgrep.get("status"),
            "detail": semgrep.get("detail"),
        },
        sandbox={
            "available": docker["available"] and docker["image_ready"],
            "docker": docker,
            "isolation": ISOLATION_PROFILE,
        },
    )
    return payload.model_dump()


@app.get("/api/demo/scenarios")
def demo_scenarios() -> dict:
    return {"scenarios": list_scenarios(), "disclaimer": DISCLAIMER}


@app.post("/api/verify")
async def verify(body: VerifyRequest) -> dict:
    if "\x00" in body.code:
        raise HTTPException(status_code=400, detail="Code contains a null byte.")
    policies = load_policies()
    store = get_store()
    meta = meta_status()
    now = _now()
    run = {
        "run_id": str(uuid4()),
        "status": "running",
        "created_at": now,
        "updated_at": now,
        "scenario_id": body.scenario_id,
        "filename": "submitted_code.py",
        "code": body.code,
        "code_sha256": "",
        "policy_version": policies["version"],
        "policy_sha256": policies["sha256"],
        "decision": None,
        "decision_reason": "",
        "ai": {
            "mode": meta["mode"],
            "advisory_only": True,
            "configured": meta["configured"],
            "model": meta.get("model"),
            "risk_level": "UNKNOWN",
            "vulnerabilities": [],
            "suggested_tests": [],
            "recommendation": None,
            "disclaimer": meta["label"],
            "error": None,
        },
        "stages": initial_stages(),
        "findings": [],
        "advisory_findings": [],
        "generated_tests": "",
        "test_plan": [],
        "test_results": [],
        "sandbox": {"status": "pending", "isolation": ISOLATION_PROFILE},
        "storage_backend": store.backend,
        "storage_label": store.label,
        "disclaimer": DISCLAIMER,
        "related_memory": [],
        "memory_retrieval": {},
        "adversarial": {},
        "report": {},
        "component": (body.component or ComponentMetadata()).model_dump(),
        "rerun_of": body.rerun_of,
        "requested_policy_version": body.policy_version,
        "requirements_note": body.requirements,
        "reproducibility": "",
    }
    store.create_run(run)
    if get_settings().sync_verification:
        await asyncio.to_thread(execute, run["run_id"])
    else:
        asyncio.get_running_loop().run_in_executor(None, execute, run["run_id"])
    saved = store.get_run(run["run_id"])
    if saved is None:
        raise HTTPException(status_code=500, detail="Run was not stored.")
    return _public_run(saved)


@app.get("/api/verification/{run_id}")
def get_verification(run_id: str) -> dict:
    run = get_store().get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Verification run not found.")
    return _public_run(run)


@app.get("/api/verification/{run_id}/report")
def verification_report(run_id: str) -> JSONResponse:
    run = get_store().get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Verification run not found.")
    payload = run.get("report") or build_report(run)
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="medguard-{run_id}.json"'},
    )


@app.post("/api/verification/{run_id}/rerun")
async def rerun_verification(run_id: str) -> dict:
    previous = get_store().get_run(run_id)
    if previous is None:
        raise HTTPException(status_code=404, detail="Verification run not found.")
    component = previous.get("component") or None
    body = VerifyRequest(
        code=previous["code"],
        scenario_id=previous.get("scenario_id"),
        policy_version=previous.get("policy_version"),
        requirements=previous.get("requirements_note"),
        component=component,
        rerun_of=run_id,
    )
    return await verify(body)


@app.get("/api/history")
def history() -> dict:
    items = []
    for run in get_store().list_runs():
        items.append(
            HistoryItem(
                run_id=run["run_id"],
                created_at=run["created_at"],
                scenario_id=run.get("scenario_id"),
                decision=run.get("decision"),
                status=run["status"],
                code_sha256=run.get("code_sha256") or "",
                storage_backend=run.get("storage_backend", ""),
                storage_label=run.get("storage_label", ""),
            ).model_dump()
        )
    return {"runs": items}
