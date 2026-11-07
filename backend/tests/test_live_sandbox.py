import pytest

from app.config import ROOT
from app.engine import execute
from app.sandbox import docker_available
from app.scenarios import list_scenarios
from app.store import get_store, reset_store


def _scenario(scenario_id: str) -> dict:
    return next(item for item in list_scenarios() if item["id"] == scenario_id)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MEDGUARD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MEDGUARD_SANDBOX_DIR", str(ROOT / ".sandbox-runs"))
    for name in ("MONGODB_URI", "MONGO_URI", "MONGODB_URL", "META_API_KEY", "META_MODEL", "META_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    reset_store()
    yield get_store()
    reset_store()


@pytest.mark.skipif(not docker_available()["image_ready"], reason="medguard-sandbox image is not built")
def test_live_sandbox_blocks_vulnerable_and_approves_corrected(store):
    from app.engine import initial_stages
    from datetime import datetime, timezone

    results = {}
    for scenario_id in ("vulnerable-cross-clinic", "corrected-clinic-scope", "incomplete-dependency"):
        scenario = _scenario(scenario_id)
        now = datetime.now(timezone.utc).isoformat()
        run_id = scenario_id
        store.create_run(
            {
                "run_id": run_id,
                "status": "running",
                "created_at": now,
                "updated_at": now,
                "scenario_id": scenario_id,
                "filename": "submitted_code.py",
                "code": scenario["code"],
                "code_sha256": "",
                "policy_version": "medguard-policy-2026.1",
                "policy_sha256": "",
                "decision": None,
                "decision_reason": "",
                "ai": {
                    "mode": "demo",
                    "advisory_only": True,
                    "configured": False,
                    "model": None,
                    "risk_level": "UNKNOWN",
                    "vulnerabilities": [],
                    "suggested_tests": [],
                    "recommendation": None,
                    "disclaimer": "pending",
                    "error": None,
                },
                "stages": initial_stages(),
                "findings": [],
                "advisory_findings": [],
                "generated_tests": "",
                "test_plan": [],
                "test_results": [],
                "sandbox": {"status": "pending"},
                "storage_backend": store.backend,
                "storage_label": store.label,
                "disclaimer": "synthetic",
                "related_memory": [],
            }
        )
        finished = execute(run_id)
        results[scenario_id] = finished

    assert results["vulnerable-cross-clinic"]["decision"] == "BLOCK"
    assert results["vulnerable-cross-clinic"]["sandbox"]["status"] == "executed"
    failed = [item["id"] for item in results["vulnerable-cross-clinic"]["test_results"] if item["outcome"] == "failed"]
    assert "test_pol02_cross_clinic_exposure" in failed
    assert "test_adv_cross_clinic_patient_leak" in failed
    assert results["vulnerable-cross-clinic"]["ai"]["advisory_only"] is True
    assert results["vulnerable-cross-clinic"]["storage_backend"] == "local_fallback"
    assert results["vulnerable-cross-clinic"]["report"]["code_sha256"]
    assert results["vulnerable-cross-clinic"]["report"]["test_results"]

    assert results["corrected-clinic-scope"]["decision"] == "APPROVE"
    corrected = results["corrected-clinic-scope"]["test_results"]
    mandatory = [item for item in corrected if item.get("mandatory")]
    assert mandatory and all(item["outcome"] == "passed" for item in mandatory)
    cross = next(item for item in corrected if item["id"] == "test_adv_cross_clinic_patient_leak")
    assert cross["outcome"] == "passed"

    assert results["incomplete-dependency"]["decision"] == "REVIEW"
    assert results["incomplete-dependency"]["sandbox"]["status"] == "executed"
