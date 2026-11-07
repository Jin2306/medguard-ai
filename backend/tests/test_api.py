from app.store import redact_secret


def test_health_labels_demo_mode_and_local_fallback(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["meta_ai"]["mode"] == "demo"
    assert body["meta_ai"]["configured"] is False
    assert "DEMO MODE" in body["meta_ai"]["label"]
    assert body["mongodb"]["backend"] == "local_fallback"
    assert body["mongodb"]["atlas"] is False
    assert "not" in body["mongodb"]["label"].lower() or "Nothing" in body["mongodb"]["label"]
    assert "Atlas" in body["mongodb"]["label"]
    assert body["mongodb"]["retrieval_mode"] == "local_keyword"
    assert body["mongodb"]["vector_search"] == "not_configured"


def test_scenarios_endpoint(client):
    response = client.get("/api/demo/scenarios")
    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["scenarios"]]
    assert ids == ["vulnerable-cross-clinic", "corrected-clinic-scope", "incomplete-dependency"]


def test_model_approval_does_not_override_failed_tests(client, monkeypatch):
    def fake_meta(**_kwargs):
        return {
            "mode": "live",
            "advisory_only": True,
            "configured": True,
            "model": "configured-by-env",
            "risk_level": "LOW",
            "vulnerabilities": [],
            "suggested_tests": ["trust the coding agent"],
            "recommendation": "APPROVE",
            "disclaimer": "advisory",
            "error": None,
        }

    def fake_static(_source):
        return {"parse_error": None, "semgrep_status": "completed", "semgrep_detail": "", "findings": []}

    def fake_sandbox(_code, _tests, plan):
        tests = []
        for item in plan:
            outcome = "failed" if item["policy_id"] == "POL-02" else "passed"
            tests.append({**item, "outcome": outcome, "detail": "cross clinic returned a record"})
        return {
            "status": "executed",
            "reason": "mocked",
            "tests": tests,
            "stdout": "",
            "stderr": "",
            "duration_ms": 1,
            "docker_argv": [],
            "isolation": {},
        }

    monkeypatch.setattr("app.engine.analyze_with_meta", fake_meta)
    monkeypatch.setattr("app.engine.analyze_static", fake_static)
    monkeypatch.setattr("app.engine.sandbox.run", fake_sandbox)

    scenarios = client.get("/api/demo/scenarios").json()["scenarios"]
    vulnerable = next(item for item in scenarios if item["id"] == "vulnerable-cross-clinic")
    response = client.post(
        "/api/verify",
        json={"code": vulnerable["code"], "scenario_id": vulnerable["id"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BLOCK"
    assert body["ai"]["recommendation"] == "APPROVE"
    assert body["ai"]["advisory_only"] is True
    assert body["storage_backend"] == "local_fallback"
    assert "Atlas" in body["storage_label"]
    assert all(item["confirmed"] is False for item in body["advisory_findings"])

    fetched = client.get(f"/api/verification/{body['run_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["decision"] == "BLOCK"
    history = client.get("/api/history").json()["runs"]
    assert history[0]["run_id"] == body["run_id"]
    assert history[0]["storage_backend"] == "local_fallback"


def test_passing_evidence_approves_even_if_model_says_block(client, monkeypatch):
    def fake_meta(**_kwargs):
        return {
            "mode": "demo",
            "advisory_only": True,
            "configured": False,
            "model": None,
            "risk_level": "CRITICAL",
            "vulnerabilities": [
                {
                    "type": "Broken Access Control",
                    "severity": "CRITICAL",
                    "description": "Unproven claim.",
                    "recommendation": "Block it.",
                }
            ],
            "suggested_tests": [],
            "recommendation": "BLOCK",
            "disclaimer": "DEMO MODE",
            "error": None,
        }

    def fake_static(_source):
        return {"parse_error": None, "semgrep_status": "completed", "findings": []}

    def fake_sandbox(_code, _tests, plan):
        return {
            "status": "executed",
            "reason": "mocked",
            "tests": [{**item, "outcome": "passed", "detail": ""} for item in plan],
            "stdout": "",
            "stderr": "",
            "duration_ms": 1,
            "docker_argv": [],
            "isolation": {},
        }

    monkeypatch.setattr("app.engine.analyze_with_meta", fake_meta)
    monkeypatch.setattr("app.engine.analyze_static", fake_static)
    monkeypatch.setattr("app.engine.sandbox.run", fake_sandbox)
    response = client.post("/api/verify", json={"code": "def get_patient(patient_id, actor=None):\n    return {}\n"})
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "APPROVE"
    assert body["ai"]["recommendation"] == "BLOCK"
    assert body["advisory_findings"][0]["confirmed"] is False
    assert body["adversarial"]["origin"] == "deterministic_fallback"
    assert body["memory_retrieval"]["mode"] == "local_keyword"
    assert "test_adv_cross_clinic_patient_leak" in body["generated_tests"]
    report = client.get(f"/api/verification/{body['run_id']}/report")
    assert report.status_code == 200
    assert report.json()["decision"] == "APPROVE"
    assert report.json()["code_sha256"]
    assert report.json()["sandbox_status"] == "executed"


def test_docker_unavailable_reviews_instead_of_approving(client, monkeypatch):
    monkeypatch.setattr(
        "app.engine.sandbox.run",
        lambda *_args, **_kwargs: {
            "status": "unavailable",
            "reason": "Docker is not available.",
            "tests": [],
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "docker_argv": [],
            "isolation": {},
        },
    )
    monkeypatch.setattr(
        "app.engine.analyze_static",
        lambda _source: {"parse_error": None, "semgrep_status": "completed", "findings": []},
    )
    response = client.post("/api/verify", json={"code": "print('synthetic')\n"})
    assert response.json()["decision"] == "REVIEW"


def test_local_store_file_does_not_claim_atlas(client, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "app.engine.sandbox.run",
        lambda *_args, **_kwargs: {
            "status": "unavailable",
            "reason": "mocked",
            "tests": [],
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "docker_argv": [],
            "isolation": {},
        },
    )
    monkeypatch.setattr(
        "app.engine.analyze_static",
        lambda _source: {"parse_error": None, "semgrep_status": "completed", "findings": []},
    )
    client.post("/api/verify", json={"code": "x = 1\n"})
    raw = (tmp_path / "local_store.json").read_text(encoding="utf-8")
    assert "NOT written to MongoDB Atlas" in raw


def test_uri_redaction():
    assert "s3cret" not in redact_secret("mongodb+srv://user:s3cret@cluster.example.net/medguard")
