from app.adversarial import build_adversarial_layer, validate_test_source
from app.decision import decide
from app.memory import keyword_hits, memory_document, retrieve
from app.gate import exit_code_for
from app.report import build_report


def test_validator_rejects_network_and_shell():
    rejected = validate_test_source("import os\n\ndef test_bad():\n    os.system('curl http://example')\n")
    assert rejected["ok"] is False


def test_deterministic_adversarial_layer_is_valid_without_meta():
    layer = build_adversarial_layer(meta_source=None, meta_error=None, meta_mode="demo", memory_hits=[])
    assert layer["origin"] == "deterministic_fallback"
    assert layer["validation"]["ok"] is True
    assert "test_adv_cross_clinic_patient_leak" in layer["source"]
    assert any(item["id"] == "test_adv_cross_clinic_patient_leak" and item["mandatory"] for item in layer["plan"])
    assert "DEMO MODE" in layer["rejected"][0]["reason"]


def test_invalid_meta_tests_are_not_included():
    layer = build_adversarial_layer(
        meta_source="import subprocess\n\ndef test_meta_bad():\n    subprocess.call(['id'])\n",
        meta_error=None,
        meta_mode="live",
        memory_hits=[],
    )
    assert "subprocess" not in layer["source"]
    assert layer["origin"] == "deterministic_fallback"
    assert layer["rejected"]


def test_ai_severity_does_not_decide_and_non_evidence_failures_do_not_block():
    decision, reason = decide(
        sandbox_status="executed",
        tests=[
            {"id": "baseline", "mandatory": True, "outcome": "passed", "counts_as_evidence": True},
            {"id": "hypothesis", "mandatory": False, "outcome": "failed", "counts_as_evidence": False},
        ],
        confirmed_findings=[],
        semgrep_status="completed",
    )
    assert decision == "APPROVE"
    assert "not used as proof" in reason


def test_memory_retrieval_is_local_and_not_vector_search():
    entries = [
        memory_document(
            "POL-02",
            run_id="old",
            code_sha256="abc",
            timestamp="2026-01-01T00:00:00+00:00",
            verified=True,
        )
    ]
    result = retrieve("cross-clinic authorization", entries, backend="local_fallback", db=None)
    assert result["mode"] == "local_keyword"
    assert result["vector_search"] == "not_configured"
    assert "Vector Search" in result["label"]
    assert result["hits"]
    assert result["hits"][0]["evidence_against_new_changes"] is False
    assert keyword_hits(entries, "unrelated-topic-zzz") == []


def test_report_contains_actual_evidence_fields():
    report = build_report(
        {
            "run_id": "run-1",
            "created_at": "t",
            "updated_at": "t",
            "code_sha256": "abc",
            "policy_version": "medguard-policy-2026.1",
            "policy_sha256": "def",
            "decision": "BLOCK",
            "decision_reason": "tests failed",
            "ai": {"mode": "demo", "model": None, "recommendation": "BLOCK"},
            "findings": [{"policy_id": "POL-02", "source": "semgrep", "confirmed": True, "line": 1, "description": "x"}],
            "generated_tests": "def test_adv_cross_clinic_patient_leak():\n    pass\n",
            "test_results": [{"id": "test_adv_cross_clinic_patient_leak", "policy_id": "POL-02", "mandatory": True, "outcome": "failed", "layer": "adversarial_deterministic"}],
            "sandbox": {"status": "executed"},
            "memory_retrieval": {"mode": "local_keyword", "hits": [{"pattern_id": "POL-02", "verified": True}]},
            "disclaimer": "synthetic",
        }
    )
    assert report["code_sha256"] == "abc"
    assert report["policy_version"] == "medguard-policy-2026.1"
    assert report["model"]["identifier"] == "demo-deterministic"
    assert report["test_results"][0]["outcome"] == "failed"
    assert report["sandbox_status"] == "executed"
    assert "not guaranteed" in report["reproducibility"]
    assert report["security_memory_references"][0]["evidence_against_new_changes"] is False


def test_gate_passes_only_on_approve():
    assert exit_code_for("APPROVE") == 0
    assert exit_code_for("BLOCK") == 1
    assert exit_code_for("REVIEW") == 1
