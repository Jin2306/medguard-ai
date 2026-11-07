"""Reproducible verification report. Model text is recorded, not treated as a replay guarantee."""

from __future__ import annotations

REPRODUCIBILITY = (
    "This report stores the code hash, policy version, model identifier, generated tests, "
    "and the sandbox results that produced the decision. "
    "Rerunning the same code and policy repeats the deterministic tests. "
    "Probabilistic model output is not guaranteed to match exactly."
)


def build_report(run: dict) -> dict:
    tests = []
    for item in run.get("test_results") or []:
        tests.append(
            {
                "id": item.get("id"),
                "policy_id": item.get("policy_id"),
                "layer": item.get("layer", "baseline"),
                "mandatory": item.get("mandatory"),
                "counts_as_evidence": item.get("counts_as_evidence", True),
                "outcome": item.get("outcome"),
            }
        )
    memory_refs = []
    for item in (run.get("memory_retrieval") or {}).get("hits") or []:
        memory_refs.append(
            {
                "pattern_id": item.get("pattern_id"),
                "vulnerability_type": item.get("vulnerability_type"),
                "verified": item.get("verified"),
                "evidence_against_new_changes": False,
            }
        )
    ai = run.get("ai") or {}
    return {
        "report_type": "medguard-verification",
        "run_id": run.get("run_id"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
        "code_sha256": run.get("code_sha256"),
        "policy_version": run.get("policy_version"),
        "policy_sha256": run.get("policy_sha256"),
        "model": {
            "mode": ai.get("mode"),
            "identifier": ai.get("model") or ("demo-deterministic" if ai.get("mode") == "demo" else None),
            "advisory_only": True,
            "recommendation": ai.get("recommendation"),
        },
        "component": run.get("component") or {},
        "decision": run.get("decision"),
        "decision_reason": run.get("decision_reason"),
        "static_findings": [
            {
                "policy_id": item.get("policy_id"),
                "source": item.get("source"),
                "confirmed": item.get("confirmed"),
                "line": item.get("line"),
                "description": item.get("description"),
            }
            for item in run.get("findings") or []
        ],
        "generated_test_source": run.get("generated_tests") or "",
        "test_results": tests,
        "sandbox_status": (run.get("sandbox") or {}).get("status"),
        "memory_retrieval_mode": (run.get("memory_retrieval") or {}).get("mode"),
        "security_memory_references": memory_refs,
        "rerun_of": run.get("rerun_of"),
        "reproducibility": REPRODUCIBILITY,
        "disclaimer": run.get("disclaimer"),
    }
