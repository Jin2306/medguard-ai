"""Verification pipeline. The decision is computed from evidence, never from model advice."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from app.adversarial import build_adversarial_layer
from app.config import DISCLAIMER
from app.decision import decide
from app.memory import memory_document
from app.meta_client import analyze_with_meta, propose_adversarial_tests
from app.policies import load_policies, load_requirements
from app.report import REPRODUCIBILITY, build_report
from app.sandbox import DockerSandbox
from app.static_analysis import analyze_static
from app.store import get_store
from app.testgen import generate_tests

logger = logging.getLogger("medguard.engine")
sandbox = DockerSandbox()

STAGE_DEFS = [
    ("ingest", "Ingest code"),
    ("policies", "Load security policies"),
    ("static_analysis", "Static analysis"),
    ("meta_ai", "Independent model review"),
    ("test_generation", "Generate security tests"),
    ("sandbox", "Sandbox execution"),
    ("decision", "Verification decision"),
    ("persist", "Store evidence"),
]


def initial_stages() -> list[dict]:
    return [{"id": stage_id, "label": label, "status": "pending", "detail": ""} for stage_id, label in STAGE_DEFS]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_stage(run_id: str, stage_id: str, status: str, detail: str = "") -> None:
    store = get_store()
    run = store.get_run(run_id)
    if run is None:
        return
    for stage in run["stages"]:
        if stage["id"] == stage_id:
            stage["status"] = status
            stage["detail"] = detail
    store.update_run(run_id, {"stages": run["stages"], "updated_at": _now()})


def execute(run_id: str) -> dict:
    store = get_store()
    try:
        return _execute(run_id)
    except Exception as exc:
        logger.exception("verification failed for %s", run_id)
        current = store.get_run(run_id) or {}
        stages = current.get("stages") or initial_stages()
        for stage in stages:
            if stage["status"] in {"pending", "running"}:
                stage["status"] = "failed"
                stage["detail"] = "Stopped because verification raised an error."
                break
        store.update_run(
            run_id,
            {
                "status": "error",
                "decision": "REVIEW",
                "decision_reason": "Verification failed before a decision could be proven: " + str(exc)[:500],
                "stages": stages,
                "updated_at": _now(),
            },
        )
        return store.get_run(run_id) or {}


def _execute(run_id: str) -> dict:
    store = get_store()
    run = store.get_run(run_id)
    if run is None:
        raise KeyError(run_id)
    code = run["code"]

    _set_stage(run_id, "ingest", "running", "Hashing the submitted code.")
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    _set_stage(run_id, "ingest", "completed", digest[:12])

    _set_stage(run_id, "policies", "running", "Loading the medical software policy pack.")
    policies = load_policies()
    requirements = load_requirements()
    if run.get("requirements_note"):
        requirements = {**requirements, "caller_supplied_requirements": run["requirements_note"]}
    _set_stage(run_id, "policies", "completed", policies["version"])

    _set_stage(run_id, "static_analysis", "running", "Running built-in rules and Semgrep.")
    static = analyze_static(code)
    findings = static["findings"]
    confirmed = [item for item in findings if item.get("confirmed") and item.get("source") in {"builtin", "semgrep"}]
    static_detail = f"Semgrep {static['semgrep_status']}. {len(confirmed)} confirmed finding(s)."
    if static.get("parse_error"):
        static_detail = "Code did not parse: " + static["parse_error"]
    _set_stage(run_id, "static_analysis", "completed" if static["semgrep_status"] != "error" else "failed", static_detail)

    _set_stage(run_id, "meta_ai", "running", "Searching security memory, then requesting an independent review.")
    memory_retrieval = store.search_memory(
        "cross-clinic patient authorization clinic_id role leakage " + requirements.get("summary", "")
    )
    ai = analyze_with_meta(
        code=code,
        requirements=requirements,
        policies=policies,
        static_findings=findings,
    )
    ai_detail = ai.get("disclaimer", "")[:180]
    if ai.get("error"):
        _set_stage(run_id, "meta_ai", "failed", ai["error"][:180])
    else:
        _set_stage(run_id, "meta_ai", "completed", f"{ai['mode']} advisory: {ai.get('recommendation')}. {ai_detail}")

    _set_stage(run_id, "test_generation", "running", "Generating baseline tests and validating adversarial tests.")
    generated = generate_tests()
    strategies = [
        str(hit.get("successful_test_strategy") or hit.get("strategy") or "")
        for hit in memory_retrieval.get("hits") or []
    ]
    proposal = propose_adversarial_tests(
        code=code,
        requirements=requirements,
        policies=policies,
        memory_strategies=strategies,
    )
    adversarial = build_adversarial_layer(
        meta_source=proposal.get("source"),
        meta_error=proposal.get("error"),
        meta_mode=proposal.get("mode") or "demo",
        memory_hits=memory_retrieval.get("hits") or [],
    )
    for item in generated["plan"]:
        item.setdefault("layer", "baseline")
        item.setdefault("counts_as_evidence", True)
    test_source = generated["source"]
    test_plan = list(generated["plan"])
    if adversarial["source"]:
        test_source = test_source + "\n\n" + adversarial["source"]
        test_plan.extend(adversarial["plan"])
    _set_stage(run_id, "test_generation", "completed", adversarial["label"])

    _set_stage(run_id, "sandbox", "running", "Executing tests with no network, a read-only root, and a non-root user.")
    sandbox_result = sandbox.run(code, test_source, test_plan)
    if sandbox_result["status"] == "executed":
        failed = sum(1 for item in sandbox_result["tests"] if item["outcome"] == "failed")
        _set_stage(run_id, "sandbox", "completed", f"Executed. {failed} failed test(s).")
    elif sandbox_result["status"] == "unavailable":
        _set_stage(run_id, "sandbox", "incomplete", sandbox_result["reason"])
    else:
        _set_stage(run_id, "sandbox", "failed", sandbox_result["reason"])

    _set_stage(run_id, "decision", "running", "Comparing evidence with the policy. Ignoring model advice as proof.")
    decision, reason = decide(
        sandbox_status=sandbox_result["status"],
        tests=sandbox_result["tests"],
        confirmed_findings=confirmed,
        semgrep_status=static["semgrep_status"],
    )
    requested_policy = run.get("requested_policy_version")
    if requested_policy and requested_policy != policies["version"]:
        decision = "REVIEW"
        reason = (
            f"Requested policy version {requested_policy} is not loaded. "
            f"MedGuard ran {policies['version']} and will not treat that as the requested policy. "
            "The model advisory was not used as proof."
        )
    _set_stage(run_id, "decision", "completed", decision)

    advisory = []
    for vuln in ai.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        advisory.append(
            {
                "policy_id": "ADVISORY",
                "title": str(vuln.get("type") or "Advisory"),
                "severity": str(vuln.get("severity") or "UNKNOWN"),
                "source": "demo_mode" if ai.get("mode") == "demo" else "meta_ai",
                "confirmed": False,
                "description": str(vuln.get("description") or ""),
                "recommendation": str(vuln.get("recommendation") or ""),
                "line": None,
            }
        )

    _set_stage(run_id, "persist", "running", "Writing the run, the audit log, and security memory.")
    timestamp = _now()
    for test in sandbox_result["tests"]:
        if test.get("outcome") != "failed" or test.get("counts_as_evidence", True) is False:
            continue
        document = memory_document(
            test.get("policy_id") or "POL-UNKNOWN",
            run_id=run_id,
            code_sha256=digest,
            timestamp=timestamp,
            verified=True,
        )
        document["test_id"] = test.get("id")
        store.remember(document)
    if decision == "APPROVE":
        store.remember(
            {
                "pattern_id": "policy_suite",
                "vulnerability_type": "Verified Fix",
                "severity": "INFO",
                "failure_pattern": "",
                "successful_test_strategy": "Keep authentication, clinic comparison, role checks, input validation, safe logging, and parameterized data access.",
                "recommended_fix": "Preserve the clinic-scoped controls that passed.",
                "verified": True,
                "outcome": "fix",
                "run_id": run_id,
                "code_sha256": digest,
                "timestamp": timestamp,
                "evidence_against_new_changes": False,
            }
        )
    store.add_audit(
        {
            "run_id": run_id,
            "decision": decision,
            "policy_version": policies["version"],
            "policy_sha256": policies["sha256"],
            "timestamp": timestamp,
            "evidence": {
                "code_sha256": digest,
                "semgrep_status": static["semgrep_status"],
                "confirmed_findings": len(confirmed),
                "sandbox_status": sandbox_result["status"],
                "test_results": [
                    {"id": item["id"], "outcome": item["outcome"]} for item in sandbox_result["tests"]
                ],
            },
        }
    )
    _set_stage(run_id, "persist", "completed", store.label)

    store.update_run(
        run_id,
        {
            "status": "completed",
            "updated_at": timestamp,
            "code_sha256": digest,
            "policy_version": policies["version"],
            "policy_sha256": policies["sha256"],
            "decision": decision,
            "decision_reason": reason,
            "ai": ai,
            "findings": findings,
            "advisory_findings": advisory,
            "generated_tests": test_source,
            "test_plan": test_plan,
            "test_results": sandbox_result["tests"],
            "sandbox": sandbox_result,
            "related_memory": store.memory_for(digest),
            "memory_retrieval": memory_retrieval,
            "adversarial": {
                "origin": adversarial["origin"],
                "label": adversarial["label"],
                "validation": adversarial["validation"],
                "rejected": adversarial["rejected"],
                "proposal_mode": proposal.get("mode"),
            },
            "component": run.get("component") or {},
            "reproducibility": REPRODUCIBILITY,
            "disclaimer": DISCLAIMER,
        },
    )
    finished = store.get_run(run_id) or {}
    store.update_run(run_id, {"report": build_report(finished)})
    logger.info("run %s decision %s sandbox %s", run_id, decision, sandbox_result["status"])
    return store.get_run(run_id) or {}
