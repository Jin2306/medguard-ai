"""Adversarial tests. Deterministic tests always run. Model tests run only after validation."""

from __future__ import annotations

import ast
import json
import re

from app.policies import load_synthetic_patients

FORBIDDEN_IMPORTS = {
    "os",
    "subprocess",
    "socket",
    "sys",
    "shutil",
    "requests",
    "httpx",
    "urllib",
    "pathlib",
    "pickle",
    "ctypes",
    "importlib",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "remove", "unlink", "rmdir"}
ALLOWED_IMPORTS = {"pytest", "re", "logging"}


def validate_test_source(source: str, *, existing_names: set[str] | None = None) -> dict:
    errors: list[str] = []
    if not source or len(source) > 8_000:
        errors.append("Adversarial test source is empty or too large.")
        return {"ok": False, "errors": errors, "names": []}
    if re.search(r"https?://|socket\.", source, re.IGNORECASE):
        errors.append("Network endpoints are not allowed in generated tests.")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"ok": False, "errors": [f"Syntax error: {exc.msg} (line {exc.lineno})"], "names": []}
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in ALLOWED_IMPORTS:
                    errors.append(f"Import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root not in ALLOWED_IMPORTS:
                errors.append(f"Import not allowed: {node.module}")
        elif isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if called in FORBIDDEN_CALLS:
                errors.append(f"Call not allowed: {called}")
        elif isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            names.append(node.name)
            if existing_names and node.name in existing_names:
                errors.append(f"Duplicate test name: {node.name}")
    if not names:
        errors.append("Generated source has no test_ function.")
    return {"ok": not errors, "errors": errors, "names": names}


def deterministic_fragment() -> dict:
    patients = load_synthetic_patients()
    own = patients["patients"][0]
    other = patients["patients"][1]
    source = FRAGMENT
    replacements = {
        "__OWN_ID__": json.dumps(own["patient_id"]),
        "__OWN_CLINIC__": json.dumps(own["clinic_id"]),
        "__OTHER_ID__": json.dumps(other["patient_id"]),
        "__OTHER_CLINIC__": json.dumps(other["clinic_id"]),
        "__OWN_DOB__": json.dumps(own["dob"]),
        "__OWN_MRN__": json.dumps(own["mrn"]),
    }
    for key, value in replacements.items():
        source = source.replace(key, value)
    plan = [
        {
            "id": "test_adv_cross_clinic_patient_leak",
            "policy_id": "POL-02",
            "title": "Adversarial cross-clinic patient leakage",
            "mandatory": True,
            "layer": "adversarial_deterministic",
            "counts_as_evidence": True,
        },
        {
            "id": "test_adv_sensitive_response_leakage",
            "policy_id": "POL-06",
            "title": "Adversarial sensitive field leakage",
            "mandatory": False,
            "layer": "adversarial_deterministic",
            "counts_as_evidence": True,
        },
        {
            "id": "test_adv_wrong_role_cannot_read",
            "policy_id": "POL-04",
            "title": "Adversarial incorrect role",
            "mandatory": False,
            "layer": "adversarial_deterministic",
            "counts_as_evidence": True,
        },
        {
            "id": "test_adv_unauthorized_modification",
            "policy_id": "POL-01",
            "title": "Adversarial unauthorized modification",
            "mandatory": False,
            "layer": "adversarial_deterministic",
            "counts_as_evidence": True,
        },
    ]
    return {"source": source, "plan": plan, "origin": "deterministic_fallback"}


def build_adversarial_layer(*, meta_source: str | None, meta_error: str | None, meta_mode: str, memory_hits: list[dict]) -> dict:
    base = deterministic_fragment()
    notes = []
    for hit in memory_hits[:5]:
        strategy = str(hit.get("successful_test_strategy") or hit.get("strategy") or "").replace("\n", " ")
        if strategy:
            notes.append("# Past strategy (not evidence against this change): " + strategy[:240])
    header = "\n".join(
        [
            "# MedGuard adversarial layer.",
            "# Origin of the extra model tests is recorded separately.",
            "# Historical memory informed generation and is not proof.",
            *notes,
            "",
        ]
    )
    pieces = [header, base["source"]]
    plan = list(base["plan"])
    validation = validate_test_source(base["source"])
    rejected = []
    origin = "deterministic_fallback" if meta_mode != "live" else "meta_plus_deterministic"
    if meta_mode != "live":
        rejected.append(
            {
                "origin": "meta",
                "accepted": False,
                "reason": "DEMO MODE. Meta did not generate tests because credentials are not configured.",
            }
        )
    elif meta_error:
        rejected.append({"origin": "meta", "accepted": False, "reason": meta_error[:500]})
        origin = "deterministic_fallback"
    elif meta_source:
        existing = {item["id"] for item in plan}
        checked = validate_test_source(meta_source, existing_names=existing)
        if checked["ok"]:
            pieces.append(meta_source.strip() + "\n")
            for name in checked["names"]:
                plan.append(
                    {
                        "id": name,
                        "policy_id": "ADVERSARIAL",
                        "title": "Meta adversarial test " + name,
                        "mandatory": False,
                        "layer": "adversarial_meta",
                        "counts_as_evidence": True,
                    }
                )
        else:
            rejected.append({"origin": "meta", "accepted": False, "reason": "; ".join(checked["errors"])})
            origin = "deterministic_fallback"
    combined = "\n".join(pieces)
    if not validation["ok"]:
        return {
            "source": "",
            "plan": [],
            "origin": "rejected",
            "validation": validation,
            "rejected": rejected,
            "label": "Deterministic adversarial tests failed validation and were not executed.",
        }
    label = "Deterministic adversarial tests validated for sandbox execution."
    if any(item["layer"] == "adversarial_meta" for item in plan):
        label = "Meta adversarial tests passed validation and were added to the deterministic suite."
    elif meta_mode == "live":
        label = "Meta adversarial output was not executed. The deterministic suite was used instead."
    return {
        "source": combined,
        "plan": plan,
        "origin": origin,
        "validation": validation,
        "rejected": rejected,
        "label": label,
    }


FRAGMENT = '''
import pytest


def test_adv_cross_clinic_patient_leak(api):
    """Clinic A employee requests a Clinic B patient. Access must be denied."""
    own_clinic = __OWN_CLINIC__
    other_id = __OTHER_ID__
    other_clinic = __OTHER_CLINIC__
    actor = {
        "user_id": "employee-" + own_clinic,
        "authenticated": True,
        "clinic_id": own_clinic,
        "roles": ["clinician"],
    }
    try:
        result = api.get_patient(other_id, actor)
    except Exception as exc:
        blob = (type(exc).__name__ + " " + str(exc)).lower()
        assert any(token in blob for token in ("auth", "permission", "forbidden", "denied"))
        return
    leaked = repr(result).lower()
    assert other_id.lower() not in leaked, "Clinic B patient was returned to Clinic A: %r" % (result,)
    assert other_clinic.lower() not in leaked, "Cross-clinic record was returned: %r" % (result,)


def test_adv_sensitive_response_leakage(api):
    own_id = __OWN_ID__
    own_clinic = __OWN_CLINIC__
    actor = {
        "user_id": "employee-" + own_clinic,
        "authenticated": True,
        "clinic_id": own_clinic,
        "roles": ["clinician"],
    }
    result = api.get_patient(own_id, actor)
    blob = repr(result).lower()
    assert __OWN_DOB__.lower() not in blob
    assert __OWN_MRN__.lower() not in blob


def test_adv_wrong_role_cannot_read(api):
    own_id = __OWN_ID__
    own_clinic = __OWN_CLINIC__
    actor = {
        "user_id": "receptionist-" + own_clinic,
        "authenticated": True,
        "clinic_id": own_clinic,
        "roles": ["receptionist"],
    }
    try:
        result = api.get_patient(own_id, actor)
    except Exception as exc:
        blob = (type(exc).__name__ + " " + str(exc)).lower()
        assert any(token in blob for token in ("auth", "permission", "forbidden", "denied"))
        return
    pytest.fail("Wrong role received a record: %r" % (result,))


def test_adv_unauthorized_modification(api):
    if not hasattr(api, "update_patient"):
        pytest.skip("submitted code has no update_patient")
    own_clinic = __OWN_CLINIC__
    other_id = __OTHER_ID__
    actor = {
        "user_id": "employee-" + own_clinic,
        "authenticated": True,
        "clinic_id": own_clinic,
        "roles": ["clinician"],
    }
    try:
        result = api.update_patient(other_id, {"name": "mutated"}, actor)
    except Exception as exc:
        blob = (type(exc).__name__ + " " + str(exc)).lower()
        assert any(token in blob for token in ("auth", "permission", "forbidden", "denied"))
        return
    pytest.fail("Cross-clinic modification was accepted: %r" % (result,))
'''
