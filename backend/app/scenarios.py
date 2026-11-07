"""Synthetic medical software examples shipped with the demo."""

from __future__ import annotations

from app.config import get_settings
from app.policies import load_requirements, load_synthetic_patients

SCENARIOS = [
    {
        "id": "vulnerable-cross-clinic",
        "title": "Vulnerable patient read",
        "filename": "vulnerable_patient_api.py",
        "expected_decision": "BLOCK",
        "summary": "Clinic A can read a Clinic B patient. Credentials and query strings are also unsafe.",
    },
    {
        "id": "corrected-clinic-scope",
        "title": "Clinic-scoped patient read",
        "filename": "corrected_patient_api.py",
        "expected_decision": "APPROVE",
        "summary": "Authentication, clinician role, and clinic match are enforced before a record is returned.",
    },
    {
        "id": "incomplete-dependency",
        "title": "Incomplete patient read",
        "filename": "incomplete_patient_api.py",
        "expected_decision": "REVIEW",
        "summary": "The code imports a helper that is not in the sandbox, so execution cannot finish.",
    },
]


def list_scenarios() -> list[dict]:
    root = get_settings().root / "examples"
    requirements = load_requirements()
    patients = load_synthetic_patients()
    items = []
    for scenario in SCENARIOS:
        code = (root / scenario["filename"]).read_text(encoding="utf-8")
        items.append(
            {
                **scenario,
                "code": code,
                "requirements": requirements,
                "synthetic_patients": patients,
            }
        )
    return items
