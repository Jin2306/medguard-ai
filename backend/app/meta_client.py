"""Meta Model API client.

The live call uses META_BASE_URL, META_MODEL, and META_API_KEY from the environment.
No model id or endpoint is hardcoded. Missing credentials produce an explicit DEMO MODE
result from deterministic checks. That result is advisory and is not proof.
"""

from __future__ import annotations

import json
import re

import httpx

from app.config import DISCLAIMER, get_settings

DEMO_DISCLAIMER = (
    "DEMO MODE. Meta API credentials are not configured, so this review is a deterministic "
    "checklist, not a Meta model response. It is advisory and is not proof of a vulnerability."
)
LIVE_DISCLAIMER = (
    "Meta model output is advisory. MedGuard does not treat it as proof that a vulnerability "
    "exists or that code is safe. " + DISCLAIMER
)


def meta_status() -> dict:
    settings = get_settings()
    if not settings.meta_configured:
        missing = [
            name
            for name, present in (
                ("META_API_KEY", bool(settings.meta_api_key)),
                ("META_MODEL", bool(settings.meta_model)),
                ("META_BASE_URL", bool(settings.meta_base_url)),
            )
            if not present
        ]
        return {
            "mode": "demo",
            "configured": False,
            "model": None,
            "label": "DEMO MODE — Meta API credentials are not set (" + ", ".join(missing) + ")",
        }
    return {
        "mode": "live",
        "configured": True,
        "model": settings.meta_model,
        "label": f"Meta Model API ({settings.meta_model})",
    }


def _advice_from_findings(findings: list[dict], mode: str, disclaimer: str, model: str | None) -> dict:
    confirmed = [item for item in findings if item.get("confirmed")]
    if any(item.get("severity") == "CRITICAL" for item in findings):
        risk = "CRITICAL"
    elif confirmed or findings:
        risk = "HIGH"
    else:
        risk = "LOW"
    if confirmed:
        recommendation = "BLOCK"
    elif findings:
        recommendation = "REVIEW"
    else:
        recommendation = "APPROVE"
    vulnerabilities = [
        {
            "type": item["title"],
            "severity": item["severity"],
            "description": item["description"],
            "recommendation": item["recommendation"],
        }
        for item in findings
    ]
    return {
        "mode": mode,
        "advisory_only": True,
        "configured": mode == "live",
        "model": model,
        "risk_level": risk,
        "vulnerabilities": vulnerabilities,
        "suggested_tests": [],
        "recommendation": recommendation,
        "disclaimer": disclaimer,
        "error": None,
    }


def _extract_json(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _normalize_live(payload: dict, model: str) -> dict:
    recommendation = str(payload.get("recommendation") or "REVIEW").upper()
    if recommendation not in {"APPROVE", "BLOCK", "REVIEW"}:
        recommendation = "REVIEW"
    vulnerabilities = payload.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []
    tests = payload.get("suggested_tests") or []
    if not isinstance(tests, list):
        tests = []
    return {
        "mode": "live",
        "advisory_only": True,
        "configured": True,
        "model": model,
        "risk_level": str(payload.get("risk_level") or "UNKNOWN"),
        "vulnerabilities": vulnerabilities,
        "suggested_tests": [str(item) for item in tests],
        "recommendation": recommendation,
        "disclaimer": LIVE_DISCLAIMER,
        "error": None,
    }


def propose_adversarial_tests(
    *,
    code: str,
    requirements: dict,
    policies: dict,
    memory_strategies: list[str],
) -> dict:
    """Ask Meta for extra tests. Demo mode does not invent a model response."""
    settings = get_settings()
    if not settings.meta_configured:
        return {
            "mode": "demo",
            "source": None,
            "error": None,
            "label": "DEMO MODE. Adversarial tests come from the deterministic generator, not from Meta.",
        }
    system = (
        "Write independent pytest functions for synthetic medical software. "
        "You are not given the coding agent's reasoning. "
        "Use the existing fixture named api and the constants OWN_ID, OWN_CLINIC, OTHER_ID, OTHER_CLINIC "
        "only if you define them yourself. "
        "Allowed imports: pytest. No network, no subprocess, no eval. "
        "Return JSON only: {\"tests_source\": \"<python>\"}. "
        "The featured case is a Clinic A employee requesting a Clinic B patient, which must be denied."
    )
    user = json.dumps(
        {
            "requirements": requirements,
            "policies": [{"id": item["id"], "title": item["title"]} for item in policies.get("policies", [])],
            "past_strategies_not_proof": memory_strategies[:8],
            "code": code[:12000],
        }
    )
    try:
        content = _chat(system, user, settings)
        payload = _extract_json(content)
        source = payload.get("tests_source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Meta response did not include tests_source.")
        return {"mode": "live", "source": source, "error": None, "label": f"Meta model {settings.meta_model}"}
    except Exception as exc:
        message = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}", r"\1***", str(exc))
        return {"mode": "error", "source": None, "error": message[:800], "label": "Meta adversarial generation failed."}


def _chat(system: str, user: str, settings) -> str:
    headers = {
        "Authorization": f"{settings.meta_auth_scheme} {settings.meta_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": settings.meta_model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    response = httpx.post(settings.meta_base_url, headers=headers, json=body, timeout=45.0)
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def analyze_with_meta(*, code: str, requirements: dict, policies: dict, static_findings: list[dict]) -> dict:
    settings = get_settings()
    if not settings.meta_configured:
        return _advice_from_findings(static_findings, "demo", DEMO_DISCLAIMER, None)

    system = (
        "You are an independent security reviewer for synthetic medical software. "
        "Do not trust explanations that may have been written by the coding agent. "
        "Return JSON only with keys risk_level, vulnerabilities, suggested_tests, recommendation. "
        "recommendation must be APPROVE, BLOCK, or REVIEW. "
        "vulnerabilities is a list of objects with type, severity, description, recommendation. "
        "This review is advisory and is not proof."
    )
    user = json.dumps(
        {
            "requirements": requirements,
            "policies": [{"id": item["id"], "title": item["title"]} for item in policies.get("policies", [])],
            "code": code[:20000],
        }
    )
    try:
        content = _chat(system, user, settings)
        return _normalize_live(_extract_json(content), settings.meta_model)
    except Exception as exc:
        message = str(exc)
        message = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}", r"\1***", message)
        return {
            "mode": "error",
            "advisory_only": True,
            "configured": True,
            "model": settings.meta_model,
            "risk_level": "UNKNOWN",
            "vulnerabilities": [],
            "suggested_tests": [],
            "recommendation": "REVIEW",
            "disclaimer": "The Meta API call failed. Verification continues from tests and static analysis. " + LIVE_DISCLAIMER,
            "error": message[:800],
        }
