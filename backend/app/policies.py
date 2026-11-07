"""Load the medical software security policy pack."""

from __future__ import annotations

import hashlib
import json

from app.config import get_settings


def load_policies() -> dict:
    path = get_settings().root / "policies" / "medical_security_policies.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    payload["path"] = str(path.name)
    return payload


def load_requirements() -> dict:
    path = get_settings().root / "examples" / "security_requirements.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_synthetic_patients() -> dict:
    path = get_settings().root / "examples" / "synthetic_patients.json"
    return json.loads(path.read_text(encoding="utf-8"))
