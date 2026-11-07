"""Deterministic static checks and Semgrep. These are evidence. Model text is not."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.config import get_settings

SECRET_NAME = re.compile(r"(password|api_key|secret|token)", re.IGNORECASE)
SENSITIVE = {"dob", "mrn", "ssn", "diagnosis", "date_of_birth", "social_security"}
LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical"}


def _finding(
    *,
    policy_id: str,
    title: str,
    severity: str,
    source: str,
    confirmed: bool,
    description: str,
    recommendation: str,
    line: int | None,
) -> dict:
    return {
        "policy_id": policy_id,
        "title": title,
        "severity": severity,
        "source": source,
        "confirmed": confirmed,
        "description": description,
        "recommendation": recommendation,
        "line": line,
    }


def _names(node: ast.AST) -> set[str]:
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id.lower())
        elif isinstance(child, ast.Attribute):
            found.add(child.attr.lower())
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.add(child.value.lower())
    return found


def _assigned_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    return ""


def builtin_analysis(source: str) -> dict:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"parse_error": f"{exc.msg} (line {exc.lineno})", "findings": []}

    findings: list[dict] = []
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 4:
            for target in targets:
                name = _assigned_name(target)
                if name and SECRET_NAME.search(name):
                    findings.append(
                        _finding(
                            policy_id="POL-05",
                            title="Hardcoded credentials",
                            severity="CRITICAL",
                            source="builtin",
                            confirmed=True,
                            description=f"{name} is assigned a string literal.",
                            recommendation="Load credentials from a secret store or the environment.",
                            line=getattr(node, "lineno", None),
                        )
                    )
        if isinstance(node, ast.JoinedStr):
            literals = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if re.search(r"select\s+", literals, re.IGNORECASE):
                findings.append(
                    _finding(
                        policy_id="POL-07",
                        title="Unsafe database queries",
                        severity="HIGH",
                        source="builtin",
                        confirmed=True,
                        description="A SQL statement is built with an f-string.",
                        recommendation="Use parameterized queries. Do not format user input into SQL.",
                        line=getattr(node, "lineno", None),
                    )
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in LOG_METHODS and _names(node) & SENSITIVE:
                findings.append(
                    _finding(
                        policy_id="POL-06",
                        title="Sensitive information in application logs",
                        severity="HIGH",
                        source="builtin",
                        confirmed=True,
                        description="A log call includes a sensitive field such as dob, mrn, or ssn.",
                        recommendation="Log identifiers only. Keep clinical values out of logs.",
                        line=getattr(node, "lineno", None),
                    )
                )

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "get_patient":
            continue
        names = _names(node)
        compares = [item for item in ast.walk(node) if isinstance(item, ast.Compare)]
        clinic_compared = any("clinic_id" in _names(item) for item in compares)
        has_auth = "authenticated" in names or "require_auth" in names
        has_validation = any(
            isinstance(item, ast.Attribute) and item.attr in {"match", "fullmatch"}
            for item in ast.walk(node)
        )
        if not has_auth:
            findings.append(
                _finding(
                    policy_id="POL-03",
                    title="Missing authentication",
                    severity="HIGH",
                    source="builtin_heuristic",
                    confirmed=False,
                    description="get_patient does not reference an authentication check. This is a lead, not proof.",
                    recommendation="Reject callers that are not authenticated before reading a record.",
                    line=node.lineno,
                )
            )
        if not clinic_compared:
            findings.append(
                _finding(
                    policy_id="POL-02",
                    title="Cross-clinic data exposure",
                    severity="CRITICAL",
                    source="builtin_heuristic",
                    confirmed=False,
                    description="get_patient does not compare the caller clinic with the record clinic. This is a lead, not proof.",
                    recommendation="Return a record only when actor clinic_id equals the patient clinic_id.",
                    line=node.lineno,
                )
            )
            findings.append(
                _finding(
                    policy_id="POL-04",
                    title="Missing authorization",
                    severity="HIGH",
                    source="builtin_heuristic",
                    confirmed=False,
                    description="No clinic-scoped authorization comparison was found on get_patient. This is a lead, not proof.",
                    recommendation="Require a clinician role and a matching clinic before returning a record.",
                    line=node.lineno,
                )
            )
        if not has_validation:
            findings.append(
                _finding(
                    policy_id="POL-08",
                    title="Missing input validation",
                    severity="MEDIUM",
                    source="builtin_heuristic",
                    confirmed=False,
                    description="get_patient does not match the patient id against an explicit pattern. This is a lead, not proof.",
                    recommendation="Reject patient ids that do not match the expected format.",
                    line=node.lineno,
                )
            )
    return {"parse_error": None, "findings": findings}


def semgrep_available() -> dict:
    binary = shutil.which("semgrep")
    if not binary:
        venv_binary = get_settings().root / ".venv" / "bin" / "semgrep"
        if venv_binary.exists():
            binary = str(venv_binary)
    if not binary:
        return {"available": False, "status": "unavailable", "detail": "semgrep is not installed"}
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=8,
            env=_semgrep_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "status": "unavailable", "detail": str(exc)}
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    error_lines = [line.strip() for line in (proc.stderr or "").splitlines() if line.strip()]
    detail = lines[-1] if proc.returncode == 0 and lines else (error_lines[-1] if error_lines else "semgrep")
    return {
        "available": proc.returncode == 0,
        "status": "available" if proc.returncode == 0 else "unavailable",
        "detail": detail,
        "binary": binary,
    }


def _semgrep_env() -> dict:
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    for secret in ("META_API_KEY", "MONGODB_URI", "MONGO_URI", "MONGODB_URL"):
        env.pop(secret, None)
    return env


def run_semgrep(source: str) -> dict:
    probe = semgrep_available()
    if not probe.get("available"):
        return {"status": "unavailable", "findings": [], "detail": probe.get("detail", "semgrep unavailable")}

    rules = get_settings().root / "policies" / "semgrep.yml"
    with tempfile.TemporaryDirectory(prefix="medguard-semgrep-") as tmp:
        target = Path(tmp) / "submitted_code.py"
        target.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                probe["binary"],
                "scan",
                "--disable-version-check",
                "--metrics",
                "off",
                "--config",
                str(rules),
                "--json",
                "--quiet",
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=40,
            env=_semgrep_env(),
        )
    if proc.returncode not in {0, 1}:
        detail = (proc.stderr or proc.stdout or "semgrep failed").strip()
        return {"status": "error", "findings": [], "detail": detail[:1500]}
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "error", "findings": [], "detail": "Semgrep did not return JSON."}
    if payload.get("errors"):
        return {
            "status": "error",
            "findings": [],
            "detail": json.dumps(payload["errors"])[:1500],
        }

    findings = []
    for result in payload.get("results", []):
        check_id = str(result.get("check_id", ""))
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        policy_id = str(metadata.get("policy_id") or "POL-UNKNOWN")
        findings.append(
            _finding(
                policy_id=policy_id,
                title=check_id.split(".")[-1],
                severity=str(extra.get("severity") or "ERROR"),
                source="semgrep",
                confirmed=True,
                description=str(extra.get("message") or check_id),
                recommendation="Fix the pattern Semgrep reported, then re-run verification.",
                line=(result.get("start") or {}).get("line"),
            )
        )
    return {"status": "completed", "findings": findings, "detail": f"{len(findings)} semgrep finding(s)"}


def analyze_static(source: str) -> dict:
    builtin = builtin_analysis(source)
    semgrep = run_semgrep(source)
    findings = list(builtin["findings"]) + list(semgrep["findings"])
    return {
        "parse_error": builtin.get("parse_error"),
        "semgrep_status": semgrep["status"],
        "semgrep_detail": semgrep.get("detail", ""),
        "findings": findings,
    }
