"""Run generated tests in a locked-down container. Never on the host."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from app.config import get_settings

IMAGE = "medguard-sandbox:latest"
SANDBOX_USER = "65532:65532"
TIMEOUT_SECONDS = 45

ISOLATION_PROFILE = {
    "image": IMAGE,
    "network": "none",
    "read_only_root": True,
    "privileged": False,
    "user": SANDBOX_USER,
    "memory": "256m",
    "cpus": "0.5",
    "pids_limit": 64,
    "timeout_seconds": TIMEOUT_SECONDS,
    "host_credentials_mounted": False,
    "capabilities": "ALL dropped",
    "no_new_privileges": True,
}


def build_docker_args(work: Path, out: Path, name: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "0.5",
        "--pids-limit",
        "64",
        "--user",
        SANDBOX_USER,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "--tmpfs",
        "/dev/shm:rw,nosuid,nodev,size=16m",
        "-v",
        f"{work.resolve()}:/work:ro",
        "-v",
        f"{out.resolve()}:/out:rw",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "HOME=/tmp",
        "-e",
        "PYTHONPATH=/work",
        IMAGE,
        "python",
        "-m",
        "pytest",
        "/work/test_security.py",
        "-p",
        "no:cacheprovider",
        "--json-report",
        "--json-report-file",
        "/out/report.json",
        "-q",
    ]


def docker_available() -> dict:
    if shutil.which("docker") is None:
        return {"available": False, "detail": "docker is not installed", "image_ready": False}
    try:
        version = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "detail": str(exc), "image_ready": False}
    if version.returncode != 0:
        detail = (version.stderr or "docker daemon is not reachable").strip()
        return {"available": False, "detail": detail, "image_ready": False}
    image = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
        timeout=5,
    )
    ready = image.returncode == 0
    detail = f"Docker {version.stdout.strip()}"
    if not ready:
        detail += f". Image {IMAGE} is not built, so generated code will not be executed."
    return {"available": True, "detail": detail, "image_ready": ready}


def _parse_report(report_path: Path, plan: list[dict], stdout: str) -> list[dict]:
    by_id = {item["nodeid"].split("::")[-1]: item for item in []}
    if report_path.exists():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        by_id = {}
        for item in payload.get("tests", []):
            nodeid = str(item.get("nodeid", ""))
            test_id = nodeid.split("::")[-1]
            longrepr = ""
            for phase in ("setup", "call", "teardown"):
                phase_body = item.get(phase) or {}
                if phase_body.get("longrepr"):
                    longrepr = str(phase_body["longrepr"])
            by_id[test_id] = {"outcome": item.get("outcome", "error"), "detail": longrepr[:2000]}
    else:
        by_id = _parse_stdout(stdout)

    results = []
    for item in plan:
        found = by_id.get(item["id"])
        if found is None:
            results.append({**item, "outcome": "error", "detail": "Test did not appear in the sandbox report."})
        else:
            results.append({**item, "outcome": found["outcome"], "detail": found.get("detail", "")})
    return results


def _parse_stdout(stdout: str) -> dict:
    found: dict[str, dict] = {}
    for line in stdout.splitlines():
        if "::" not in line:
            continue
        test_id = line.split("::")[-1].split()[0]
        lower = line.lower()
        if " passed" in lower or lower.startswith("passed"):
            outcome = "passed"
        elif " failed" in lower or "failed" in lower:
            outcome = "failed"
        elif " error" in lower or "error" in lower:
            outcome = "error"
        elif " skipped" in lower:
            outcome = "skipped"
        else:
            continue
        found[test_id] = {"outcome": outcome, "detail": line.strip()}
    return found


class DockerSandbox:
    def run(self, code: str, tests_source: str, plan: list[dict]) -> dict:
        probe = docker_available()
        profile = dict(ISOLATION_PROFILE)
        if not probe["available"] or not probe["image_ready"]:
            return {
                "status": "unavailable",
                "reason": probe["detail"],
                "tests": [],
                "stdout": "",
                "stderr": "",
                "duration_ms": 0,
                "docker_argv": [],
                "isolation": profile,
            }

        settings = get_settings()
        run_dir = settings.sandbox_dir / uuid.uuid4().hex
        work = run_dir / "work"
        out = run_dir / "out"
        work.mkdir(parents=True, exist_ok=True)
        out.mkdir(parents=True, exist_ok=True)
        os.chmod(work, 0o755)
        os.chmod(out, 0o777)
        (work / "submitted_code.py").write_text(code, encoding="utf-8")
        (work / "test_security.py").write_text(tests_source, encoding="utf-8")
        os.chmod(work / "submitted_code.py", 0o644)
        os.chmod(work / "test_security.py", 0o644)

        name = f"medguard-{uuid.uuid4().hex[:12]}"
        argv = build_docker_args(work, out, name)
        env = os.environ.copy()
        for secret in ("META_API_KEY", "MONGODB_URI", "MONGO_URI", "MONGODB_URL"):
            env.pop(secret, None)
        import time

        started = time.perf_counter()
        try:
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_SECONDS,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=15)
                return {
                    "status": "error",
                    "reason": f"Sandbox exceeded {TIMEOUT_SECONDS}s and was stopped.",
                    "tests": [],
                    "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
                    "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "docker_argv": argv,
                    "isolation": profile,
                }
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            report = out / "report.json"
            if not report.exists():
                return {
                    "status": "error",
                    "reason": "Sandbox finished without a test report.",
                    "tests": [],
                    "stdout": stdout[-4000:],
                    "stderr": stderr[-4000:],
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "docker_argv": argv,
                    "isolation": profile,
                    "exit_code": proc.returncode,
                }
            tests = _parse_report(report, plan, stdout)
            return {
                "status": "executed",
                "reason": "Tests ran inside the sandbox.",
                "tests": tests,
                "stdout": stdout[-4000:],
                "stderr": stderr[-4000:],
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "docker_argv": argv,
                "isolation": profile,
                "exit_code": proc.returncode,
            }
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
