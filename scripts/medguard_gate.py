"""Exit 0 only when MedGuard approves. Does not merge or deploy."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.engine import execute, initial_stages  # noqa: E402
from app.gate import exit_code_for  # noqa: E402
from app.store import get_store  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/medguard_gate.py <python-file>", file=sys.stderr)
        return 1
    code = Path(sys.argv[1]).read_text(encoding="utf-8")
    os.environ["MEDGUARD_SYNC"] = "1"
    store = get_store()
    now = datetime.now(timezone.utc).isoformat()
    run_id = str(uuid4())
    store.create_run(
        {
            "run_id": run_id,
            "status": "running",
            "created_at": now,
            "updated_at": now,
            "scenario_id": None,
            "filename": Path(sys.argv[1]).name,
            "code": code,
            "code_sha256": "",
            "policy_version": "",
            "policy_sha256": "",
            "decision": None,
            "decision_reason": "",
            "ai": {
                "mode": "demo",
                "advisory_only": True,
                "configured": False,
                "model": None,
                "risk_level": "UNKNOWN",
                "vulnerabilities": [],
                "suggested_tests": [],
                "recommendation": None,
                "disclaimer": "",
                "error": None,
            },
            "stages": initial_stages(),
            "findings": [],
            "advisory_findings": [],
            "generated_tests": "",
            "test_plan": [],
            "test_results": [],
            "sandbox": {"status": "pending"},
            "storage_backend": store.backend,
            "storage_label": store.label,
            "disclaimer": "",
            "related_memory": [],
            "component": {"name": Path(sys.argv[1]).stem, "version": "unspecified", "language": "python"},
        }
    )
    finished = execute(run_id)
    decision = finished.get("decision")
    print(json.dumps({"run_id": run_id, "decision": decision, "reason": finished.get("decision_reason")}, indent=2))
    return exit_code_for(decision)


if __name__ == "__main__":
    raise SystemExit(main())
