"""Persistence for verification runs, security memory, and audit logs.

MongoDB Atlas is used when MONGODB_URI connects. Otherwise the store is an
explicit local fallback and never claims the records were written to Atlas.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any

from app.config import get_settings
from app.memory import capability_label, retrieve

_store: "RunStore | None" = None
_guard = threading.Lock()


def redact_secret(text: str) -> str:
    return re.sub(r"://[^@\s/]+@", "://***@", text)


def reset_store() -> None:
    global _store
    with _guard:
        _store = None


def get_store() -> "RunStore":
    global _store
    with _guard:
        if _store is None:
            _store = RunStore()
        return _store


class RunStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}
        self._memory: list[dict] = []
        self._audits: list[dict] = []
        self.backend = "local_fallback"
        self.label = (
            "Local fallback. MongoDB credentials are not configured, so nothing is written to MongoDB Atlas."
        )
        self.error: str | None = None
        self._client: Any = None
        self._db: Any = None
        settings = get_settings()
        self._path = settings.data_dir / "local_store.json"
        self._db_name = settings.mongodb_db
        self._connect(settings.mongodb_uri)

    def _connect(self, uri: str) -> None:
        if not uri:
            self._load_file()
            return
        try:
            from pymongo import MongoClient

            client = MongoClient(uri, serverSelectionTimeoutMS=2000)
            client.admin.command("ping")
            self._client = client
            self._db = client[self._db_name]
            self.backend = "mongodb_atlas"
            self.label = f"Connected to MongoDB Atlas database '{self._db_name}'."
            self._db.verification_runs.create_index("created_at")
            self._db.audit_logs.create_index("timestamp")
            self._db.security_memory.create_index("pattern_id")
            self._db.security_memory.create_index("vulnerability_type")
            self._load_mongo()
        except Exception as exc:
            self.backend = "local_fallback"
            self.error = redact_secret(str(exc))
            self.label = (
                "MongoDB credentials were found, but Atlas could not be reached. "
                "Using a local fallback. Nothing was written to MongoDB Atlas."
            )
            self._client = None
            self._db = None
            self._load_file()

    def _load_file(self) -> None:
        if not self._path.exists():
            return
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for run in payload.get("verification_runs", []):
            self._runs[run["run_id"]] = run
        self._memory = list(payload.get("security_memory", []))
        self._audits = list(payload.get("audit_logs", []))

    def _load_mongo(self) -> None:
        for run in self._db.verification_runs.find().sort("created_at", -1).limit(50):
            run.pop("_id", None)
            self._runs[run["run_id"]] = run
        self._memory = []
        for item in self._db.security_memory.find().sort("timestamp", -1).limit(100):
            item.pop("_id", None)
            self._memory.append(item)
        self._audits = []
        for item in self._db.audit_logs.find().sort("timestamp", -1).limit(100):
            item.pop("_id", None)
            self._audits.append(item)

    def _flush_local(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "backend": "local_fallback",
            "notice": "These records were NOT written to MongoDB Atlas.",
            "verification_runs": list(self._runs.values()),
            "security_memory": self._memory[-200:],
            "audit_logs": self._audits[-200:],
        }
        self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _persist_run(self, run: dict) -> None:
        if self.backend == "mongodb_atlas" and self._db is not None:
            try:
                document = dict(run)
                document["_id"] = run["run_id"]
                self._db.verification_runs.replace_one({"_id": run["run_id"]}, document, upsert=True)
                run["storage_backend"] = "mongodb_atlas"
                run["storage_label"] = self.label
                return
            except Exception as exc:
                self.backend = "local_fallback"
                self.error = redact_secret(str(exc))
                self.label = (
                    "An Atlas write failed. This run was copied to the local fallback and was not saved to MongoDB Atlas."
                )
        run["storage_backend"] = "local_fallback"
        run["storage_label"] = self.label
        self._flush_local()

    def create_run(self, run: dict) -> dict:
        with self._lock:
            run["storage_backend"] = self.backend
            run["storage_label"] = self.label
            self._runs[run["run_id"]] = run
            self._persist_run(run)
            return dict(run)

    def update_run(self, run_id: str, patch: dict) -> dict:
        with self._lock:
            current = self._runs[run_id]
            current.update(patch)
            current["storage_backend"] = self.backend if "storage_backend" not in patch else patch["storage_backend"]
            self._persist_run(current)
            return dict(current)

    def get_run(self, run_id: str) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
            return dict(run) if run else None

    def list_runs(self) -> list[dict]:
        with self._lock:
            runs = sorted(self._runs.values(), key=lambda item: item.get("created_at", ""), reverse=True)
            return [dict(item) for item in runs[:50]]

    def add_audit(self, entry: dict) -> None:
        with self._lock:
            self._audits.append(entry)
            if self.backend == "mongodb_atlas" and self._db is not None:
                try:
                    self._db.audit_logs.insert_one(dict(entry))
                    return
                except Exception as exc:
                    self.error = redact_secret(str(exc))
                    self.label = (
                        "An Atlas audit write failed. The audit entry was kept in the local fallback and was not saved to MongoDB Atlas."
                    )
                    self.backend = "local_fallback"
            self._flush_local()

    def remember(self, entry: dict) -> None:
        with self._lock:
            self._memory.append(entry)
            if self.backend == "mongodb_atlas" and self._db is not None:
                try:
                    self._db.security_memory.insert_one(dict(entry))
                    return
                except Exception as exc:
                    self.error = redact_secret(str(exc))
                    self.label = (
                        "An Atlas memory write failed. The memory entry was kept in the local fallback and was not saved to MongoDB Atlas."
                    )
                    self.backend = "local_fallback"
            self._flush_local()

    def memory_for(self, code_sha256: str) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._memory if item.get("code_sha256") == code_sha256]

    def search_memory(self, query: str) -> dict:
        with self._lock:
            entries = [dict(item) for item in self._memory]
            backend = self.backend
            db = self._db
        return retrieve(query, entries, backend=backend, db=db)

    def status(self) -> dict:
        retrieval = capability_label(self.backend)
        return {
            "backend": self.backend,
            "label": self.label,
            "configured": get_settings().mongodb_uri != "",
            "error": self.error,
            "atlas": self.backend == "mongodb_atlas",
            "retrieval_mode": retrieval["mode"],
            "retrieval_label": retrieval["label"],
            "vector_search": retrieval["vector_search"],
        }
