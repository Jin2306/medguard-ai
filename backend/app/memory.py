"""Security-memory retrieval.

Historical findings are context for new tests. They are never evidence that the
current change is vulnerable. Atlas Vector Search is used only when a real
vector query succeeds. Otherwise the mode is an ordinary query or local keywords.
"""

from __future__ import annotations

import os
import re
from typing import Any

CATALOG = {
    "POL-01": {
        "vulnerability_type": "Unauthorized Patient Record Access",
        "severity": "CRITICAL",
        "failure_pattern": "Patient read is not limited to the caller's own record",
        "successful_test_strategy": "Request a patient the caller is not allowed to see",
        "recommended_fix": "Authorize the specific patient before returning the record",
    },
    "POL-02": {
        "vulnerability_type": "Cross-Clinic Data Exposure",
        "severity": "CRITICAL",
        "failure_pattern": "Missing clinic_id authorization check",
        "successful_test_strategy": "Attempt patient retrieval using another clinic's identity",
        "recommended_fix": "Enforce clinic-scoped access controls",
    },
    "POL-03": {
        "vulnerability_type": "Missing Authentication",
        "severity": "HIGH",
        "failure_pattern": "get_patient accepts an unauthenticated caller",
        "successful_test_strategy": "Call get_patient with no authenticated actor",
        "recommended_fix": "Reject callers that are not authenticated",
    },
    "POL-04": {
        "vulnerability_type": "Incorrect Role Permissions",
        "severity": "HIGH",
        "failure_pattern": "A non-clinician role can read patient records",
        "successful_test_strategy": "Request a record as a receptionist",
        "recommended_fix": "Allow only the clinician role to read records",
    },
    "POL-05": {
        "vulnerability_type": "Hardcoded Credentials",
        "severity": "CRITICAL",
        "failure_pattern": "Secret assigned from a string literal",
        "successful_test_strategy": "Scan source for credential assignments",
        "recommended_fix": "Load secrets from a secret store",
    },
    "POL-06": {
        "vulnerability_type": "Sensitive Data Leakage",
        "severity": "HIGH",
        "failure_pattern": "Date of birth or MRN written to logs or responses",
        "successful_test_strategy": "Read the record and inspect logs and the returned body",
        "recommended_fix": "Keep clinical values out of logs and cross-clinic responses",
    },
    "POL-07": {
        "vulnerability_type": "Unsafe Input Handling",
        "severity": "HIGH",
        "failure_pattern": "SQL built with an f-string",
        "successful_test_strategy": "Reject source that formats user input into SQL",
        "recommended_fix": "Use parameterized queries",
    },
    "POL-08": {
        "vulnerability_type": "Unsafe Input Handling",
        "severity": "MEDIUM",
        "failure_pattern": "Patient id is not validated",
        "successful_test_strategy": "Submit a patient id that includes a quote and SQL fragment",
        "recommended_fix": "Reject ids that do not match the expected pattern",
    },
    "REQ-ALLOW": {
        "vulnerability_type": "Authorized Access Broken",
        "severity": "HIGH",
        "failure_pattern": "A clinician cannot read a patient in their own clinic",
        "successful_test_strategy": "Read p-100 as an authenticated clinic-a clinician",
        "recommended_fix": "Allow the in-clinic clinician path after the checks succeed",
    },
}

TEXT_FIELDS = (
    "vulnerability_type",
    "failure_pattern",
    "successful_test_strategy",
    "recommended_fix",
    "pattern_id",
    "strategy",
    "outcome",
)


def memory_document(policy_id: str, *, run_id: str, code_sha256: str, timestamp: str, verified: bool) -> dict:
    profile = CATALOG.get(policy_id, {
        "vulnerability_type": policy_id,
        "severity": "HIGH",
        "failure_pattern": "Mandatory security test failed",
        "successful_test_strategy": "Re-run the independent policy test",
        "recommended_fix": "Fix the failing control and verify again",
    })
    return {
        **profile,
        "pattern_id": policy_id,
        "verified": verified,
        "outcome": "failure" if verified else "unconfirmed",
        "run_id": run_id,
        "code_sha256": code_sha256,
        "timestamp": timestamp,
        "evidence_against_new_changes": False,
    }


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


def keyword_hits(entries: list[dict], query: str, limit: int = 5) -> list[dict]:
    wanted = _tokens(query)
    scored: list[tuple[int, dict]] = []
    for entry in entries:
        blob = " ".join(str(entry.get(field, "")) for field in TEXT_FIELDS)
        overlap = wanted & _tokens(blob)
        if overlap:
            hit = dict(entry)
            hit.pop("_id", None)
            hit["match_terms"] = sorted(overlap)
            hit["evidence_against_new_changes"] = False
            scored.append((len(overlap), hit))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [item for _score, item in scored[:limit]]


def vector_configuration() -> dict:
    index = os.environ.get("MONGODB_VECTOR_INDEX", "").strip()
    embed_url = os.environ.get("EMBEDDING_URL", "").strip()
    if index and embed_url:
        return {"state": "configured", "index": index, "embedding_endpoint_set": True}
    missing = []
    if not index:
        missing.append("MONGODB_VECTOR_INDEX")
    if not embed_url:
        missing.append("EMBEDDING_URL")
    return {"state": "not_configured", "missing": missing, "embedding_endpoint_set": bool(embed_url)}


def capability_label(backend: str) -> dict:
    vector = vector_configuration()
    if backend == "mongodb_atlas":
        mode = "mongodb_index"
        label = "Ordinary indexed MongoDB query. Atlas Vector Search is not active."
    else:
        mode = "local_keyword"
        label = "Keyword retrieval on the local fallback. Not MongoDB Atlas and not Atlas Vector Search."
    if vector["state"] == "configured" and backend == "mongodb_atlas":
        label = "Atlas Vector Search is configured and will be attempted before the indexed query."
    elif vector["state"] == "not_configured":
        label += " Missing " + ", ".join(vector["missing"]) + "."
    return {"mode": mode, "label": label, "vector_search": vector["state"]}


def _embed(url: str, text: str) -> list[float]:
    import httpx

    response = httpx.post(url, json={"input": text}, timeout=20.0)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload.get("embedding"), list):
        return [float(value) for value in payload["embedding"]]
    data = payload.get("data") or []
    if data and isinstance(data[0].get("embedding"), list):
        return [float(value) for value in data[0]["embedding"]]
    raise ValueError("Embedding endpoint did not return an embedding list.")


def try_vector_search(db: Any, query: str) -> dict:
    config = vector_configuration()
    if config["state"] != "configured":
        return {"ok": False, "attempted": False, "reason": "not_configured"}
    if db is None:
        return {"ok": False, "attempted": False, "reason": "atlas_not_connected"}
    try:
        vector = _embed(os.environ["EMBEDDING_URL"].strip(), query)
        cursor = db.security_memory.aggregate(
            [
                {
                    "$vectorSearch": {
                        "index": os.environ["MONGODB_VECTOR_INDEX"].strip(),
                        "path": "embedding",
                        "queryVector": vector,
                        "numCandidates": 20,
                        "limit": 5,
                    }
                }
            ]
        )
        hits = []
        for item in cursor:
            item.pop("_id", None)
            item.pop("embedding", None)
            item["evidence_against_new_changes"] = False
            hits.append(item)
        return {"ok": True, "attempted": True, "hits": hits}
    except Exception as exc:
        return {"ok": False, "attempted": True, "reason": str(exc)[:400]}


def mongo_keyword_query(db: Any, query: str) -> list[dict]:
    tokens = list(_tokens(query))[:6]
    if not tokens:
        return []
    clauses = []
    for token in tokens:
        pattern = re.escape(token)
        for field in ("vulnerability_type", "failure_pattern", "successful_test_strategy", "pattern_id"):
            clauses.append({field: {"$regex": pattern, "$options": "i"}})
    found = []
    for item in db.security_memory.find({"$or": clauses}).limit(8):
        item.pop("_id", None)
        item["evidence_against_new_changes"] = False
        found.append(item)
    return found


def retrieve(query: str, entries: list[dict], *, backend: str, db: Any = None) -> dict:
    vector = try_vector_search(db, query) if backend == "mongodb_atlas" else {"ok": False, "attempted": False, "reason": "not_configured"}
    if vector.get("ok"):
        return {
            "mode": "atlas_vector",
            "label": "Retrieved with MongoDB Atlas Vector Search.",
            "vector_search": "active",
            "hits": vector["hits"],
            "disclaimer": "These are similar past failures. They are not proof that this change is vulnerable.",
        }
    if backend == "mongodb_atlas" and db is not None:
        try:
            hits = mongo_keyword_query(db, query)
        except Exception as exc:
            hits = keyword_hits(entries, query)
            return {
                "mode": "local_keyword",
                "label": "The Atlas query failed, so keyword matching used the in-memory copy. Nothing was treated as vector search.",
                "vector_search": "failed" if vector.get("attempted") else vector_configuration()["state"],
                "vector_error": vector.get("reason") or str(exc)[:400],
                "hits": hits,
                "disclaimer": "These are similar past failures. They are not proof that this change is vulnerable.",
            }
        label = "Ordinary MongoDB query on security_memory. Atlas Vector Search was not used."
        vector_state = "failed" if vector.get("attempted") else "not_configured"
        if vector.get("attempted"):
            label = "Atlas Vector Search failed (" + str(vector.get("reason")) + "). Fell back to an ordinary MongoDB query."
        return {
            "mode": "mongodb_index",
            "label": label,
            "vector_search": vector_state,
            "vector_error": vector.get("reason"),
            "hits": hits,
            "disclaimer": "These are similar past failures. They are not proof that this change is vulnerable.",
        }
    return {
        "mode": "local_keyword",
        "label": "Keyword retrieval on the local fallback. Not MongoDB Atlas and not Atlas Vector Search.",
        "vector_search": "not_configured",
        "hits": keyword_hits(entries, query),
        "disclaimer": "These are similar past failures. They are not proof that this change is vulnerable.",
    }
