"""Synthetic patient records API with clinic-scoped authorization.

GET /patients/{patient_id}

- Unauthenticated callers are rejected.
- Only the clinician role may read records.
- A clinician may read patients in their own clinic only.
- Patient ids must match p-###.
- Logs carry ids only.
"""

import logging
import re

logger = logging.getLogger("patient_api")

PATIENT_ID_RE = re.compile(r"^p-\d{3}$")

PATIENTS = {
    "p-100": {
        "patient_id": "p-100",
        "name": "Alex Rivera",
        "clinic_id": "clinic-a",
        "dob": "1984-03-12",
        "mrn": "MRN-A-100",
    },
    "p-200": {
        "patient_id": "p-200",
        "name": "Jordan Blake",
        "clinic_id": "clinic-b",
        "dob": "1990-11-02",
        "mrn": "MRN-B-200",
    },
}


class AuthError(Exception):
    """Authentication failed."""


class AuthorizationError(Exception):
    """Caller is not allowed to read this record."""


def get_patient(patient_id: str, actor: dict | None = None):
    if not isinstance(actor, dict) or not actor.get("authenticated") or not actor.get("user_id"):
        raise AuthError("Authentication required")
    if "clinician" not in set(actor.get("roles") or []):
        raise AuthorizationError("Clinician role required")
    if not isinstance(patient_id, str) or not PATIENT_ID_RE.fullmatch(patient_id):
        raise ValueError("Invalid patient id")
    record = PATIENTS.get(patient_id)
    if record is None:
        return None
    if actor.get("clinic_id") != record.get("clinic_id"):
        raise AuthorizationError("Cross-clinic access denied")
    logger.info("Fetched patient_id=%s clinic_id=%s", patient_id, record["clinic_id"])
    return {
        "patient_id": record["patient_id"],
        "name": record["name"],
        "clinic_id": record["clinic_id"],
    }
