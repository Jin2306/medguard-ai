"""INTENTIONALLY VULNERABLE synthetic patient API.

GET /patients/{patient_id}

A clinician from clinic-a can read Jordan Blake, who belongs to clinic-b.
There is no authentication and no authorization.
"""

import logging

logger = logging.getLogger("patient_api")

API_KEY = "sk-live-clinic-secret-12345"
DB_PASSWORD = "ClinicAdmin!2024"

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


def get_patient(patient_id: str, actor: dict | None = None):
    record = PATIENTS.get(patient_id)
    if record is None:
        return None
    logger.info(
        "Fetched patient %s dob=%s mrn=%s",
        patient_id,
        record["dob"],
        record["mrn"],
    )
    return record


def query_patients(name_filter: str):
    query = f"SELECT * FROM patients WHERE name = '{name_filter}'"
    return [row for row in PATIENTS.values() if name_filter in row["name"]]
