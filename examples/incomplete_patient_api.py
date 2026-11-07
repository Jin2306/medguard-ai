"""Synthetic patient API whose dependency is not available in the sandbox.

Verification cannot finish, so MedGuard should return REVIEW.
"""

import clinic_auth_internal


def get_patient(patient_id: str, actor: dict | None = None):
    return clinic_auth_internal.read_patient(patient_id, actor)
