from app.decision import decide


def _passed_suite():
    return [
        {"id": f"t{index}", "mandatory": True, "outcome": "passed"}
        for index in range(9)
    ]


def test_failed_tests_block_even_if_a_model_would_approve():
    decision, reason = decide(
        sandbox_status="executed",
        tests=[{"id": "test_pol02_cross_clinic_exposure", "mandatory": True, "outcome": "failed"}],
        confirmed_findings=[],
        semgrep_status="completed",
    )
    assert decision == "BLOCK"
    assert "not used as proof" in reason


def test_confirmed_static_finding_blocks_when_tests_pass():
    decision, _reason = decide(
        sandbox_status="executed",
        tests=_passed_suite(),
        confirmed_findings=[{"policy_id": "POL-05", "confirmed": True}],
        semgrep_status="completed",
    )
    assert decision == "BLOCK"


def test_approve_requires_execution_semgrep_and_passing_tests():
    decision, reason = decide(
        sandbox_status="executed",
        tests=_passed_suite(),
        confirmed_findings=[],
        semgrep_status="completed",
    )
    assert decision == "APPROVE"
    assert "HIPAA" in reason


def test_missing_sandbox_is_review_even_with_static_findings():
    decision, _reason = decide(
        sandbox_status="unavailable",
        tests=[],
        confirmed_findings=[{"policy_id": "POL-05", "confirmed": True}],
        semgrep_status="completed",
    )
    assert decision == "REVIEW"


def test_semgrep_not_completed_cannot_approve():
    decision, _reason = decide(
        sandbox_status="executed",
        tests=_passed_suite(),
        confirmed_findings=[],
        semgrep_status="unavailable",
    )
    assert decision == "REVIEW"


def test_test_errors_are_review_not_block():
    decision, _reason = decide(
        sandbox_status="executed",
        tests=[{"id": "test_pol03_authentication_required", "mandatory": True, "outcome": "error"}],
        confirmed_findings=[],
        semgrep_status="completed",
    )
    assert decision == "REVIEW"
