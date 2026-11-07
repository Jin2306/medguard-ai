"""Map evidence to APPROVE, BLOCK, or REVIEW.

Model advice is intentionally not an argument. A model cannot approve or block code.
"""

from __future__ import annotations


def decide(
    *,
    sandbox_status: str,
    tests: list[dict],
    confirmed_findings: list[dict],
    semgrep_status: str,
) -> tuple[str, str]:
    if sandbox_status != "executed":
        return (
            "REVIEW",
            "Generated tests were not executed in the sandbox, so verification is incomplete. "
            "Static analysis is attached and is not treated as a final block or approval. "
            "The model advisory was not used as proof.",
        )

    evidence = [item for item in tests if item.get("counts_as_evidence", True) is not False]
    failures = [item for item in evidence if item.get("outcome") == "failed"]
    if failures or confirmed_findings:
        parts = []
        if failures:
            parts.append(f"{len(failures)} security test(s) failed")
        if confirmed_findings:
            parts.append(f"{len(confirmed_findings)} confirmed static finding(s)")
        return (
            "BLOCK",
            "BLOCK: " + "; ".join(parts) + ". AI severity labels were not the decision. The model advisory was not used as proof.",
        )

    mandatory = [item for item in evidence if item.get("mandatory")]
    incomplete = [
        item for item in mandatory if item.get("outcome") not in {"passed"}
    ]
    if not mandatory or incomplete or semgrep_status != "completed":
        reason = "Verification is inconclusive."
        if semgrep_status != "completed":
            reason = "Semgrep did not complete, so a mandatory static check is missing."
        if incomplete:
            reason = "One or more mandatory tests did not pass cleanly."
        return (
            "REVIEW",
            reason + " MedGuard will not approve incomplete evidence. The model advisory was not used as proof.",
        )

    return (
        "APPROVE",
        "APPROVE: every mandatory security test passed, Semgrep completed with no blocking findings, "
        "and the built-in static checks found no confirmed policy violations. "
        "The model advisory was not used as proof. This is not a HIPAA determination.",
    )
