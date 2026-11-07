"""Decision gate used by the local CLI and GitHub Actions. It does not merge or deploy."""


def exit_code_for(decision: str | None) -> int:
    return 0 if decision == "APPROVE" else 1
