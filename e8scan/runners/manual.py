"""Manual check runner — for controls that cannot be technically verified."""

from __future__ import annotations

from e8scan.models import CheckDefinition, CheckResult, ResultStatus


def run(check: CheckDefinition) -> CheckResult:
    """Return a MANUAL result with guidance text."""
    guidance = str(check.check.get("guidance", "Verify manually in your environment."))
    return CheckResult(
        check=check,
        status=ResultStatus.MANUAL,
        actual_value="<manual verification required>",
        message=guidance,
    )
