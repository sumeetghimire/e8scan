"""File existence/content/permissions check runner."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from e8scan.models import CheckDefinition, CheckResult, ResultStatus


def run(check: CheckDefinition) -> CheckResult:
    """Run a file-based check."""
    cfg = check.check
    path_str = str(cfg.get("path", ""))
    operator = str(cfg.get("operator", "exists"))
    expected = cfg.get("expected")

    if not path_str:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message="File check missing 'path' field",
        )

    path = Path(os.path.expandvars(os.path.expanduser(path_str)))

    if operator == "exists":
        exists = path.exists()
        return CheckResult(
            check=check,
            status=ResultStatus.PASS if exists else ResultStatus.FAIL,
            actual_value=str(exists),
            message="" if exists else f"File not found: {path}",
        )

    elif operator == "not_exists":
        exists = path.exists()
        return CheckResult(
            check=check,
            status=ResultStatus.PASS if not exists else ResultStatus.FAIL,
            actual_value=str(exists),
            message="" if not exists else f"File should not exist but does: {path}",
        )

    elif operator in ("contains", "not_contains", "regex"):
        if not path.exists():
            return CheckResult(
                check=check,
                status=ResultStatus.FAIL,
                actual_value="<file not found>",
                message=f"File not found: {path}",
            )
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except PermissionError as exc:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                message=f"Permission denied reading {path}: {exc}",
            )

        if operator == "contains":
            passed = str(expected) in content
        elif operator == "not_contains":
            passed = str(expected) not in content
        else:  # regex
            passed = bool(re.search(str(expected), content, re.MULTILINE))

        return CheckResult(
            check=check,
            status=ResultStatus.PASS if passed else ResultStatus.FAIL,
            actual_value=content[:100] + "..." if len(content) > 100 else content,
            message="" if passed else f"Content check failed ({operator}): {expected!r}",
        )

    elif operator == "permissions":
        if not path.exists():
            return CheckResult(
                check=check,
                status=ResultStatus.FAIL,
                actual_value="<file not found>",
                message=f"File not found: {path}",
            )
        try:
            mode = oct(stat.S_IMODE(path.stat().st_mode))
            passed = mode == str(expected)
            return CheckResult(
                check=check,
                status=ResultStatus.PASS if passed else ResultStatus.FAIL,
                actual_value=mode,
                message="" if passed else f"Expected permissions {expected}, got {mode}",
            )
        except PermissionError as exc:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                message=f"Permission denied stat {path}: {exc}",
            )

    else:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Unknown file operator: {operator}",
        )
