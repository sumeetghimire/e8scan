"""Service running/enabled state check runner."""

from __future__ import annotations

import subprocess
import sys

from e8scan.models import CheckDefinition, CheckResult, ResultStatus


def run(check: CheckDefinition) -> CheckResult:
    """Check whether a system service is running or enabled."""
    cfg = check.check
    service_name = str(cfg.get("name", ""))
    expected_state = str(cfg.get("expected_state", "running")).lower()

    if not service_name:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message="Service check missing 'name' field",
        )

    if sys.platform == "win32":
        return _check_windows_service(check, service_name, expected_state)
    else:
        return _check_systemd_service(check, service_name, expected_state)


def _check_windows_service(check: CheckDefinition, name: str, expected_state: str) -> CheckResult:
    try:
        result = subprocess.run(
            ["sc", "query", name],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout.lower()
        if "state" not in output:
            return CheckResult(
                check=check,
                status=ResultStatus.FAIL,
                actual_value="<service not found>",
                message=f"Service not found: {name}",
            )

        running = "running" in output
        if expected_state == "running":
            return CheckResult(
                check=check,
                status=ResultStatus.PASS if running else ResultStatus.FAIL,
                actual_value="running" if running else "not running",
                message="" if running else f"Service '{name}' is not running",
            )
        elif expected_state == "stopped":
            return CheckResult(
                check=check,
                status=ResultStatus.PASS if not running else ResultStatus.FAIL,
                actual_value="running" if running else "stopped",
                message="" if not running else f"Service '{name}' should be stopped but is running",
            )
        else:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                message=f"Unknown expected_state: {expected_state}",
            )
    except FileNotFoundError:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message="'sc' command not found",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message="Service query timed out",
        )


def _check_systemd_service(check: CheckDefinition, name: str, expected_state: str) -> CheckResult:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        actual_state = result.stdout.strip().lower()

        if expected_state == "running":
            passed = actual_state == "active"
        elif expected_state == "stopped":
            passed = actual_state in ("inactive", "failed", "dead")
        elif expected_state == "enabled":
            enabled_result = subprocess.run(
                ["systemctl", "is-enabled", name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            actual_state = enabled_result.stdout.strip().lower()
            passed = actual_state == "enabled"
        else:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                message=f"Unknown expected_state: {expected_state}",
            )

        return CheckResult(
            check=check,
            status=ResultStatus.PASS if passed else ResultStatus.FAIL,
            actual_value=actual_state,
            message="" if passed else f"Service '{name}' expected {expected_state}, got {actual_state}",
        )
    except FileNotFoundError:
        return CheckResult(
            check=check,
            status=ResultStatus.SKIPPED,
            message="systemctl not found — not a systemd system",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message="Service query timed out",
        )
