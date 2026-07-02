"""Windows registry check runner."""

from __future__ import annotations

import sys
from typing import Any

from e8scan.models import CheckDefinition, CheckResult, ResultStatus

_HIVE_MAP: dict[str, Any] = {}

if sys.platform == "win32":
    import winreg

    _HIVE_MAP = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }


def run(check: CheckDefinition) -> CheckResult:
    """Run a registry check (Windows only)."""
    if sys.platform != "win32":
        return CheckResult(
            check=check,
            status=ResultStatus.SKIPPED,
            message="Registry checks only run on Windows",
        )

    cfg = check.check
    hive_name = str(cfg.get("hive", "HKLM"))
    reg_path = str(cfg.get("path", ""))
    key_name = str(cfg.get("key", ""))
    expected = cfg.get("expected")

    hive = _HIVE_MAP.get(hive_name)
    if hive is None:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Unknown registry hive: {hive_name}",
        )

    import winreg

    try:
        with winreg.OpenKey(hive, reg_path, access=winreg.KEY_READ) as reg_key:
            actual, _ = winreg.QueryValueEx(reg_key, key_name)
    except FileNotFoundError:
        return CheckResult(
            check=check,
            status=ResultStatus.FAIL,
            actual_value="<key not found>",
            message=f"Registry key not found: {hive_name}\\{reg_path}\\{key_name}",
        )
    except PermissionError as exc:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Permission denied reading registry (run as administrator): {exc}",
        )
    except OSError as exc:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Registry read error: {exc}",
        )

    actual_str = str(actual)
    passed = _evaluate(actual, expected, cfg)
    return CheckResult(
        check=check,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        actual_value=actual_str,
        message="" if passed else f"Expected {expected!r}, got {actual!r}",
    )


def _evaluate(actual: Any, expected: Any, cfg: dict[str, Any]) -> bool:
    operator = str(cfg.get("operator", "equals"))
    if operator == "equals":
        return bool(actual == expected)
    elif operator == "not_equals":
        return bool(actual != expected)
    elif operator == "contains":
        return str(expected) in str(actual)
    elif operator == "gte":
        try:
            return int(actual) >= int(expected)
        except (ValueError, TypeError):
            return False
    return bool(actual == expected)
