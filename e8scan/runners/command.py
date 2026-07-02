"""Command-based check runner."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any

from e8scan.models import CheckDefinition, CheckResult, ResultStatus

try:
    from packaging.version import Version as PkgVersion

    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False


def run(check: CheckDefinition) -> CheckResult:
    """Run a shell command and evaluate its output."""
    cfg = check.check
    cmd = cfg.get("cmd", "")
    shell = bool(cfg.get("shell", True))
    timeout = int(cfg.get("timeout", 30))
    expected = cfg.get("expected")
    operator = str(cfg.get("operator", "equals"))

    # Support platform-specific command overrides
    if isinstance(cmd, dict):
        plat = sys.platform
        if plat == "win32":
            cmd = cmd.get("windows", "")
        elif plat == "darwin":
            cmd = cmd.get("macos", cmd.get("unix", ""))
        else:
            cmd = cmd.get("linux", cmd.get("unix", ""))

    if not cmd:
        return CheckResult(
            check=check,
            status=ResultStatus.SKIPPED,
            message="No command defined for this platform",
        )

    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip()
        stderr = result.stderr.strip()

        # Some checks care about exit code only
        if operator == "exit_code":
            actual = str(result.returncode)
            passed = result.returncode == int(expected if expected is not None else 0)
            return CheckResult(
                check=check,
                status=ResultStatus.PASS if passed else ResultStatus.FAIL,
                actual_value=actual,
                message="" if passed else f"Expected exit code {expected}, got {result.returncode}. stderr: {stderr}",
            )

        if result.returncode != 0 and not output:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                actual_value=stderr[:500] if stderr else f"exit code {result.returncode}",
                message=f"Command failed (exit {result.returncode}): {stderr[:200]}",
            )

        actual_value, passed = _evaluate(output, expected, operator, cfg)
        return CheckResult(
            check=check,
            status=ResultStatus.PASS if passed else ResultStatus.FAIL,
            actual_value=actual_value,
            message="" if passed else f"Expected {expected!r} ({operator}), got {actual_value!r}",
        )

    except subprocess.TimeoutExpired:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Command timed out after {timeout}s",
        )
    except FileNotFoundError as exc:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Command not found: {exc}",
        )
    except PermissionError as exc:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Permission denied running command (try as administrator/root): {exc}",
        )


def _evaluate(output: str, expected: Any, operator: str, cfg: dict[str, Any]) -> tuple[str, bool]:
    """Return (actual_value_str, passed)."""
    if operator == "equals":
        return output, output == str(expected)
    elif operator == "not_equals":
        return output, output != str(expected)
    elif operator == "contains":
        return output[:200], str(expected) in output
    elif operator == "not_contains":
        return output[:200], str(expected) not in output
    elif operator == "regex":
        match = re.search(str(expected), output, re.IGNORECASE | re.MULTILINE)
        return output[:200], match is not None
    elif operator == "jsonpath":
        field = str(cfg.get("jsonpath_field", ""))
        try:
            data = json.loads(output)
            actual = _jsonpath_get(data, field)
            actual_str = str(actual)
            return actual_str, actual == expected
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return f"<json parse error: {exc}>", False
    elif operator == "version_gte":
        # Extract first version-like string from output
        match = re.search(r"(\d+\.\d+[\.\d]*)", output)
        if not match:
            return output[:200], False
        actual_ver = match.group(1)
        if _HAS_PACKAGING:
            try:
                result = PkgVersion(actual_ver) >= PkgVersion(str(expected))
                return actual_ver, result
            except Exception:
                pass
        # Fallback: compare tuples
        try:
            actual_parts = tuple(int(x) for x in actual_ver.split("."))
            expected_parts = tuple(int(x) for x in str(expected).split("."))
            return actual_ver, actual_parts >= expected_parts
        except ValueError:
            return actual_ver, False
    else:
        return output, output == str(expected)


def _jsonpath_get(data: Any, path: str) -> Any:
    """Simple dot-notation path getter."""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise KeyError(part)
    return current
