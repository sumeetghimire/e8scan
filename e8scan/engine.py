"""Check loading and execution engine."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Any

import yaml

from e8scan.models import CheckDefinition, CheckResult, ResultStatus, ScanReport

# Required fields in every check YAML
REQUIRED_FIELDS = {"id", "strategy", "title", "ism_controls", "maturity_level", "platforms", "severity", "check", "remediation"}
VALID_STRATEGIES = {
    "configure_office_macros",
    "patch_operating_systems",
    "restrict_admin_privileges",
    "user_application_hardening",
    "multi_factor_authentication",
    "regular_backups",
    "application_control",
    "patch_applications",
}
VALID_CHECK_TYPES = {"registry", "command", "file", "service", "manual"}


def validate_check_dict(data: dict[str, Any], source: str = "") -> None:
    """Raise ValueError if the check definition is malformed."""
    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"Check {source} missing required fields: {missing}")
    if data["strategy"] not in VALID_STRATEGIES:
        raise ValueError(f"Check {source} has unknown strategy: {data['strategy']}")
    if not isinstance(data["maturity_level"], int) or data["maturity_level"] not in (1, 2, 3):
        raise ValueError(f"Check {source} maturity_level must be 1, 2, or 3")
    check_type = data.get("check", {}).get("type", "")
    if check_type not in VALID_CHECK_TYPES:
        raise ValueError(f"Check {source} has unknown check type: {check_type}")


def load_check_from_dict(data: dict[str, Any], source: str = "") -> CheckDefinition:
    """Parse a dict into a CheckDefinition, validating fields."""
    validate_check_dict(data, source)
    return CheckDefinition(
        id=str(data["id"]),
        strategy=str(data["strategy"]),
        title=str(data["title"]),
        ism_controls=list(data.get("ism_controls", [])),
        maturity_level=int(data["maturity_level"]),
        platforms=list(data.get("platforms", ["all"])),
        severity=str(data.get("severity", "medium")),
        check=dict(data["check"]),
        remediation=str(data.get("remediation", "")),
        references=list(data.get("references", [])),
    )


def load_checks_from_dir(directory: Path) -> list[CheckDefinition]:
    """Load all YAML check files from a directory."""
    checks: list[CheckDefinition] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        with yaml_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ValueError(f"Check file {yaml_file} must be a YAML mapping")
        checks.append(load_check_from_dict(data, source=yaml_file.name))
    return checks


def load_bundled_checks() -> list[CheckDefinition]:
    """Load check definitions bundled with the package."""
    checks_ref = importlib.resources.files("e8scan") / "checks"
    checks_dir = Path(str(checks_ref))
    return load_checks_from_dir(checks_dir)


def run_check(check: CheckDefinition) -> CheckResult:
    """Dispatch a check to the appropriate runner."""
    if not check.is_applicable():
        return CheckResult(
            check=check,
            status=ResultStatus.SKIPPED,
            message=f"Not applicable on {check.platforms} (current platform: {_current_platform()})",
        )

    check_type = check.check_type
    try:
        if check_type == "registry":
            from e8scan.runners.registry import run as run_registry
            return run_registry(check)
        elif check_type == "command":
            from e8scan.runners.command import run as run_command
            return run_command(check)
        elif check_type == "file":
            from e8scan.runners.file import run as run_file
            return run_file(check)
        elif check_type == "service":
            from e8scan.runners.service import run as run_service
            return run_service(check)
        elif check_type == "manual":
            from e8scan.runners.manual import run as run_manual
            return run_manual(check)
        else:
            return CheckResult(
                check=check,
                status=ResultStatus.ERROR,
                message=f"Unknown check type: {check_type}",
            )
    except PermissionError as exc:
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Permission denied (try running as administrator/root): {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            check=check,
            status=ResultStatus.ERROR,
            message=f"Unexpected error: {type(exc).__name__}: {exc}",
        )


def _current_platform() -> str:
    import platform
    return platform.system()


def scan(
    extra_checks_dir: Path | None = None,
    strategy_filter: str | None = None,
    maturity_level_filter: int | None = None,
    skip_manual: bool = False,
) -> ScanReport:
    """Load and run all applicable checks, returning a ScanReport."""
    checks = load_bundled_checks()
    if extra_checks_dir:
        checks.extend(load_checks_from_dir(extra_checks_dir))

    # Apply filters
    if strategy_filter:
        checks = [c for c in checks if c.strategy == strategy_filter]
    if maturity_level_filter is not None:
        checks = [c for c in checks if c.maturity_level <= maturity_level_filter]
    if skip_manual:
        checks = [c for c in checks if c.check_type != "manual"]

    report = ScanReport()
    for check in checks:
        result = run_check(check)
        report.results.append(result)

    return report
