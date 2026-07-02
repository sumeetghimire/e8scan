"""Data models for e8scan checks and results."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResultStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    MANUAL = "MANUAL"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


STRATEGY_LABELS: dict[str, str] = {
    "configure_office_macros": "Configure Office Macros",
    "patch_operating_systems": "Patch Operating Systems",
    "restrict_admin_privileges": "Restrict Admin Privileges",
    "user_application_hardening": "User Application Hardening",
    "multi_factor_authentication": "Multi-Factor Authentication",
    "regular_backups": "Regular Backups",
    "application_control": "Application Control",
    "patch_applications": "Patch Applications",
}


@dataclass
class CheckDefinition:
    """Parsed YAML check definition."""

    id: str
    strategy: str
    title: str
    ism_controls: list[str]
    maturity_level: int
    platforms: list[str]
    severity: str
    check: dict[str, Any]
    remediation: str
    references: list[str] = field(default_factory=list)

    @property
    def check_type(self) -> str:
        return str(self.check.get("type", ""))

    def is_applicable(self) -> bool:
        """Return True if this check applies to the current platform."""
        current = platform.system().lower()
        platform_map = {"windows": "windows", "linux": "linux", "darwin": "macos"}
        current_key = platform_map.get(current, current)
        return any(p.lower() in (current_key, "all") for p in self.platforms)


@dataclass
class CheckResult:
    """Result of running a single check."""

    check: CheckDefinition
    status: ResultStatus
    actual_value: str = ""
    message: str = ""

    @property
    def id(self) -> str:
        return self.check.id

    @property
    def title(self) -> str:
        return self.check.title

    @property
    def strategy(self) -> str:
        return self.check.strategy

    @property
    def maturity_level(self) -> int:
        return self.check.maturity_level

    @property
    def severity(self) -> str:
        return self.check.severity

    @property
    def ism_controls(self) -> list[str]:
        return self.check.ism_controls

    @property
    def remediation(self) -> str:
        return self.check.remediation

    @property
    def references(self) -> list[str]:
        return self.check.references


@dataclass
class ScanReport:
    """Aggregated results from a full scan."""

    results: list[CheckResult] = field(default_factory=list)
    scan_platform: str = field(default_factory=lambda: platform.system())
    scan_platform_version: str = field(default_factory=lambda: platform.version())

    def by_strategy(self) -> dict[str, list[CheckResult]]:
        grouped: dict[str, list[CheckResult]] = {}
        for r in self.results:
            grouped.setdefault(r.strategy, []).append(r)
        return grouped

    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.status == ResultStatus.PASS)

    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == ResultStatus.FAIL)

    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status == ResultStatus.ERROR)

    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.status == ResultStatus.SKIPPED)

    def manual_count(self) -> int:
        return sum(1 for r in self.results if r.status == ResultStatus.MANUAL)

    def total(self) -> int:
        return len(self.results)

    def strategy_pass_rate(self, strategy: str) -> float:
        strategy_results = [
            r for r in self.results if r.strategy == strategy and r.status in (ResultStatus.PASS, ResultStatus.FAIL)
        ]
        if not strategy_results:
            return 0.0
        passed = sum(1 for r in strategy_results if r.status == ResultStatus.PASS)
        return passed / len(strategy_results)

    def indicative_maturity_level(self) -> int:
        """Return highest ML where all applicable checks pass (1, 2, 3, or 0)."""
        for ml in (3, 2, 1):
            ml_results = [
                r for r in self.results
                if r.maturity_level <= ml and r.status in (ResultStatus.PASS, ResultStatus.FAIL)
            ]
            if not ml_results:
                continue
            all_pass = all(r.status == ResultStatus.PASS for r in ml_results)
            if all_pass:
                return ml
        return 0
