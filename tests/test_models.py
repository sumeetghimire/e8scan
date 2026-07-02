"""Tests for e8scan models."""

from __future__ import annotations

import platform

from e8scan.models import (
    CheckDefinition,
    CheckResult,
    ResultStatus,
    ScanReport,
)


def make_check(
    check_id: str = "E8-TST-001",
    strategy: str = "configure_office_macros",
    platforms: list[str] | None = None,
    maturity_level: int = 1,
) -> CheckDefinition:
    return CheckDefinition(
        id=check_id,
        strategy=strategy,
        title="Test check",
        ism_controls=["ISM-9999"],
        maturity_level=maturity_level,
        platforms=platforms or ["all"],
        severity="medium",
        check={"type": "manual"},
        remediation="Fix it.",
    )


def test_check_is_applicable_all_platforms() -> None:
    check = make_check(platforms=["all"])
    assert check.is_applicable() is True


def test_check_is_applicable_current_platform() -> None:
    sys_map = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}
    current = sys_map.get(platform.system(), platform.system().lower())
    check = make_check(platforms=[current])
    assert check.is_applicable() is True


def test_check_not_applicable_wrong_platform() -> None:
    system = platform.system().lower()
    wrong = "linux" if system != "linux" else "windows"
    check = make_check(platforms=[wrong])
    assert check.is_applicable() is False


def test_check_result_properties() -> None:
    check = make_check()
    result = CheckResult(check=check, status=ResultStatus.PASS, actual_value="1", message="")
    assert result.id == "E8-TST-001"
    assert result.title == "Test check"
    assert result.strategy == "configure_office_macros"
    assert result.maturity_level == 1
    assert result.status == ResultStatus.PASS


def test_scan_report_counts() -> None:
    check = make_check()
    results = [
        CheckResult(check=check, status=ResultStatus.PASS),
        CheckResult(check=check, status=ResultStatus.PASS),
        CheckResult(check=check, status=ResultStatus.FAIL),
        CheckResult(check=check, status=ResultStatus.ERROR),
        CheckResult(check=check, status=ResultStatus.SKIPPED),
        CheckResult(check=check, status=ResultStatus.MANUAL),
    ]
    report = ScanReport(results=results)
    assert report.pass_count() == 2
    assert report.fail_count() == 1
    assert report.error_count() == 1
    assert report.skipped_count() == 1
    assert report.manual_count() == 1
    assert report.total() == 6


def test_scan_report_by_strategy() -> None:
    check_a = make_check(strategy="configure_office_macros")
    check_b = make_check(strategy="patch_operating_systems")
    report = ScanReport(results=[
        CheckResult(check=check_a, status=ResultStatus.PASS),
        CheckResult(check=check_b, status=ResultStatus.FAIL),
    ])
    grouped = report.by_strategy()
    assert "configure_office_macros" in grouped
    assert "patch_operating_systems" in grouped
    assert len(grouped["configure_office_macros"]) == 1


def test_strategy_pass_rate() -> None:
    check = make_check(strategy="configure_office_macros")
    report = ScanReport(results=[
        CheckResult(check=check, status=ResultStatus.PASS),
        CheckResult(check=check, status=ResultStatus.PASS),
        CheckResult(check=check, status=ResultStatus.FAIL),
    ])
    rate = report.strategy_pass_rate("configure_office_macros")
    assert abs(rate - 2 / 3) < 0.001


def test_indicative_maturity_level_all_pass() -> None:
    check1 = make_check(maturity_level=1)
    check2 = make_check(maturity_level=2)
    check3 = make_check(maturity_level=3)
    report = ScanReport(results=[
        CheckResult(check=check1, status=ResultStatus.PASS),
        CheckResult(check=check2, status=ResultStatus.PASS),
        CheckResult(check=check3, status=ResultStatus.PASS),
    ])
    assert report.indicative_maturity_level() == 3


def test_indicative_maturity_level_ml1_fail() -> None:
    check1 = make_check(maturity_level=1)
    report = ScanReport(results=[
        CheckResult(check=check1, status=ResultStatus.FAIL),
    ])
    assert report.indicative_maturity_level() == 0


def test_indicative_maturity_level_ml2_fail() -> None:
    # ML1 passes, ML2 fails → indicative level is ML1 (ACSC model is cumulative)
    check1 = make_check(maturity_level=1)
    check2 = make_check(maturity_level=2)
    report = ScanReport(results=[
        CheckResult(check=check1, status=ResultStatus.PASS),
        CheckResult(check=check2, status=ResultStatus.FAIL),
    ])
    assert report.indicative_maturity_level() == 1
