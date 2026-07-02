"""Tests for the check engine."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from e8scan.engine import (
    load_bundled_checks,
    load_check_from_dict,
    load_checks_from_dir,
    validate_check_dict,
)
from e8scan.models import CheckDefinition

VALID_CHECK = {
    "id": "E8-TST-001",
    "strategy": "configure_office_macros",
    "title": "Test check",
    "ism_controls": ["ISM-9999"],
    "maturity_level": 1,
    "platforms": ["all"],
    "severity": "high",
    "check": {"type": "manual", "guidance": "Check manually."},
    "remediation": "Fix it.",
}


def test_validate_check_dict_valid() -> None:
    validate_check_dict(VALID_CHECK)  # Should not raise


def test_validate_check_dict_missing_field() -> None:
    bad = {**VALID_CHECK}
    del bad["strategy"]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_check_dict(bad)


def test_validate_check_dict_bad_strategy() -> None:
    bad = {**VALID_CHECK, "strategy": "not_a_strategy"}
    with pytest.raises(ValueError, match="unknown strategy"):
        validate_check_dict(bad)


def test_validate_check_dict_bad_maturity() -> None:
    bad = {**VALID_CHECK, "maturity_level": 4}
    with pytest.raises(ValueError, match="maturity_level must be 1, 2, or 3"):
        validate_check_dict(bad)


def test_validate_check_dict_bad_check_type() -> None:
    bad = {**VALID_CHECK, "check": {"type": "unknown"}}
    with pytest.raises(ValueError, match="unknown check type"):
        validate_check_dict(bad)


def test_load_check_from_dict() -> None:
    check = load_check_from_dict(VALID_CHECK)
    assert isinstance(check, CheckDefinition)
    assert check.id == "E8-TST-001"
    assert check.maturity_level == 1
    assert check.check_type == "manual"


def test_load_checks_from_dir(tmp_path: Path) -> None:
    check_file = tmp_path / "test.yaml"
    check_file.write_text(yaml.dump(VALID_CHECK), encoding="utf-8")
    checks = load_checks_from_dir(tmp_path)
    assert len(checks) == 1
    assert checks[0].id == "E8-TST-001"


def test_load_checks_from_dir_invalid_yaml(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_data = {**VALID_CHECK, "strategy": "invalid_strategy"}
    bad_file.write_text(yaml.dump(bad_data), encoding="utf-8")
    with pytest.raises(ValueError):
        load_checks_from_dir(tmp_path)


def test_load_bundled_checks() -> None:
    checks = load_bundled_checks()
    assert len(checks) >= 25, f"Expected at least 25 bundled checks, got {len(checks)}"
    ids = [c.id for c in checks]
    # Check a few known IDs
    assert "E8-OM-001" in ids
    assert "E8-RAP-001" in ids
    assert "E8-AC-001" in ids


def test_bundled_checks_all_valid() -> None:
    """Every bundled YAML must pass schema validation."""
    checks = load_bundled_checks()
    for check in checks:
        assert check.id, f"Check has no id: {check}"
        assert check.strategy, f"Check {check.id} has no strategy"
        assert check.maturity_level in (1, 2, 3), f"Check {check.id} has bad ML: {check.maturity_level}"
        assert check.check_type in ("registry", "command", "file", "service", "manual"), (
            f"Check {check.id} has unknown type: {check.check_type}"
        )


def test_bundled_checks_unique_ids() -> None:
    checks = load_bundled_checks()
    ids = [c.id for c in checks]
    assert len(ids) == len(set(ids)), f"Duplicate check IDs found: {[i for i in ids if ids.count(i) > 1]}"
