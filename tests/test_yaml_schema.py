"""Validate every bundled YAML check against the schema."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import pytest
import yaml

from e8scan.engine import validate_check_dict, VALID_STRATEGIES, VALID_CHECK_TYPES, REQUIRED_FIELDS


def get_bundled_yaml_files() -> list[Path]:
    checks_ref = importlib.resources.files("e8scan") / "checks"
    checks_dir = Path(str(checks_ref))
    return sorted(checks_dir.glob("*.yaml"))


YAML_FILES = get_bundled_yaml_files()


@pytest.mark.parametrize("yaml_file", YAML_FILES, ids=lambda f: f.name)
def test_yaml_check_has_required_fields(yaml_file: Path) -> None:
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), f"{yaml_file.name} must be a YAML mapping"
    missing = REQUIRED_FIELDS - set(data.keys())
    assert not missing, f"{yaml_file.name} missing fields: {missing}"


@pytest.mark.parametrize("yaml_file", YAML_FILES, ids=lambda f: f.name)
def test_yaml_check_valid_strategy(yaml_file: Path) -> None:
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["strategy"] in VALID_STRATEGIES, (
        f"{yaml_file.name}: unknown strategy '{data['strategy']}'"
    )


@pytest.mark.parametrize("yaml_file", YAML_FILES, ids=lambda f: f.name)
def test_yaml_check_valid_maturity_level(yaml_file: Path) -> None:
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["maturity_level"] in (1, 2, 3), (
        f"{yaml_file.name}: maturity_level must be 1, 2, or 3"
    )


@pytest.mark.parametrize("yaml_file", YAML_FILES, ids=lambda f: f.name)
def test_yaml_check_valid_check_type(yaml_file: Path) -> None:
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    check_type = data.get("check", {}).get("type", "")
    assert check_type in VALID_CHECK_TYPES, (
        f"{yaml_file.name}: unknown check type '{check_type}'"
    )


@pytest.mark.parametrize("yaml_file", YAML_FILES, ids=lambda f: f.name)
def test_yaml_check_passes_full_validation(yaml_file: Path) -> None:
    with yaml_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    validate_check_dict(data, source=yaml_file.name)
