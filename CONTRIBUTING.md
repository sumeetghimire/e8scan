# Contributing to e8scan

Thank you for your interest in contributing! This document explains how to get started.

## Development setup

```bash
git clone https://github.com/your-org/e8scan
cd e8scan
pip install -e ".[dev]"
```

Add dev dependencies to pyproject.toml if not already present:

```bash
pip install pytest pytest-mock ruff mypy
```

## Running tests

```bash
pytest
```

## Linting and type checking

```bash
ruff check .
mypy e8scan/
```

## Adding a new check

1. Create a YAML file in `e8scan/checks/` following the schema in [docs/check-schema.md](docs/check-schema.md).
2. Use a unique ID: `E8-{STRATEGY_ABBR}-{NNN}` (e.g. `E8-OM-009`).
3. Map to real ISM control IDs. If uncertain, add a `# TODO: verify ISM-XXXX` comment.
4. Run `pytest tests/test_yaml_schema.py` to validate your check.
5. Open a pull request.

## Code style

- Python 3.10+, type hints everywhere
- `ruff` for formatting/linting
- `mypy --strict` for type checking
- Keep dependencies minimal

## Pull request checklist

- [ ] Tests pass (`pytest`)
- [ ] Ruff clean (`ruff check .`)
- [ ] Mypy clean (`mypy e8scan/`)
- [ ] New YAML checks pass schema validation
- [ ] README updated if adding new strategies
