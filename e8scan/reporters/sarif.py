"""SARIF 2.1.0 reporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from e8scan import __version__
from e8scan.models import ResultStatus, ScanReport

# Map e8scan severities to SARIF levels
SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def render(report: ScanReport) -> str:
    """Return a SARIF 2.1.0 JSON string."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids_seen: set[str] = set()

    for r in report.results:
        if r.id not in rule_ids_seen:
            rule_ids_seen.add(r.id)
            rules.append(
                {
                    "id": r.id,
                    "name": _to_camel(r.title),
                    "shortDescription": {"text": r.title},
                    "fullDescription": {"text": r.title},
                    "help": {
                        "text": r.remediation,
                        "markdown": r.remediation,
                    },
                    "properties": {
                        "tags": [r.strategy, "essential-eight"] + r.ism_controls,
                        "precision": "medium",
                        "problem.severity": r.severity,
                        "maturity_level": r.maturity_level,
                        "ism_controls": r.ism_controls,
                    },
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_LEVEL.get(r.severity, "warning"),
                    },
                }
            )

        # Only emit SARIF results for FAIL and ERROR states
        if r.status in (ResultStatus.FAIL, ResultStatus.ERROR):
            level = SEVERITY_TO_LEVEL.get(r.severity, "warning")
            message_text = r.message or f"Check {r.id} {r.status.value}: {r.actual_value}"
            results.append(
                {
                    "ruleId": r.id,
                    "level": level,
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "system://localhost",
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": {
                        "status": r.status.value,
                        "actual_value": r.actual_value,
                        "strategy": r.strategy,
                        "maturity_level": r.maturity_level,
                    },
                }
            )

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "e8scan",
                        "version": __version__,
                        "informationUri": "https://github.com/your-org/e8scan",
                        "organization": "e8scan contributors",
                        "rules": rules,
                        "properties": {
                            "tags": ["security", "compliance", "essential-eight", "acsc"],
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(tz=timezone.utc).isoformat(),
                        "properties": {
                            "platform": report.scan_platform,
                            "indicative_maturity_level": report.indicative_maturity_level(),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _to_camel(title: str) -> str:
    """Convert a title string to CamelCase for SARIF rule name."""
    return "".join(word.capitalize() for word in title.split() if word.isalpha())
