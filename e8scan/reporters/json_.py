"""JSON reporter."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from typing import Any

from e8scan.models import ScanReport


def render(report: ScanReport) -> str:
    """Return a JSON string of the full scan report."""
    data: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "platform": {
            "system": report.scan_platform,
            "version": report.scan_platform_version,
            "python": platform.python_version(),
        },
        "summary": {
            "total": report.total(),
            "pass": report.pass_count(),
            "fail": report.fail_count(),
            "error": report.error_count(),
            "skipped": report.skipped_count(),
            "manual": report.manual_count(),
            "indicative_maturity_level": report.indicative_maturity_level(),
        },
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "strategy": r.strategy,
                "maturity_level": r.maturity_level,
                "severity": r.severity,
                "ism_controls": r.ism_controls,
                "status": r.status.value,
                "actual_value": r.actual_value,
                "message": r.message,
                "remediation": r.remediation,
                "references": r.references,
            }
            for r in report.results
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
