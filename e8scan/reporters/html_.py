"""Self-contained HTML reporter."""

from __future__ import annotations

from datetime import datetime, timezone

from e8scan.models import STRATEGY_LABELS, ResultStatus, ScanReport

STATUS_BADGE: dict[ResultStatus, tuple[str, str]] = {
    ResultStatus.PASS: ("#22c55e", "PASS"),
    ResultStatus.FAIL: ("#ef4444", "FAIL"),
    ResultStatus.SKIPPED: ("#6b7280", "SKIP"),
    ResultStatus.ERROR: ("#f59e0b", "ERROR"),
    ResultStatus.MANUAL: ("#06b6d4", "MANUAL"),
}

SEVERITY_COLOR: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0f172a; color: #e2e8f0; font-size: 14px; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
         border: 1px solid #1e40af; border-radius: 12px; padding: 32px; margin-bottom: 24px; }
header h1 { font-size: 2rem; font-weight: 700; color: #60a5fa; margin-bottom: 8px; }
header p { color: #94a3b8; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 16px; margin-bottom: 24px; }
.stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
             padding: 16px; text-align: center; }
.stat-card .value { font-size: 2rem; font-weight: 700; }
.stat-card .label { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
.ml-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-weight: 700;
            font-size: 1rem; background: #1d4ed8; color: white; margin-top: 8px; }
.strategy-section { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                    padding: 20px; margin-bottom: 16px; }
.strategy-section h2 { font-size: 1.1rem; font-weight: 600; color: #60a5fa;
                        margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.progress-bar { height: 6px; background: #334155; border-radius: 3px; margin-bottom: 16px; overflow: hidden; }
.progress-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 12px; color: #94a3b8; font-weight: 600;
     text-transform: uppercase; letter-spacing: 0.05em; font-size: 11px;
     border-bottom: 1px solid #334155; }
td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #1e2d3d; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 11px; font-weight: 700; letter-spacing: 0.05em; }
.severity-dot { display: inline-block; width: 8px; height: 8px;
                border-radius: 50%; margin-right: 4px; vertical-align: middle; }
.remediation { background: #0f172a; border-left: 3px solid #3b82f6;
               padding: 8px 12px; margin-top: 6px; border-radius: 0 4px 4px 0;
               font-size: 12px; color: #94a3b8; display: none; }
.show-remediation { cursor: pointer; color: #3b82f6; font-size: 11px;
                    text-decoration: underline; background: none; border: none;
                    padding: 0; margin-top: 4px; }
.check-id { font-family: monospace; font-size: 12px; color: #94a3b8; }
.ism-tag { display: inline-block; padding: 1px 6px; background: #1e3a5f;
           border: 1px solid #1d4ed8; border-radius: 3px; font-size: 11px;
           font-family: monospace; margin: 1px; }
.disclaimer { color: #475569; font-size: 12px; text-align: center; padding: 24px;
              border-top: 1px solid #1e293b; margin-top: 24px; }
.actual { max-width: 300px; overflow: hidden; text-overflow: ellipsis;
          white-space: nowrap; color: #94a3b8; font-family: monospace; font-size: 12px; }
"""

JS = """
function toggleRemediation(id) {
  var el = document.getElementById(id);
  el.style.display = el.style.display === 'block' ? 'none' : 'block';
}
"""


def render(report: ScanReport) -> str:
    """Return a self-contained HTML report string."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ml = report.indicative_maturity_level()

    body_parts: list[str] = []

    # Header
    body_parts.append(f"""
<header>
  <h1>e8scan — Essential Eight Report</h1>
  <p>Platform: <strong>{report.scan_platform} {report.scan_platform_version}</strong>
     &nbsp;&bull;&nbsp; Generated: <strong>{now}</strong>
     &nbsp;&bull;&nbsp; Indicative Maturity Level: <span class="ml-badge">ML{ml}</span>
  </p>
</header>
""")

    # Summary grid
    body_parts.append(f"""
<div class="summary-grid">
  <div class="stat-card"><div class="value" style="color:#22c55e">{report.pass_count()}</div>
    <div class="label">Pass</div></div>
  <div class="stat-card"><div class="value" style="color:#ef4444">{report.fail_count()}</div>
    <div class="label">Fail</div></div>
  <div class="stat-card"><div class="value" style="color:#f59e0b">{report.error_count()}</div>
    <div class="label">Error</div></div>
  <div class="stat-card"><div class="value" style="color:#06b6d4">{report.manual_count()}</div>
    <div class="label">Manual</div></div>
  <div class="stat-card"><div class="value" style="color:#6b7280">{report.skipped_count()}</div>
    <div class="label">Skipped</div></div>
  <div class="stat-card"><div class="value">{report.total()}</div>
    <div class="label">Total</div></div>
</div>
""")

    grouped = report.by_strategy()

    for strategy, results in grouped.items():
        label = STRATEGY_LABELS.get(strategy, strategy)
        rate = report.strategy_pass_rate(strategy)
        fill_color = "#22c55e" if rate >= 0.8 else ("#f59e0b" if rate >= 0.5 else "#ef4444")
        pass_rate_pct = f"{rate * 100:.0f}%"

        rows_html = ""
        for i, r in enumerate(sorted(results, key=lambda x: x.maturity_level)):
            bg_color, badge_label = STATUS_BADGE[r.status]
            sev_color = SEVERITY_COLOR.get(r.severity, "#6b7280")
            ism_tags = " ".join(f'<span class="ism-tag">{c}</span>' for c in r.ism_controls)
            rem_id = f"rem-{r.id}-{i}"
            actual = r.actual_value[:80] + "..." if len(r.actual_value) > 80 else r.actual_value

            remediation_html = ""
            if r.status in (ResultStatus.FAIL, ResultStatus.ERROR):
                remediation_html = f"""
<button class="show-remediation" onclick="toggleRemediation('{rem_id}')">Show remediation</button>
<div class="remediation" id="{rem_id}">{_escape(r.remediation)}</div>"""

            rows_html += f"""
<tr>
  <td class="check-id">{_escape(r.id)}</td>
  <td><span class="badge" style="background:{bg_color};color:white">{badge_label}</span></td>
  <td style="font-weight:600">{_escape(r.title)}{remediation_html}</td>
  <td><span class="severity-dot" style="background:{sev_color}"></span>{r.severity}</td>
  <td style="text-align:center">{r.maturity_level}</td>
  <td>{ism_tags}</td>
  <td class="actual" title="{_escape(actual)}">{_escape(actual)}</td>
</tr>"""

        body_parts.append(f"""
<div class="strategy-section">
  <h2>{_escape(label)} <span style="color:#94a3b8;font-weight:400;font-size:0.85em">
    — {pass_rate_pct} pass rate</span></h2>
  <div class="progress-bar">
    <div class="progress-fill" style="width:{pass_rate_pct};background:{fill_color}"></div>
  </div>
  <table>
    <thead><tr>
      <th>ID</th><th>Status</th><th>Title</th>
      <th>Severity</th><th>ML</th><th>ISM Controls</th><th>Actual</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
</div>""")

    body_parts.append("""
<div class="disclaimer">
  DISCLAIMER: Results are indicative only and do not constitute a formal ASD/ACSC Essential Eight assessment.
  This tool is not affiliated with the Australian Government.
  Always engage an accredited assessor for compliance verification.
</div>""")

    body = "\n".join(body_parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>e8scan — Essential Eight Report</title>
  <style>{CSS}</style>
</head>
<body>
<div class="container">
{body}
</div>
<script>{JS}</script>
</body>
</html>"""


def _escape(text: str) -> str:
    """HTML escape a string."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
