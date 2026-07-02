"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from e8scan.models import STRATEGY_LABELS, ResultStatus, ScanReport

STATUS_STYLE: dict[ResultStatus, str] = {
    ResultStatus.PASS: "bold green",
    ResultStatus.FAIL: "bold red",
    ResultStatus.SKIPPED: "dim",
    ResultStatus.ERROR: "bold yellow",
    ResultStatus.MANUAL: "bold cyan",
}

STATUS_SYMBOL: dict[ResultStatus, str] = {
    ResultStatus.PASS: "PASS",
    ResultStatus.FAIL: "FAIL",
    ResultStatus.SKIPPED: "SKIP",
    ResultStatus.ERROR: "ERR ",
    ResultStatus.MANUAL: "MAN ",
}

SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render(report: ScanReport, console: Console | None = None) -> None:
    """Print a rich terminal report for the scan report."""
    if console is None:
        console = Console()

    console.print()
    console.print(
        Panel.fit(
            "[bold white]e8scan[/] — Essential Eight Configuration Scanner",
            subtitle=f"Platform: {report.scan_platform}",
            border_style="blue",
        )
    )
    console.print()

    grouped = report.by_strategy()

    for strategy, results in grouped.items():
        label = STRATEGY_LABELS.get(strategy, strategy)

        table = Table(
            title=f"[bold]{label}[/]",
            show_header=True,
            header_style="bold white",
            border_style="dim",
            show_lines=False,
            expand=False,
        )
        table.add_column("ID", style="dim", width=14, no_wrap=True)
        table.add_column("ML", justify="center", width=3)
        table.add_column("Status", justify="center", width=6)
        table.add_column("Title", min_width=40)
        table.add_column("Actual / Note", style="dim", min_width=30)

        for result in sorted(results, key=lambda r: r.maturity_level):
            status_text = Text(STATUS_SYMBOL[result.status], style=STATUS_STYLE[result.status])
            note = result.actual_value or result.message
            if len(note) > 60:
                note = note[:57] + "..."
            table.add_row(
                result.id,
                str(result.maturity_level),
                status_text,
                result.title,
                note,
            )

        console.print(table)
        console.print()

    # Summary panel
    total = report.total()
    passes = report.pass_count()
    fails = report.fail_count()
    errors = report.error_count()
    skipped = report.skipped_count()
    manual = report.manual_count()
    ml = report.indicative_maturity_level()

    summary_lines = [
        f"[green]PASS[/]    {passes:>4}",
        f"[red]FAIL[/]    {fails:>4}",
        f"[yellow]ERROR[/]   {errors:>4}",
        f"[cyan]MANUAL[/]  {manual:>4}",
        f"[dim]SKIPPED[/] {skipped:>4}",
        f"[bold]TOTAL[/]   {total:>4}",
        "",
        f"Indicative Maturity Level: [bold {'green' if ml > 0 else 'red'}]ML{ml}[/]",
    ]

    # Per-strategy pass rates
    strategy_lines: list[str] = []
    for strategy, _results in grouped.items():
        label = STRATEGY_LABELS.get(strategy, strategy)
        rate = report.strategy_pass_rate(strategy)
        bar = _mini_bar(rate)
        strategy_lines.append(f"{label:<40} {bar} {rate * 100:5.1f}%")

    panel_content = "\n".join(summary_lines)
    if strategy_lines:
        panel_content += "\n\nPer-strategy pass rate:\n" + "\n".join(strategy_lines)

    console.print(
        Panel(
            panel_content,
            title="[bold]Scan Summary[/]",
            border_style="blue",
            expand=False,
        )
    )
    console.print()
    console.print(
        "[dim italic]DISCLAIMER: Results are indicative only and do not constitute a formal ASD/ACSC Essential Eight assessment. "
        "This tool is not affiliated with the Australian Government.[/]"
    )
    console.print()


def _mini_bar(rate: float, width: int = 20) -> str:
    filled = int(rate * width)
    empty = width - filled
    color = "green" if rate >= 0.8 else ("yellow" if rate >= 0.5 else "red")
    return f"[{color}]{'█' * filled}{'░' * empty}[/]"
