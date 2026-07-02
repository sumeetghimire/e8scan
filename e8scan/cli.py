"""e8scan CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from e8scan import __version__
from e8scan.engine import load_bundled_checks, scan
from e8scan.models import STRATEGY_LABELS

app = typer.Typer(
    name="e8scan",
    help="Scan machine configuration against the ACSC Essential Eight.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def scan_cmd(
    strategy: str | None = typer.Option(
        None, "--strategy", "-s",
        help="Filter by strategy name (e.g. configure_office_macros).",
    ),
    maturity_level: int | None = typer.Option(
        None, "--maturity-level", "-m",
        help="Only include checks at or below this maturity level (1, 2, or 3).",
        min=1, max=3,
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f",
        help="Output format: terminal | json | html | sarif.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o",
        help="Write output to a file instead of stdout.",
    ),
    checks_dir: Path | None = typer.Option(  # noqa: B008
        None, "--checks-dir",
        help="Load additional custom check YAML files from this directory.",
    ),
    skip_manual: bool = typer.Option(
        False, "--skip-manual",
        help="Exclude manual checks from the scan.",
    ),
) -> None:
    """Run Essential Eight checks against this machine."""
    if format not in ("terminal", "json", "html", "sarif"):
        err_console.print(f"[red]Unknown format: {format}. Choose terminal, json, html, or sarif.[/]")
        raise typer.Exit(1)

    if strategy and strategy not in STRATEGY_LABELS:
        err_console.print(
            f"[red]Unknown strategy: {strategy}[/]\n"
            f"Valid strategies: {', '.join(sorted(STRATEGY_LABELS.keys()))}"
        )
        raise typer.Exit(1)

    if format == "terminal":
        console.print("[dim]Running checks...[/]")

    report = scan(
        extra_checks_dir=checks_dir,
        strategy_filter=strategy,
        maturity_level_filter=maturity_level,
        skip_manual=skip_manual,
    )

    if format == "terminal":
        from e8scan.reporters import terminal
        terminal.render(report, console=console)
    elif format == "json":
        from e8scan.reporters import json_
        text = json_.render(report)
        _write_or_print(text, output)
    elif format == "html":
        from e8scan.reporters import html_
        text = html_.render(report)
        _write_or_print(text, output)
    elif format == "sarif":
        from e8scan.reporters import sarif
        text = sarif.render(report)
        _write_or_print(text, output)

    if report.fail_count() > 0 or report.error_count() > 0:
        raise typer.Exit(1)


@app.command(name="list-checks")
def list_checks(
    strategy: str | None = typer.Option(
        None, "--strategy", "-s",
        help="Filter by strategy.",
    ),
    maturity_level: int | None = typer.Option(
        None, "--maturity-level", "-m",
        help="Filter by maximum maturity level.",
        min=1, max=3,
    ),
) -> None:
    """List all available checks in a table."""
    checks = load_bundled_checks()

    if strategy:
        checks = [c for c in checks if c.strategy == strategy]
    if maturity_level is not None:
        checks = [c for c in checks if c.maturity_level <= maturity_level]

    table = Table(
        title="Essential Eight Checks",
        show_header=True,
        header_style="bold white",
        border_style="dim",
    )
    table.add_column("ID", style="dim", no_wrap=True, width=14)
    table.add_column("Strategy", width=30)
    table.add_column("ML", justify="center", width=3)
    table.add_column("Platform", width=10)
    table.add_column("Severity", width=9)
    table.add_column("ISM Controls", width=25)
    table.add_column("Title")

    for c in sorted(checks, key=lambda x: (x.strategy, x.maturity_level, x.id)):
        strategy_label = STRATEGY_LABELS.get(c.strategy, c.strategy)
        ism = ", ".join(c.ism_controls)
        platforms = ", ".join(c.platforms)
        table.add_row(
            c.id,
            strategy_label,
            str(c.maturity_level),
            platforms,
            c.severity,
            ism,
            c.title,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(checks)} checks[/]")


@app.command()
def explain(
    check_id: str = typer.Argument(help="Check ID to explain (e.g. E8-OM-001)"),
) -> None:
    """Show full detail of a single check including remediation and references."""
    checks = load_bundled_checks()
    check = next((c for c in checks if c.id.upper() == check_id.upper()), None)
    if check is None:
        err_console.print(f"[red]Check '{check_id}' not found.[/]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[bold cyan]{check.id}[/] — [bold]{check.title}[/]")
    console.print()
    console.print(f"  Strategy:       {STRATEGY_LABELS.get(check.strategy, check.strategy)}")
    console.print(f"  Maturity Level: ML{check.maturity_level}")
    console.print(f"  Severity:       {check.severity}")
    console.print(f"  Platforms:      {', '.join(check.platforms)}")
    console.print(f"  ISM Controls:   {', '.join(check.ism_controls)}")
    console.print(f"  Check Type:     {check.check_type}")
    console.print()
    console.print("[bold]Remediation:[/]")
    for line in check.remediation.strip().splitlines():
        console.print(f"  {line}")
    if check.references:
        console.print()
        console.print("[bold]References:[/]")
        for ref in check.references:
            console.print(f"  - {ref}")
    console.print()


@app.command()
def version() -> None:
    """Show the e8scan version."""
    console.print(f"e8scan {__version__}")


# Register 'scan' as the default name too
app.command(name="scan")(scan_cmd)


def _write_or_print(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Output written to {output}[/]")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
