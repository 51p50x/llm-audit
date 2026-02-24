"""Rich-based terminal reporter and JSON exporter for llm-audit."""

from __future__ import annotations

import json
import sys
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from llm_audit.types import AuditReport, ProbeResult

console = Console()
err_console = Console(stderr=True)


def render_report(report: AuditReport, *, verbose: bool = False, output: TextIO = sys.stdout) -> None:
    """Render a full audit report to the terminal using Rich."""
    out = Console(file=output)

    _render_header(out, report)

    for probe_name, result in report["results"].items():
        _render_probe_panel(out, probe_name, result, verbose=verbose)

    _render_summary(out, report)


def render_json(report: AuditReport, *, output: TextIO = sys.stdout) -> None:
    """Dump the audit report as pretty-printed JSON."""
    json.dump(report, output, indent=2, default=str)
    output.write("\n")


def render_error(message: str) -> None:
    """Print a formatted error panel to stderr."""
    err_console.print(
        Panel(
            Text(message, style="bold red"),
            title="[bold red]Error[/bold red]",
            border_style="red",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _render_header(out: Console, report: AuditReport) -> None:
    model_line = f"Model   : {report['model']}" if report["model"] else "Model   : (not specified)"
    header_text = (
        f"[bold cyan]Endpoint[/bold cyan]: {report['endpoint']}\n"
        f"[bold cyan]{model_line}[/bold cyan]\n"
        f"[dim]Timestamp: {report['timestamp']}[/dim]"
    )
    out.print(
        Panel(
            header_text,
            title="[bold white]llm-audit[/bold white] [dim]OWASP LLM Top 10 Audit[/dim]",
            border_style="cyan",
            expand=True,
        )
    )
    out.print()


def _render_probe_panel(
    out: Console, probe_name: str, result: ProbeResult, *, verbose: bool
) -> None:
    passed = result["passed"]
    status_icon = "[bold green]✔ PASS[/bold green]" if passed else "[bold red]✘ FAIL[/bold red]"
    border = "green" if passed else "red"

    body_parts: list[str] = [
        f"[bold]Status[/bold]  : {status_icon}",
        f"[bold]Reason[/bold]  : {result['reason']}",
    ]

    if not passed or verbose:
        if result["evidence"]:
            body_parts.append(f"\n[bold]Evidence[/bold]:\n[dim]{result['evidence']}[/dim]")
        body_parts.append(
            f"\n[bold]Recommendation[/bold]:\n[yellow]{result['recommendation']}[/yellow]"
        )

    out.print(
        Panel(
            "\n".join(body_parts),
            title=f"[bold]{probe_name}[/bold]",
            border_style=border,
            expand=True,
        )
    )


def _render_summary(out: Console, report: AuditReport) -> None:
    summary = report["summary"]
    total = summary["total"]
    passed = summary["passed"]
    failed = summary["failed"]

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Metric", style="bold cyan", justify="left")
    table.add_column("Value", justify="right")

    table.add_row("Total probes", str(total))
    table.add_row("[green]Passed[/green]", f"[green]{passed}[/green]")
    table.add_row("[red]Failed[/red]", f"[red]{failed}[/red]")

    score_pct = int((passed / total) * 100) if total else 0
    score_style = "green" if score_pct == 100 else ("yellow" if score_pct >= 60 else "red")
    table.add_row("Security score", f"[{score_style}]{score_pct}%[/{score_style}]")

    verdict = (
        "[bold green]SECURE[/bold green]"
        if failed == 0
        else (
            "[bold yellow]PARTIAL[/bold yellow]"
            if passed > 0
            else "[bold red]VULNERABLE[/bold red]"
        )
    )

    out.print()
    out.print(
        Panel(
            table,
            title=f"[bold white]Audit Summary[/bold white]  {verdict}",
            border_style=score_style,
            expand=False,
        )
    )
