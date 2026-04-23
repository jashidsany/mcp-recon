"""Output formatters: human (rich), JSON, markdown."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_recon.models import CheckStatus, ScanReport, Severity

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "yellow",
    Severity.MEDIUM: "orange3",
    Severity.HIGH: "bold red",
}

STATUS_ICON = {
    CheckStatus.RAN: "[green]+[/green]",
    CheckStatus.SKIPPED_MISSING_INPUT: "[dim]-[/dim]",
    CheckStatus.SKIPPED_NOT_APPLICABLE: "[dim]-[/dim]",
    CheckStatus.ERRORED: "[red]x[/red]",
}


def render_human(report: ScanReport) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100, legacy_windows=False)

    header = Text()
    header.append(f"target:     {report.target}\n")
    header.append(f"started:    {report.started_at}\n")
    header.append(f"schema:     {report.schema_version}    tool: {report.tool_version}\n")
    header.append(f"duration:   {report.duration_ms} ms")
    console.print(Panel(header, title=f"mcp-recon v{report.tool_version}", border_style="blue"))

    obs_count = 0
    for check in report.checks:
        icon = STATUS_ICON.get(check.status, "?")
        title = f"{icon} [bold]{check.name}[/bold]   [dim]({check.status.value}, {check.duration_ms} ms)[/dim]"
        console.print(title)
        if check.notes:
            for n in check.notes:
                console.print(f"    [dim]note:[/dim] {n}")
        if check.error:
            console.print(f"    [red]error:[/red] {check.error}")
        if check.data:
            # concise data rendering
            for k, v in check.data.items():
                if isinstance(v, list | dict) and len(str(v)) > 120:
                    console.print(f"    {k}: [dim]<{_kind_summary(v)}>[/dim]")
                else:
                    console.print(f"    {k}: {v}")
        for obs in check.observations:
            obs_count += 1
            style = SEVERITY_STYLE.get(obs.severity, "")
            console.print(f"    [{style}]![/{style}] [{style}]{obs.title}[/{style}]   [dim][{obs.severity.value}][/dim]")
            console.print(f"        [dim]{obs.summary}[/dim]")
            if obs.follow_up:
                console.print("        [dim]follow-up:[/dim]")
                for line in obs.follow_up.splitlines():
                    console.print(f"        [dim]  {line}[/dim]")
            for ref in obs.see_also:
                console.print(f"        [dim]see:[/dim] {ref}")
        console.print()

    ran = sum(1 for c in report.checks if c.status == CheckStatus.RAN)
    skipped = sum(1 for c in report.checks if c.status.value.startswith("skipped"))
    errored = sum(1 for c in report.checks if c.status == CheckStatus.ERRORED)

    # summary
    summary = Table.grid(padding=(0, 2))
    summary.add_row("observations flagged:", str(obs_count))
    summary.add_row("checks run:", str(ran))
    summary.add_row("checks skipped:", str(skipped))
    summary.add_row("checks errored:", str(errored))
    summary.add_row("exit code:", str(report.exit_code))
    console.print(Panel(summary, title="summary", border_style="blue"))

    return buf.getvalue()


def _kind_summary(v) -> str:
    if isinstance(v, list):
        return f"list[{len(v)}]"
    if isinstance(v, dict):
        return f"dict[{len(v)} keys]"
    return type(v).__name__


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def render_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"# mcp-recon report: `{report.target}`")
    lines.append("")
    lines.append(f"- tool version: `{report.tool_version}`")
    lines.append(f"- schema: `{report.schema_version}`")
    lines.append(f"- started: `{report.started_at}`")
    lines.append(f"- duration: `{report.duration_ms} ms`")
    lines.append("")

    flagged = 0
    for check in report.checks:
        lines.append(f"## {check.name}")
        lines.append(f"- status: `{check.status.value}`")
        lines.append(f"- duration: `{check.duration_ms} ms`")
        if check.notes:
            lines.append("- notes:")
            for n in check.notes:
                lines.append(f"    - {n}")
        if check.error:
            lines.append(f"- error: `{check.error}`")
        if check.observations:
            lines.append("")
            lines.append("### observations")
            for obs in check.observations:
                flagged += 1
                lines.append(f"- **{obs.title}**  `[{obs.severity.value}]`")
                lines.append("")
                lines.append(f"  {obs.summary}")
                if obs.evidence:
                    ev = json.dumps(obs.evidence, indent=2, default=str)
                    lines.append("")
                    lines.append("  ```json")
                    lines.append("  " + ev.replace("\n", "\n  "))
                    lines.append("  ```")
                if obs.follow_up:
                    lines.append("")
                    lines.append("  follow-up:")
                    lines.append("")
                    lines.append("  ```")
                    for ln in obs.follow_up.splitlines():
                        lines.append(f"  {ln}")
                    lines.append("  ```")
                for ref in obs.see_also:
                    lines.append(f"  - see: {ref}")
        lines.append("")

    lines.append("---")
    lines.append(f"**Summary:** {flagged} observations flagged, exit code {report.exit_code}")
    return "\n".join(lines)
