"""CLI entry point for the Red Team Agent."""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_banner() -> None:
    banner = r"""
 ╔══════════════════════════════════════════════════════════╗
 ║  🔴  RED TEAM AGENT — Autonomous Security Assessment   ║
 ║      Powered by LangGraph + Ollama                      ║
 ╚══════════════════════════════════════════════════════════╝"""
    console.print(banner, style="bold red")


def cmd_run(args: argparse.Namespace) -> None:
    """Run the red team agent."""
    from src.agent.graph import run_agent

    print_banner()

    console.print(
        Panel(
            f"[bold]Target Subnet:[/bold] {args.target}\n"
            f"[bold]Objective:[/bold]     {args.objective}\n"
            f"[bold]Model:[/bold]         {args.model or 'from config'}",
            title="🎯 Engagement Configuration",
            border_style="blue",
        )
    )

    if args.model:
        import os
        os.environ["OLLAMA_MODEL"] = args.model

    final_state = run_agent(target_subnet=args.target, objective=args.objective)

    # ── Results ──
    console.print()
    console.print(Panel("📊 Engagement Complete", style="bold green"))

    findings = final_state.get("findings", [])
    if findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Target", style="cyan")
        table.add_column("Vuln Type", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Evidence", style="dim", max_width=40)
        table.add_column("Remediation", style="green", max_width=40)

        for f in findings:
            table.add_row(
                f.get("target", ""),
                f.get("vuln_type", ""),
                f.get("severity", ""),
                (f.get("evidence", "") or "")[:80],
                (f.get("remediation", "") or "")[:80],
            )
        console.print(table)
    else:
        console.print("[yellow]No structured findings recorded.[/yellow]")
        console.print("[dim]Check the agent messages above for unstructured results.[/dim]")

    console.print(f"\n[bold]Steps:[/bold]  {final_state.get('step_count', 0)}")
    console.print(f"[bold]Phase:[/bold]  {final_state.get('current_phase', '?')}")


def cmd_report(args: argparse.Namespace) -> None:
    """View the audit log."""
    from pathlib import Path

    log_path = Path(args.log_file)
    if not log_path.exists():
        console.print(f"[red]Audit log not found: {log_path}[/red]")
        sys.exit(1)

    entries = [json.loads(line) for line in log_path.read_text().strip().splitlines() if line.strip()]

    console.print(Panel(f"📋 Audit Log — {len(entries)} entries", style="bold blue"))
    table = Table(title="Audit Trail")
    table.add_column("Time", style="dim", max_width=19)
    table.add_column("Event", style="cyan")
    table.add_column("Tool", style="yellow")
    table.add_column("Target", style="red")
    table.add_column("Risk", style="bold")

    for e in entries:
        table.add_row(
            e.get("timestamp", "")[:19],
            e.get("event", ""),
            e.get("tool", "—"),
            e.get("target", "—"),
            e.get("risk_level", "low"),
        )
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="🔴 Red Team Agent — Autonomous AI Security Assessment",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # ── run ──
    rp = sub.add_parser("run", help="Launch the red team agent")
    rp.add_argument("-t", "--target", default="172.28.0.0/16", help="Target subnet (CIDR)")
    rp.add_argument(
        "-o", "--objective",
        default="Perform a full red team assessment on the DVWA target.",
        help="Engagement objective",
    )
    rp.add_argument("-m", "--model", default=None, help="Override Ollama model name")
    rp.set_defaults(func=cmd_run)

    # ── report ──
    rep = sub.add_parser("report", help="Display audit log")
    rep.add_argument("-l", "--log-file", default="logs/audit.jsonl", help="Audit log path")
    rep.set_defaults(func=cmd_report)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
