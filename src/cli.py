"""CLI entry point for the Red Team Agent.

Supports engagement modes:
  --mode dynamic   (default) — medium aggression, full kill-chain
  --mode safe      — low aggression, stealth, no exploitation
  --mode aggressive — high aggression, more steps, extra warnings
"""

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


def _print_mode_warning(mode: str) -> None:
    """Print mode-specific warnings before engagement starts."""
    if mode == "aggressive":
        console.print()
        console.print(
            Panel(
                "[bold red]⚠️  AGGRESSIVE MODE ENABLED[/bold red]\n\n"
                "This mode uses [bold]high aggression[/bold] with extended step limits.\n"
                "• Exploitation will be attempted on all viable targets\n"
                "• Kill-switch threshold is relaxed (risk > 80)\n"
                "• Human approval is still required for exploit execution\n\n"
                "[yellow]Ensure you have explicit written authorisation for all targets.[/yellow]",
                title="🔴 Aggressive Mode Warning",
                border_style="red",
                expand=False,
            )
        )
    elif mode == "safe":
        console.print()
        console.print(
            Panel(
                "[bold green]🛡️  SAFE MODE ENABLED[/bold green]\n\n"
                "This mode uses [bold]low aggression[/bold] with stealth scanning.\n"
                "• No exploitation will be attempted\n"
                "• Uses SYN scans and slow timing (stealth)\n"
                "• Reduced step limit (30 steps)\n"
                "• Ideal for initial reconnaissance and assessment",
                title="🛡️ Safe Mode",
                border_style="green",
                expand=False,
            )
        )


def cmd_run(args: argparse.Namespace) -> None:
    """Run the red team agent."""
    from src.agent.graph import run_redteam_agent

    print_banner()

    mode = getattr(args, "mode", "dynamic")
    _print_mode_warning(mode)

    console.print()
    console.print(
        Panel(
            f"[bold]Target Subnet:[/bold] {args.target}\n"
            f"[bold]Objective:[/bold]     {args.objective}\n"
            f"[bold]Model:[/bold]         {args.model or 'from config'}\n"
            f"[bold]Mode:[/bold]          {mode}",
            title="🎯 Engagement Configuration",
            border_style="blue",
        )
    )

    if args.model:
        import os
        os.environ["OLLAMA_MODEL"] = args.model

    targets = [t.strip() for t in args.target.split(",")]

    final_state = run_redteam_agent(
        objective=args.objective,
        targets=targets,
        mode=mode,
        verbose=getattr(args, "verbose", False),
    )

    # ── Results ──
    console.print()
    console.print(Panel("📊 Engagement Complete", style="bold green"))

    # Get the state values (handles both dict and StateSnapshot)
    state_vals = final_state.values if hasattr(final_state, "values") else final_state

    # Show kill-switch status
    if state_vals.get("kill_switch_triggered"):
        console.print(
            Panel(
                f"[bold red]🛑 KILL SWITCH ACTIVATED[/bold red]\n"
                f"Reason: {state_vals.get('kill_switch_reason', 'Unknown')}",
                border_style="red",
            )
        )

    # Show findings
    findings = state_vals.get("findings", [])
    if findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Target", style="cyan")
        table.add_column("Vulnerability", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Confidence", style="blue", justify="center")
        table.add_column("Evidence", style="dim", max_width=40)
        table.add_column("Remediation", style="green", max_width=40)

        for f in findings:
            sev = f.get("severity", "")
            sev_style = {
                "critical": "[bold red]critical[/bold red]",
                "high": "[red]high[/red]",
                "medium": "[yellow]medium[/yellow]",
                "low": "[blue]low[/blue]",
                "info": "[dim]info[/dim]",
            }.get(sev, sev)

            table.add_row(
                f.get("target", ""),
                f.get("vulnerability", f.get("vuln_type", "")),
                sev_style,
                f"{f.get('confidence', 0):.0%}" if f.get("confidence") else "—",
                (f.get("evidence", "") or "")[:80],
                (f.get("remediation", "") or "")[:80],
            )
        console.print(table)
    else:
        console.print("[yellow]No structured findings recorded.[/yellow]")
        console.print("[dim]Check the agent messages above for unstructured results.[/dim]")

    # Show engagement summary
    console.print()
    summary_table = Table(title="Engagement Summary", show_lines=True)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Steps", str(state_vals.get("step_count", 0)))
    summary_table.add_row("Final Phase", state_vals.get("current_phase", "?"))
    summary_table.add_row("Risk Score", f"{state_vals.get('risk_score', 0):.0f}/100")
    summary_table.add_row("Targets Discovered", str(len(state_vals.get("discovered_targets", []))))
    summary_table.add_row("Total Errors", str(state_vals.get("total_errors", 0)))
    summary_table.add_row("Critic Interventions", str(len(state_vals.get("critic_feedback", []))))
    console.print(summary_table)

    # Generate detailed report if requested
    if getattr(args, "report", False):
        _generate_report(state_vals)


def _generate_report(state_vals: dict) -> None:
    """Generate and display the full engagement report."""
    from src.evaluation import build_engagement_report

    report = build_engagement_report(state_vals)
    md = report.to_markdown()

    console.print()
    console.print(Panel("📋 Detailed Engagement Report", style="bold blue"))
    console.print(md)

    # Also save to file
    from pathlib import Path
    report_dir = Path("logs/reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    report_path = report_dir / f"engagement_report_{ts}.md"
    report_path.write_text(md, encoding="utf-8")
    console.print(f"\n[dim]Report saved to: {report_path}[/dim]")


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

def cmd_demo(args: argparse.Namespace) -> None:
    """Run a pre-recorded mock engagement for demonstration."""
    import time
    print_banner()
    
    console.print(Panel("🎬 [bold cyan]Starting Pre-recorded Demo Engagement[/bold cyan]\n[dim]No actual network requests will be made.[/dim]", border_style="cyan"))
    
    events = [
        ("strategic_planner", "Transitioning to Scanning phase based on finding web services.", "🧠"),
        ("adaptive_strategy", "Target is a highly-likely web server. Recommending web_specialist with http_get and directory_bruteforce.", "🎯"),
        ("web_specialist", "Executing fast directory brute-force on 172.28.0.10:80 to find admin panels.", "🔬"),
        ("nmap_scan", "Found Sub-directories: /admin, /login, /upload", "🔍"),
        ("critic", "[warning] No critical vulnerabilities found in last 5 steps. Broadening scan scope.", "🔍"),
        ("web_specialist", "Testing /upload for arbitrary file upload vulnerability...", "🔬"),
        ("strategic_planner", "High risk vulnerability discovered! Halting for human approval.", "🛑"),
        ("human_approval", "Exploit action approved by operator.", "👤"),
        ("adaptive_learning", "Self-critique: The agent efficiently identified the web service and utilized the web_specialist appropriately. Next time, could attempt stealthier HTTP probing before full brute-force.", "🧑‍🏫")
    ]
    
    for actor, message, icon in events:
        time.sleep(1.5)
        if actor == "human_approval":
            console.print(Panel(message, title="✅ Human-in-the-Loop", border_style="green"))
            time.sleep(0.5)
        else:
            console.print(f"  {icon} [{actor}]: {message}")

    time.sleep(1)
    console.print("\n[bold green]✅ Demo engagement completed successfully.[/bold green]\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="🔴 Red Team Agent — Autonomous AI Security Assessment",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # ── run ──
    rp = sub.add_parser("run", help="Launch the red team agent")
    rp.add_argument("-t", "--target", default="172.28.0.0/16", help="Target subnet (CIDR or comma-separated IPs)")
    rp.add_argument(
        "-o", "--objective",
        default="Perform a full red team assessment on the target environment.",
        help="Engagement objective",
    )
    rp.add_argument("-m", "--model", default=None, help="Override Ollama model name")
    rp.add_argument(
        "--mode",
        choices=["dynamic", "safe", "aggressive"],
        default="dynamic",
        help="Engagement mode: dynamic (default), safe (recon-only), aggressive (full auto)",
    )
    rp.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Generate detailed evaluation report after engagement",
    )
    rp.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Show detailed reasoning and complete output blocks",
    )
    rp.set_defaults(func=cmd_run)

    # ── report ──
    rep = sub.add_parser("report", help="Display audit log")
    rep.add_argument("-l", "--log-file", default="logs/audit.jsonl", help="Audit log path")
    rep.set_defaults(func=cmd_report)

    # ── demo ──
    demo = sub.add_parser("demo", help="Run a recorded safe engagement demo (no network activity)")
    demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
