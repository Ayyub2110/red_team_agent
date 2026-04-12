"""Evaluator — batch test runner, cross-config comparison, and reporting.

Runs the dynamic test suite scenarios across different configurations
(modes, models, step budgets) and produces:
- Per-scenario JSON reports with 5-axis scoring
- Cross-configuration comparison tables
- Summary markdown/Rich dashboard

Usage:
    # Run default scenarios
    python -m evaluation.evaluator

    # Compare modes
    python -m evaluation.evaluator --compare-modes

    # Compare step budgets
    python -m evaluation.evaluator --compare-budgets 10 25 50

    # Save markdown report
    python -m evaluation.evaluator --output logs/evaluation_report.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ── Try Rich for terminal dashboard ──────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConfigProfile:
    """A single configuration to evaluate the agent against."""

    name: str
    mode: str  # "safe", "dynamic", "aggressive"
    max_steps: int = 50
    stealth: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioScore:
    """Per-scenario scores from a single run."""

    scenario_id: int
    scenario_name: str
    success_rate: float = 0.0
    safety_compliance: float = 0.0
    efficiency: float = 0.0
    risk_management: float = 0.0
    phase_smoothness: float = 0.0
    overall: float = 0.0
    final_phase: str = ""
    total_steps: int = 0
    total_findings: int = 0
    kill_switch: bool = False


@dataclass
class EvalRunResult:
    """Results of a complete evaluation run for one configuration."""

    config: ConfigProfile
    scenario_scores: list[ScenarioScore] = field(default_factory=list)
    timestamp: str = ""

    @property
    def avg_overall(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.overall for s in self.scenario_scores) / len(self.scenario_scores), 1)

    @property
    def avg_safety(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.safety_compliance for s in self.scenario_scores) / len(self.scenario_scores), 1)

    @property
    def avg_success(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.success_rate for s in self.scenario_scores) / len(self.scenario_scores), 1)

    @property
    def avg_efficiency(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.efficiency for s in self.scenario_scores) / len(self.scenario_scores), 1)

    @property
    def avg_risk_mgmt(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.risk_management for s in self.scenario_scores) / len(self.scenario_scores), 1)

    @property
    def avg_smoothness(self) -> float:
        if not self.scenario_scores:
            return 0.0
        return round(sum(s.phase_smoothness for s in self.scenario_scores) / len(self.scenario_scores), 1)


# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Pre-defined configuration profiles for comparison
DEFAULT_CONFIGS: list[ConfigProfile] = [
    ConfigProfile("Safe Mode", "safe", max_steps=30, stealth=True,
                  description="Reconnaissance-only, stealth scans"),
    ConfigProfile("Dynamic Mode", "dynamic", max_steps=50,
                  description="Balanced operation, full kill-chain"),
    ConfigProfile("Aggressive Mode", "aggressive", max_steps=75,
                  description="Maximum aggression, extended budget"),
]


def run_evaluation(config: ConfigProfile) -> EvalRunResult:
    """Run all 8 scenarios against a single configuration.

    Uses the test suite's batch runner, overriding mode and step budget.
    """
    from tests.dynamic_test_suite import ALL_SCENARIOS, ScenarioResult, _run_planner_loop
    from src.agent.graph import MODE_PRESETS
    from src.agent.state import initial_state

    preset = MODE_PRESETS.get(config.mode, MODE_PRESETS["dynamic"])
    scores: list[ScenarioScore] = []

    for scenario in ALL_SCENARIOS:
        state = initial_state(
            targets=scenario["targets"],
            max_steps=config.max_steps,
            aggression_level=preset["aggression_level"],
            stealth_mode=config.stealth or preset.get("stealth_mode", False),
        )
        state["discovered_targets"] = scenario.get("discovered", [])
        state["findings"] = list(scenario.get("findings", []))
        state["active_sessions"] = dict(scenario.get("sessions", {}))
        state["error_log"] = list(scenario.get("errors", []))
        state["consecutive_failures"] = scenario.get("consec_failures", 0)
        state["phase_failures"] = dict(scenario.get("phase_failures", {}))

        state = _run_planner_loop(state)

        result = ScenarioResult(
            scenario_id=scenario["id"],
            scenario_name=scenario["name"],
            mode=config.mode,
            targets=scenario["targets"],
            execution_trace=state.get("_trace", []),
        )
        result.compute_scores(state)

        scores.append(ScenarioScore(
            scenario_id=scenario["id"],
            scenario_name=scenario["name"],
            success_rate=result.success_rate,
            safety_compliance=result.safety_compliance,
            efficiency=result.efficiency,
            risk_management=result.risk_management,
            phase_smoothness=result.phase_smoothness,
            overall=result.overall,
            final_phase=result.final_phase,
            total_steps=result.total_steps,
            total_findings=result.total_findings,
            kill_switch=result.kill_switch_triggered,
        ))

    return EvalRunResult(
        config=config,
        scenario_scores=scores,
        timestamp=dt.datetime.now(dt.UTC).isoformat(),
    )


def compare_configs(configs: list[ConfigProfile] | None = None) -> list[EvalRunResult]:
    """Run evaluation across multiple configurations for comparison."""
    if configs is None:
        configs = DEFAULT_CONFIGS

    results: list[EvalRunResult] = []
    for config in configs:
        result = run_evaluation(config)
        results.append(result)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

def _grade(score: float) -> str:
    """Convert score to letter grade."""
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def _grade_emoji(score: float) -> str:
    if score >= 80: return "🟢"
    if score >= 60: return "🟡"
    if score >= 40: return "🟠"
    return "🔴"


def generate_markdown_report(results: list[EvalRunResult]) -> str:
    """Generate a comprehensive markdown comparison report."""
    ts = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# 🔴 Red Team Agent — Evaluation Report\n",
        f"**Generated:** {ts}",
        f"**Configurations Compared:** {len(results)}\n",
        "---\n",
    ]

    # ── Summary Comparison Table ──
    lines.append("## 📊 Configuration Comparison\n")
    lines.append("| Config | Overall | Success | Safety | Efficiency | Risk Mgmt | Smoothness | Grade |")
    lines.append("|--------|---------|---------|--------|------------|-----------|------------|-------|")

    for r in results:
        lines.append(
            f"| **{r.config.name}** | "
            f"{_grade_emoji(r.avg_overall)} {r.avg_overall} | "
            f"{r.avg_success} | "
            f"{r.avg_safety} | "
            f"{r.avg_efficiency} | "
            f"{r.avg_risk_mgmt} | "
            f"{r.avg_smoothness} | "
            f"**{_grade(r.avg_overall)}** |"
        )

    lines.append("")

    # ── Per-Config Detail ──
    for r in results:
        lines.append(f"\n---\n\n## {r.config.name}\n")
        lines.append(f"**Mode:** {r.config.mode} | "
                      f"**Steps:** {r.config.max_steps} | "
                      f"**Stealth:** {'✓' if r.config.stealth else '✗'}\n")

        lines.append("| # | Scenario | Overall | Success | Safety | Eff. | Risk | Smooth | Phase | Steps | Findings | KS |")
        lines.append("|---|----------|---------|---------|--------|------|------|--------|-------|-------|----------|----|")

        for s in r.scenario_scores:
            ks = "🛑" if s.kill_switch else "✅"
            lines.append(
                f"| {s.scenario_id} | {s.scenario_name} | "
                f"{_grade_emoji(s.overall)} {s.overall} | "
                f"{s.success_rate} | {s.safety_compliance} | "
                f"{s.efficiency} | {s.risk_management} | "
                f"{s.phase_smoothness} | {s.final_phase} | "
                f"{s.total_steps} | {s.total_findings} | {ks} |"
            )
        lines.append("")

    # ── Insights ──
    lines.append("\n---\n\n## 💡 Insights\n")

    if len(results) >= 2:
        best = max(results, key=lambda r: r.avg_overall)
        safest = max(results, key=lambda r: r.avg_safety)
        most_efficient = max(results, key=lambda r: r.avg_efficiency)

        lines.append(f"- **Best Overall:** {best.config.name} ({best.avg_overall}/100)")
        lines.append(f"- **Safest:** {safest.config.name} ({safest.avg_safety}/100)")
        lines.append(f"- **Most Efficient:** {most_efficient.config.name} ({most_efficient.avg_efficiency}/100)")

        # Kill-switch analysis
        for r in results:
            ks_count = sum(1 for s in r.scenario_scores if s.kill_switch)
            if ks_count > 0:
                lines.append(f"- **Kill-switch triggered {ks_count}× in {r.config.name}**")

    lines.append("")
    return "\n".join(lines)


def print_rich_dashboard(results: list[EvalRunResult]) -> None:
    """Print a Rich terminal dashboard with comparison tables."""
    if not HAS_RICH:
        print("Rich is not installed. Use --output to save a markdown report.")
        return

    console = Console()

    # ── Title ──
    console.print()
    console.print(Panel(
        "[bold red]🔴 RED TEAM AGENT — EVALUATION DASHBOARD[/bold red]\n"
        f"[dim]{dt.datetime.now(dt.UTC).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
        border_style="red",
    ))

    # ── Summary Table ──
    summary = Table(title="📊 Configuration Comparison", show_lines=True)
    summary.add_column("Config", style="bold cyan")
    summary.add_column("Overall", justify="center")
    summary.add_column("Success", justify="center")
    summary.add_column("Safety", justify="center")
    summary.add_column("Efficiency", justify="center")
    summary.add_column("Risk Mgmt", justify="center")
    summary.add_column("Smoothness", justify="center")
    summary.add_column("Grade", justify="center", style="bold")

    for r in results:
        overall_style = "green" if r.avg_overall >= 70 else "yellow" if r.avg_overall >= 50 else "red"
        summary.add_row(
            r.config.name,
            f"[{overall_style}]{r.avg_overall}[/{overall_style}]",
            str(r.avg_success),
            str(r.avg_safety),
            str(r.avg_efficiency),
            str(r.avg_risk_mgmt),
            str(r.avg_smoothness),
            _grade(r.avg_overall),
        )

    console.print(summary)

    # ── Per-Config Detail Tables ──
    for r in results:
        console.print()
        detail = Table(
            title=f"🔍 {r.config.name} — Scenario Breakdown",
            show_lines=True,
        )
        detail.add_column("#", style="dim", width=3)
        detail.add_column("Scenario", max_width=35)
        detail.add_column("Overall", justify="center")
        detail.add_column("Phase", style="cyan")
        detail.add_column("Steps", justify="right")
        detail.add_column("Findings", justify="right")
        detail.add_column("KS", justify="center")

        for s in r.scenario_scores:
            ov_style = "green" if s.overall >= 70 else "yellow" if s.overall >= 50 else "red"
            ks_icon = "🛑" if s.kill_switch else "✅"
            detail.add_row(
                str(s.scenario_id),
                s.scenario_name,
                f"[{ov_style}]{s.overall}[/{ov_style}]",
                s.final_phase,
                str(s.total_steps),
                str(s.total_findings),
                ks_icon,
            )

        console.print(detail)

    # ── Insights ──
    if len(results) >= 2:
        best = max(results, key=lambda r: r.avg_overall)
        safest = max(results, key=lambda r: r.avg_safety)

        console.print()
        console.print(Panel(
            f"[green]🏆 Best Overall:[/green] {best.config.name} ({best.avg_overall}/100)\n"
            f"[blue]🛡️ Safest:[/blue] {safest.config.name} ({safest.avg_safety}/100)",
            title="💡 Insights",
            border_style="blue",
        ))


def save_json_report(results: list[EvalRunResult], path: Path) -> None:
    """Save full results to JSON."""
    data = {
        "timestamp": dt.datetime.now(dt.UTC).isoformat(),
        "configurations": len(results),
        "results": [
            {
                "config": r.config.to_dict(),
                "averages": {
                    "overall": r.avg_overall,
                    "success": r.avg_success,
                    "safety": r.avg_safety,
                    "efficiency": r.avg_efficiency,
                    "risk_management": r.avg_risk_mgmt,
                    "smoothness": r.avg_smoothness,
                },
                "scenarios": [asdict(s) for s in r.scenario_scores],
            }
            for r in results
        ],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point for the evaluator."""
    parser = argparse.ArgumentParser(
        prog="evaluator",
        description="🔴 Red Team Agent — Evaluation & Comparison Tool",
    )
    parser.add_argument(
        "--compare-modes", action="store_true",
        help="Compare safe / dynamic / aggressive modes",
    )
    parser.add_argument(
        "--compare-budgets", nargs="+", type=int, metavar="STEPS",
        help="Compare different step budgets (e.g., 10 25 50)",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Save markdown report to this path",
    )
    parser.add_argument(
        "--json", type=str, default=None,
        help="Save JSON results to this path",
    )

    args = parser.parse_args()

    # Build configurations
    configs: list[ConfigProfile] = []

    if args.compare_budgets:
        for budget in args.compare_budgets:
            configs.append(ConfigProfile(
                name=f"Dynamic ({budget} steps)",
                mode="dynamic",
                max_steps=budget,
                description=f"Dynamic mode with {budget}-step budget",
            ))
    elif args.compare_modes:
        configs = DEFAULT_CONFIGS
    else:
        configs = DEFAULT_CONFIGS

    # Run evaluation
    results = compare_configs(configs)

    # Output
    if args.output:
        md = generate_markdown_report(results)
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
        print(f"📄 Report saved to: {out_path}")

    if args.json:
        json_path = Path(args.json)
        save_json_report(results, json_path)
        print(f"📦 JSON saved to: {json_path}")

    # Always print Rich dashboard if available
    print_rich_dashboard(results)

    if not args.output and not args.json:
        # Auto-save markdown
        report_dir = Path("logs/evaluation_reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        auto_path = report_dir / f"eval_{ts}.md"
        md = generate_markdown_report(results)
        auto_path.write_text(md, encoding="utf-8")
        print(f"\n📄 Auto-saved report: {auto_path}")


if __name__ == "__main__":
    main()
