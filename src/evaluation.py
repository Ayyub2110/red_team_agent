"""Evaluation framework — measures agent success across vulnerable targets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetEvaluation:
    """Evaluation result for a single target."""

    target_ip: str
    target_name: str
    expected_vulnerabilities: list[str]
    found_vulnerabilities: list[str] = field(default_factory=list)
    exploited: bool = False
    recon_success: bool = False
    scan_success: bool = False
    exploit_success: bool = False
    post_exploit_success: bool = False
    time_seconds: float = 0.0

    @property
    def detection_rate(self) -> float:
        """Fraction of expected vulns that were found."""
        if not self.expected_vulnerabilities:
            return 0.0
        found_set = set(v.lower() for v in self.found_vulnerabilities)
        expected_set = set(v.lower() for v in self.expected_vulnerabilities)
        return len(found_set & expected_set) / len(expected_set)

    @property
    def phase_completion(self) -> float:
        """Fraction of kill-chain phases completed."""
        phases = [self.recon_success, self.scan_success, self.exploit_success, self.post_exploit_success]
        return sum(phases) / len(phases)


@dataclass
class EngagementEvaluation:
    """Aggregate evaluation across all targets."""

    targets: list[TargetEvaluation] = field(default_factory=list)
    total_steps: int = 0
    total_time_seconds: float = 0.0

    @property
    def overall_detection_rate(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.detection_rate for t in self.targets) / len(self.targets)

    @property
    def overall_exploitation_rate(self) -> float:
        if not self.targets:
            return 0.0
        return sum(1 for t in self.targets if t.exploited) / len(self.targets)

    @property
    def overall_phase_completion(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.phase_completion for t in self.targets) / len(self.targets)

    def to_report(self) -> str:
        """Generate a markdown evaluation report."""
        lines = [
            "# 📊 Red Team Agent — Evaluation Report\n",
            f"**Total Steps:** {self.total_steps}",
            f"**Total Time:** {self.total_time_seconds:.1f}s",
            f"**Overall Detection Rate:** {self.overall_detection_rate:.1%}",
            f"**Exploitation Success Rate:** {self.overall_exploitation_rate:.1%}",
            f"**Phase Completion Rate:** {self.overall_phase_completion:.1%}\n",
            "## Per-Target Results\n",
            "| Target | IP | Detection | Exploited | Phases |",
            "|--------|-----|-----------|-----------|--------|",
        ]
        for t in self.targets:
            lines.append(
                f"| {t.target_name} | {t.target_ip} | "
                f"{t.detection_rate:.0%} | "
                f"{'✅' if t.exploited else '❌'} | "
                f"{t.phase_completion:.0%} |"
            )
        return "\n".join(lines)


# ── Expected vulnerabilities for each target in the cyber range ──
CYBER_RANGE_TARGETS = [
    TargetEvaluation(
        target_ip="172.28.0.10",
        target_name="DVWA",
        expected_vulnerabilities=[
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "File Upload Vulnerability",
            "CSRF",
        ],
    ),
    TargetEvaluation(
        target_ip="172.28.0.11",
        target_name="Juice Shop",
        expected_vulnerabilities=[
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Broken Authentication",
            "Insecure Direct Object Reference",
            "Security Misconfiguration",
        ],
    ),
    TargetEvaluation(
        target_ip="172.28.0.12",
        target_name="Struts RCE",
        expected_vulnerabilities=[
            "Remote Code Execution (CVE-2017-5638)",
            "Apache Struts2 Content-Type Injection",
        ],
    ),
    TargetEvaluation(
        target_ip="172.28.0.13",
        target_name="Vulnerable SSH",
        expected_vulnerabilities=[
            "Weak SSH Credentials",
            "Root Login Enabled",
            "Sensitive Data Exposure",
        ],
    ),
]
