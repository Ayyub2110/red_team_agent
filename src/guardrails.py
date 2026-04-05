"""Safety guardrails — target validation, human-in-the-loop, and scope enforcement."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from src.config import get_settings

console = Console()


class TargetValidationError(Exception):
    """Raised when a target is outside the allowed scope."""


class HumanApprovalDenied(Exception):
    """Raised when a human operator denies a tool invocation."""


def validate_target(target: str) -> None:
    """Ensure *target* falls within the configured allowed subnet.

    Handles raw IPs, CIDR blocks, and hostnames (resolved to IP first).

    Raises:
        TargetValidationError: If the target is outside scope.
    """
    settings = get_settings()
    allowed = ipaddress.ip_network(settings.safety.allowed_target_subnet, strict=False)

    # Strip CIDR suffix if present for host-level check
    host = target.split("/")[0]

    # Resolve hostname → IP
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
        except socket.gaierror as exc:
            raise TargetValidationError(
                f"Cannot resolve hostname '{host}' — target validation failed."
            ) from exc

    if ip not in allowed:
        raise TargetValidationError(
            f"Target {ip} is OUTSIDE the allowed subnet {allowed}. "
            f"Refusing to proceed. Update ALLOWED_TARGET_SUBNET if this is intentional."
        )


def request_human_approval(
    tool_name: str,
    target: str,
    parameters: dict[str, Any],
    risk_level: str = "high",
) -> bool:
    """Present a tool invocation to the human operator for approval.

    Returns True if approved, raises HumanApprovalDenied otherwise.
    """
    settings = get_settings()

    if not settings.safety.require_human_approval:
        return True

    panel_content = (
        f"[bold]Tool:[/bold]        {tool_name}\n"
        f"[bold]Target:[/bold]      {target}\n"
        f"[bold]Risk Level:[/bold]  [{'red' if risk_level == 'critical' else 'yellow'}]{risk_level}[/]\n"
        f"[bold]Parameters:[/bold]\n"
    )
    for k, v in parameters.items():
        panel_content += f"  • {k}: {v}\n"

    console.print()
    console.print(
        Panel(
            panel_content,
            title="⚠️  Human-in-the-Loop Approval Required",
            border_style="red" if risk_level == "critical" else "yellow",
            expand=False,
        )
    )

    approved = Confirm.ask("[bold]Do you approve this action?[/bold]")

    if not approved:
        from src.logging import get_audit_logger

        get_audit_logger().record(
            "human_approval_denied",
            tool=tool_name,
            target=target,
            parameters=parameters,
            risk_level=risk_level,
        )
        raise HumanApprovalDenied(
            f"Human operator denied execution of {tool_name} against {target}."
        )

    from src.logging import get_audit_logger

    get_audit_logger().record(
        "human_approval_granted",
        tool=tool_name,
        target=target,
        parameters=parameters,
        approved_by="operator",
        risk_level=risk_level,
    )
    return True


def check_blocked_commands(command: str) -> None:
    """Ensure a shell command doesn't match any blocked patterns."""
    settings = get_settings()
    for blocked in settings.safety.blocked_commands:
        if blocked in command:
            raise TargetValidationError(
                f"Command contains blocked pattern '{blocked}'. Execution refused."
            )
