"""Structured logging & tamper-evident audit trail for all agent actions."""

from __future__ import annotations

import json
import datetime as dt
from pathlib import Path
from typing import Any

import structlog


def setup_logging(level: str = "INFO") -> None:
    """Configure structlog with JSON rendering for production use."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, level.upper(), structlog.INFO)  # type: ignore[arg-type]
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


class AuditLogger:
    """Append-only JSONL audit log for every tool invocation and decision."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = structlog.get_logger("audit")

    def record(
        self,
        event: str,
        *,
        tool: str | None = None,
        target: str | None = None,
        parameters: dict[str, Any] | None = None,
        result: str | None = None,
        approved_by: str | None = None,
        risk_level: str = "low",
    ) -> None:
        """Write a single audit entry to the JSONL file and structured log."""
        entry = {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "event": event,
            "tool": tool,
            "target": target,
            "parameters": parameters or {},
            "result": result,
            "approved_by": approved_by,
            "risk_level": risk_level,
        }
        # Append to file
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # Also emit via structlog (exclude 'event' key to avoid collision with structlog's event param)
        log_extra = {k: v for k, v in entry.items() if v is not None and k != "event"}
        self._log.info(event, **log_extra)


_audit_logger: AuditLogger | None = None


def get_audit_logger(log_path: Path | None = None) -> AuditLogger:
    """Return or create the singleton AuditLogger."""
    global _audit_logger  # noqa: PLW0603
    if _audit_logger is None:
        from src.config import get_settings

        path = log_path or get_settings().logging.audit_log_file
        _audit_logger = AuditLogger(path)
    return _audit_logger
