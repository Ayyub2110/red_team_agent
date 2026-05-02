"""Pydantic-based configuration with environment variable loading."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class LLMSettings(BaseSettings):
    """LLM provider configuration."""
    model_config = {"env_file": ".env", "extra": "ignore"}

    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen2.5-coder:7b", alias="OLLAMA_MODEL")
    temperature: float = 0.1
    max_tokens: int = 4096


class MetasploitSettings(BaseSettings):
    """Metasploit RPC connection settings."""
    model_config = {"env_file": ".env", "extra": "ignore"}

    host: str = Field(default="127.0.0.1", alias="MSF_RPC_HOST")
    port: int = Field(default=55553, alias="MSF_RPC_PORT")
    user: str = Field(default="msf", alias="MSF_RPC_USER")
    password: str = Field(default="msf_password", alias="MSF_RPC_PASS")


class SafetySettings(BaseSettings):
    """Safety guardrail configuration."""
    model_config = {"env_file": ".env", "extra": "ignore"}

    require_human_approval: bool = Field(default=True, alias="REQUIRE_HUMAN_APPROVAL")
    disable_target_validation: bool = Field(default=True, alias="DISABLE_TARGET_VALIDATION")
    max_agent_steps: int = Field(default=50, alias="MAX_AGENT_STEPS")
    allowed_target_subnet: str = Field(default="0.0.0.0/0", alias="ALLOWED_TARGET_SUBNET")
    blocked_commands: list[str] = Field(default_factory=lambda: [
        "rm -rf /",
        "mkfs",
        "dd if=/dev/zero",
        ":(){:|:&};:",
    ])


class LoggingSettings(BaseSettings):
    """Logging and audit trail configuration."""
    model_config = {"env_file": ".env", "extra": "ignore"}

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    audit_log_file: Path = Field(default=Path("logs/audit.jsonl"), alias="AUDIT_LOG_FILE")
    enable_structured_logging: bool = True


class Settings(BaseSettings):
    """Root application settings — aggregates all sub-configs."""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    llm: LLMSettings = Field(default_factory=LLMSettings)
    metasploit: MetasploitSettings = Field(default_factory=MetasploitSettings)
    safety: SafetySettings = Field(default_factory=SafetySettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # Project paths
    project_root: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent)


# Singleton
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return cached Settings instance."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = Settings()
    return _settings
