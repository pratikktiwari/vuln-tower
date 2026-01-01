"""
Centralized configuration management.

This is the ONLY module that reads environment variables.
All other modules must receive configuration via dependency injection.

Configuration is loaded from a pluggable SecretProvider (env vars by default), validated, and exposed as immutable
dataclass instances.
"""

from dataclasses import dataclass
from typing import Optional, List
import os

from .secrets import SecretProvider, EnvSecretProvider


def _get_secret_provider() -> SecretProvider:
    """
    Factory function to create the appropriate secret provider.

    Returns:
        A SecretProvider instance based on SECRET_PROVIDER env var
    """
    provider_type = os.getenv("SECRET_PROVIDER", "env").lower()

    if provider_type == "env":
        return EnvSecretProvider()
    else:
        raise ValueError(f"Unknown secret provider: {provider_type}")


# Global secret provider instance
_provider = _get_secret_provider()


def _get_str(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get string value from secret provider."""
    value = _provider.get_secret(key)
    return value if value is not None else default


def _get_int(key: str, default: int) -> int:
    """Get integer value from secret provider."""
    value = _provider.get_secret(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"Invalid integer value for {key}: {value}")


def _get_float(key: str, default: float) -> float:
    """Get float value from secret provider."""
    value = _provider.get_secret(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        raise ValueError(f"Invalid float value for {key}: {value}")


def _get_bool(key: str, default: bool) -> bool:
    """Get boolean value from secret provider."""
    value = _provider.get_secret(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


def _get_list(key: str, default: Optional[List[str]] = None) -> List[str]:
    """Get comma-separated list from secret provider."""
    value = _provider.get_secret(key)
    if value is None:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class GeneralConfig:
    """General application configuration."""

    app_name: str
    log_level: str
    run_mode: str

    @staticmethod
    def load() -> "GeneralConfig":
        return GeneralConfig(
            app_name=_get_str("APP_NAME", "vuln-tower"),
            log_level=_get_str("LOG_LEVEL", "INFO").upper(),
            run_mode=_get_str("RUN_MODE", "cron").lower(),
        )


@dataclass(frozen=True)
class DatabaseConfig:
    """Database configuration."""

    db_type: str
    db_name: str
    db_host: Optional[str]
    db_port: Optional[int]
    db_user: Optional[str]
    db_password: Optional[str]

    @staticmethod
    def load() -> "DatabaseConfig":
        db_type = _get_str("DB_TYPE", "sqlite").lower()

        return DatabaseConfig(
            db_type=db_type,
            db_name=_get_str("DB_NAME", "vuln_tower.db"),
            db_host=_get_str("DB_HOST"),
            db_port=_get_int("DB_PORT", 5432) if _get_str("DB_PORT") else None,
            db_user=_get_str("DB_USER"),
            db_password=_get_str("DB_PASSWORD"),
        )


@dataclass(frozen=True)
class NVDConfig:
    """NVD API configuration."""

    api_key: Optional[str]
    fetch_window_minutes: int
    max_results_per_run: int
    request_timeout: int

    @staticmethod
    def load() -> "NVDConfig":
        return NVDConfig(
            api_key=_get_str("NVD_API_KEY"),
            fetch_window_minutes=_get_int("FETCH_WINDOW_MINUTES", 60),
            max_results_per_run=_get_int("MAX_RESULTS_PER_RUN", 100),
            request_timeout=_get_int("REQUEST_TIMEOUT", 30),
        )


@dataclass(frozen=True)
class FilterConfig:
    """CVE filtering configuration."""

    min_cvss_score: float
    keywords: List[str]
    products: List[str]
    vendors: List[str]
    attack_vector: Optional[str]

    @staticmethod
    def load() -> "FilterConfig":
        return FilterConfig(
            min_cvss_score=_get_float("MIN_CVSS_SCORE", 0.0),
            keywords=_get_list("KEYWORDS", []),
            products=_get_list("PRODUCTS", []),
            vendors=_get_list("VENDORS", []),
            attack_vector=_get_str("ATTACK_VECTOR"),
        )


@dataclass(frozen=True)
class NotificationConfig:
    """Notification channel configuration."""

    enable_discord: bool
    discord_webhook_url: Optional[str]
    enable_slack: bool
    slack_webhook_url: Optional[str]
    enable_teams: bool
    teams_webhook_url: Optional[str]
    enable_telegram: bool
    telegram_bot_token: Optional[str]
    telegram_chat_id: Optional[str]
    rate_limit_delay: float

    @staticmethod
    def load() -> "NotificationConfig":
        return NotificationConfig(
            enable_discord=_get_bool("ENABLE_DISCORD", False),
            discord_webhook_url=_get_str("DISCORD_WEBHOOK_URL"),
            enable_slack=_get_bool("ENABLE_SLACK", False),
            slack_webhook_url=_get_str("SLACK_WEBHOOK_URL"),
            enable_teams=_get_bool("ENABLE_TEAMS", False),
            teams_webhook_url=_get_str("TEAMS_WEBHOOK_URL"),
            enable_telegram=_get_bool("ENABLE_TELEGRAM", False),
            telegram_bot_token=_get_str("TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=_get_str("TELEGRAM_CHAT_ID"),
            rate_limit_delay=_get_float("NOTIFICATION_RATE_LIMIT_DELAY", 1.0),
        )


@dataclass(frozen=True)
class PipelineConfig:
    """Middleware pipeline configuration."""

    enable_pipeline: bool
    pipeline_steps: List[str]
    llm_provider: Optional[str]
    llm_api_key: Optional[str]
    llm_model: Optional[str]

    @staticmethod
    def load() -> "PipelineConfig":
        return PipelineConfig(
            enable_pipeline=_get_bool("ENABLE_PIPELINE", False),
            pipeline_steps=_get_list("PIPELINE_STEPS", []),
            llm_provider=_get_str("LLM_PROVIDER"),
            llm_api_key=_get_str("LLM_API_KEY"),
            llm_model=_get_str("LLM_MODEL"),
        )


@dataclass(frozen=True)
class Config:
    """Root configuration object containing all sub-configurations."""

    general: GeneralConfig
    database: DatabaseConfig
    nvd: NVDConfig
    filter: FilterConfig
    notification: NotificationConfig
    pipeline: PipelineConfig

    @staticmethod
    def load() -> "Config":
        """
        Load all configuration from the secret provider.

        Returns:
            Immutable Config instance with all settings
        """
        return Config(
            general=GeneralConfig.load(),
            database=DatabaseConfig.load(),
            nvd=NVDConfig.load(),
            filter=FilterConfig.load(),
            notification=NotificationConfig.load(),
            pipeline=PipelineConfig.load(),
        )
