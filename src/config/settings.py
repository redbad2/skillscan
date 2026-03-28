"""
SkillScan Configuration Settings

Manages all configuration options for the threat analysis engine.
Supports loading from YAML files and environment variables.
"""

import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.config.loader import ConfigLoader
from src.config.validator import validate_all

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Default configuration directory
DEFAULT_CONFIG_DIR = Path(__file__).parent.parent.parent / "config"


class MongoDBSettings(BaseSettings):
    """MongoDB configuration settings."""

    model_config = SettingsConfigDict(env_prefix="MONGODB_", extra="ignore")

    uri: str = Field(default="mongodb://localhost:27017")
    database: str = Field(default="skillscan")
    username: str | None = Field(default=None)
    password: str | None = Field(default=None)
    auth_source: str = Field(default="admin")
    max_pool_size: int = Field(default=100)
    min_pool_size: int = Field(default=10)


class RedisSettings(BaseSettings):
    """Redis configuration settings."""

    model_config = SettingsConfigDict(env_prefix="REDIS_", extra="ignore")

    url: str = Field(default="redis://localhost:6379/0")
    password: str | None = Field(default=None)
    max_connections: int = Field(default=50)


class CelerySettings(BaseSettings):
    """Celery configuration settings."""

    model_config = SettingsConfigDict(env_prefix="CELERY_", extra="ignore")

    broker_url: str = Field(default="redis://localhost:6379/0")
    result_backend: str = Field(default="redis://localhost:6379/1")
    task_serializer: str = Field(default="json")
    result_serializer: str = Field(default="json")
    accept_content: list[str] = Field(default=["json"])
    timezone: str = Field(default="UTC")
    enable_utc: bool = Field(default=True)


class LLMSettings(BaseSettings):
    """LLM configuration settings."""

    model_config = SettingsConfigDict(env_prefix="LLM_", extra="ignore")

    openai_api_key: str | None = Field(default=None)
    openai_model: str = Field(default="gpt-4-turbo-preview")
    anthropic_api_key: str | None = Field(default=None)
    anthropic_model: str = Field(default="claude-3-opus-20240229")
    max_tokens: int = Field(default=4000)
    temperature: float = Field(default=0.1)
    timeout: int = Field(default=60)


class CollectorSettings(BaseSettings):
    """Data collector configuration settings."""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    crawl_concurrency: int = Field(default=10)
    crawl_delay_ms: int = Field(default=1000)
    crawl_user_agent: str = Field(default="SkillScan/1.0")
    crawl_timeout: int = Field(default=30)
    crawl_max_retries: int = Field(default=3)

    local_scan_threads: int = Field(default=4)
    local_watch_enabled: bool = Field(default=False)
    local_watch_recursive: bool = Field(default=True)

    clawhub_api_url: str = Field(default="https://api.clawhub.com/v1")
    smithery_api_url: str = Field(default="https://api.smithery.ai/v1")
    skillssh_api_url: str = Field(default="https://api.skills.sh/v1")
    skillsmp_api_url: str = Field(default="https://skillsmp.com/api/v1")
    skillsmp_api_key: str | None = Field(default=None)
    agentskillhub_api_url: str = Field(default="https://agentskillhub.dev/api/v1")
    aiskillstore_api_url: str = Field(default="https://skillstore.io/api")


class AnalyzerSettings(BaseSettings):
    """Analysis engine configuration settings."""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    static_analysis_timeout: int = Field(default=30)
    semgrep_path: str = Field(default="semgrep")
    max_file_size_mb: int = Field(default=10)

    llm_analysis_timeout: int = Field(default=60)
    llm_batch_size: int = Field(default=10)

    risk_threshold: float = Field(default=0.5)
    confidence_threshold: float = Field(default=0.6)
    override_threshold: float = Field(default=0.8)

    supported_languages: list[str] = Field(default=["en", "zh", "ja", "ko", "mixed"])


class APISettings(BaseSettings):
    """API configuration settings."""

    model_config = SettingsConfigDict(env_prefix="API_", extra="ignore")

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    workers: int = Field(default=4)
    api_key: str | None = Field(default=None)
    cors_origins: list[str] = Field(default=["*"])
    rate_limit: int = Field(default=100)
    rate_limit_window: int = Field(default=60)


class PerformanceSettings(BaseSettings):
    """Performance configuration settings."""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    max_concurrent_scans: int = Field(default=100)
    batch_size: int = Field(default=100)
    cache_ttl: int = Field(default=3600)
    memory_limit_mb: int = Field(default=4096)
    cpu_cores: int = Field(default=0)

    @field_validator("cpu_cores", mode="before")
    @classmethod
    def get_cpu_count(cls, v):
        if v == 0:
            return os.cpu_count() or 4
        return v


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""

    model_config = SettingsConfigDict(env_prefix="LOG_", extra="ignore")

    level: str = Field(default="INFO")
    file: str = Field(default="logs/skillscan.log")
    format: str = Field(default="json")
    max_size_mb: int = Field(default=100)
    backup_count: int = Field(default=10)


class Settings(BaseSettings):
    """Main application settings combining all configuration sections."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SkillScan"
    app_version: str = "1.1.0"
    debug: bool = Field(default=False)
    environment: str = Field(default="development")

    data_dir: Path = Field(default=Path("data"))
    logs_dir: Path = Field(default=Path("logs"))
    temp_dir: Path = Field(default=Path("tmp"))

    mongodb: MongoDBSettings = MongoDBSettings()
    redis: RedisSettings = RedisSettings()
    celery: CelerySettings = CelerySettings()
    llm: LLMSettings = LLMSettings()
    collector: CollectorSettings = CollectorSettings()
    analyzer: AnalyzerSettings = AnalyzerSettings()
    api: APISettings = APISettings()
    performance: PerformanceSettings = PerformanceSettings()
    logging: LoggingSettings = LoggingSettings()

    _yaml_config: dict[str, Any] = {}
    _config_loader: ConfigLoader | None = None

    @field_validator("data_dir", "logs_dir", "temp_dir", mode="before")
    @classmethod
    def create_directory(cls, v):
        """Ensure directories exist."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def yaml_config(self) -> dict[str, Any]:
        """Get YAML configuration."""
        if not self._yaml_config:
            self.load_yaml_config()
        return self._yaml_config

    @property
    def database_yaml(self) -> dict[str, Any]:
        """Get database YAML configuration."""
        return self.yaml_config.get("database", {})

    @property
    def llm_yaml(self) -> dict[str, Any]:
        """Get LLM YAML configuration."""
        return self.yaml_config.get("llm", {})

    def load_yaml_config(self, config_dir: str | Path | None = None) -> None:
        """
        Load configuration from YAML files.

        Args:
            config_dir: Optional configuration directory override.
        """
        if config_dir:
            self._config_loader = ConfigLoader(config_dir=config_dir)

        if self._config_loader is None:
            self._config_loader = ConfigLoader()

        self._yaml_config = self._config_loader.load_all()

        # Validate configuration
        is_valid, errors = validate_all(self._yaml_config)
        if not is_valid:
            logger.warning(
                f"Configuration validation warnings:\n{chr(10).join(str(e) for e in errors)}"
            )

        logger.info(f"Loaded YAML configuration from {self._config_loader.config_dir}")

    def reload_config(self) -> None:
        """Reload all configuration from disk."""
        if self._config_loader:
            self._config_loader.reload()
        self.load_yaml_config()

    def get_mongodb_config(self) -> dict[str, Any]:
        """
        Get MongoDB configuration merged from all sources.

        Priority: Environment variables > YAML config > Defaults
        """
        config = {
            "enabled": True,
            "uri": self.mongodb.uri,
            "database": self.mongodb.database,
            "username": self.mongodb.username,
            "password": self.mongodb.password,
            "max_pool_size": self.mongodb.max_pool_size,
            "min_pool_size": self.mongodb.min_pool_size,
        }

        # Merge with YAML config
        yaml_db = self.database_yaml.get("mongodb", {})
        for key, value in yaml_db.items():
            if key not in ("ssl",):
                if config.get(key) is None or config.get(key) == "":
                    config[key] = value

        # SSL config
        if "ssl" in yaml_db:
            config["ssl"] = yaml_db["ssl"]

        return config

    def get_redis_config(self) -> dict[str, Any]:
        """Get Redis configuration merged from all sources."""
        config = {
            "enabled": self.redis.url != "",
            "url": self.redis.url,
            "password": self.redis.password,
            "max_connections": self.redis.max_connections,
        }

        yaml_redis = self.database_yaml.get("redis", {})
        for key, value in yaml_redis.items():
            if config.get(key) is None or config.get(key) == "":
                config[key] = value

        return config

    def get_celery_config(self) -> dict[str, Any]:
        """Get Celery configuration merged from all sources."""
        config = {
            "enabled": False,
            "broker_url": self.celery.broker_url,
            "result_backend": self.celery.result_backend,
            "task_serializer": self.celery.task_serializer,
            "result_serializer": self.celery.result_serializer,
        }

        yaml_celery = self.database_yaml.get("celery", {})
        for key, value in yaml_celery.items():
            if key != "worker":
                if config.get(key) is None or config.get(key) == "":
                    config[key] = value

        if "worker" in yaml_celery:
            config["worker"] = yaml_celery["worker"]

        return config

    def get_llm_config(self) -> dict[str, Any]:
        """
        Get LLM configuration merged from all sources.

        Priority: Environment variables > YAML config > Defaults
        """
        config = {
            "enabled": True,
            "providers": {
                "openai": {
                    "enabled": bool(self.llm.openai_api_key),
                    "api_key": self.llm.openai_api_key,
                    "model": self.llm.openai_model,
                    "temperature": self.llm.temperature,
                    "max_tokens": self.llm.max_tokens,
                    "timeout": self.llm.timeout,
                },
                "anthropic": {
                    "enabled": bool(self.llm.anthropic_api_key),
                    "api_key": self.llm.anthropic_api_key,
                    "model": self.llm.anthropic_model,
                    "max_tokens": self.llm.max_tokens,
                    "timeout": self.llm.timeout,
                },
            },
            "default_provider": "openai",
        }

        # Merge with YAML config
        yaml_llm = self.llm_yaml
        if yaml_llm:
            if "llm_providers" in yaml_llm:
                for provider, provider_config in yaml_llm["llm_providers"].items():
                    if provider in config["providers"]:
                        for key, value in provider_config.items():
                            if config["providers"][provider].get(key) in (None, "") or key in (
                                "enabled",
                            ):
                                config["providers"][provider][key] = value
                    else:
                        config["providers"][provider] = provider_config

            if "default_provider" in yaml_llm:
                config["default_provider"] = yaml_llm["default_provider"]

            if "analysis" in yaml_llm:
                config["analysis"] = yaml_llm["analysis"]

            if "prompts" in yaml_llm:
                config["prompts"] = yaml_llm["prompts"]

            if "cost_control" in yaml_llm:
                config["cost_control"] = yaml_llm["cost_control"]

        return config


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def reload_settings() -> Settings:
    """Reload settings from configuration files."""
    global settings
    settings.reload_config()
    return settings
