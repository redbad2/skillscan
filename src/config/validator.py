"""
Configuration validator module for SkillScan.

Validates configuration values and provides helpful error messages.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for configuration errors."""

    pass


class ValidationError(ConfigurationError):
    """Validation error with field information."""

    def __init__(self, field: str, message: str, value: Any = None):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"[{field}] {message}")


class ConfigValidator:
    """Validates configuration values."""

    def __init__(self):
        self.errors: List[ValidationError] = []

    def add_error(self, field: str, message: str, value: Any = None) -> None:
        """Add a validation error."""
        error = ValidationError(field, message, value)
        self.errors.append(error)
        logger.error(f"Config validation error: {error}")

    def validate_database_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate database configuration.

        Args:
            config: Database configuration dictionary.

        Returns:
            True if valid, False otherwise.
        """
        self.errors.clear()
        is_valid = True

        mongodb = config.get("mongodb", {})
        redis = config.get("redis", {})
        celery = config.get("celery", {})

        if mongodb.get("enabled", True):
            if not mongodb.get("uri"):
                self.add_error("mongodb.uri", "MongoDB URI is required when MongoDB is enabled")
                is_valid = False

            pool_size = mongodb.get("max_pool_size", 100)
            if not isinstance(pool_size, int) or pool_size < 1:
                self.add_error(
                    "mongodb.max_pool_size", "max_pool_size must be a positive integer", pool_size
                )
                is_valid = False

            min_pool = mongodb.get("min_pool_size", 10)
            if not isinstance(min_pool, int) or min_pool < 0:
                self.add_error(
                    "mongodb.min_pool_size",
                    "min_pool_size must be a non-negative integer",
                    min_pool,
                )
                is_valid = False

            if min_pool > pool_size:
                self.add_error(
                    "mongodb.min_pool_size",
                    "min_pool_size cannot exceed max_pool_size",
                    f"{min_pool} > {pool_size}",
                )
                is_valid = False

            ssl = mongodb.get("ssl", {})
            if ssl.get("enabled"):
                if not ssl.get("ca_file"):
                    logger.warning("MongoDB SSL is enabled but no CA file specified")

        if redis.get("enabled", False):
            if not redis.get("url"):
                self.add_error("redis.url", "Redis URL is required when Redis is enabled")
                is_valid = False

        if celery.get("enabled", False):
            if not celery.get("broker_url"):
                self.add_error(
                    "celery.broker_url", "Celery broker URL is required when Celery is enabled"
                )
                is_valid = False
            if not celery.get("result_backend"):
                self.add_error(
                    "celery.result_backend",
                    "Celery result backend is required when Celery is enabled",
                )
                is_valid = False

        return is_valid

    def validate_llm_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate LLM configuration.

        Args:
            config: LLM configuration dictionary.

        Returns:
            True if valid, False otherwise.
        """
        self.errors.clear()
        is_valid = True

        providers = config.get("llm_providers", {})
        analysis = config.get("analysis", {})
        default_provider = config.get("default_provider", "openai")

        has_enabled_provider = False
        for provider_name, provider_config in providers.items():
            if not isinstance(provider_config, dict):
                continue

            if provider_config.get("enabled", False):
                has_enabled_provider = True

                if provider_name == "openai":
                    if not provider_config.get("api_key"):
                        logger.warning("OpenAI is enabled but no API key configured")
                elif provider_name == "anthropic":
                    if not provider_config.get("api_key"):
                        logger.warning("Anthropic is enabled but no API key configured")
                elif provider_name == "azure_openai":
                    if not provider_config.get("endpoint"):
                        self.add_error(
                            "llm_providers.azure_openai.endpoint",
                            "Azure OpenAI endpoint is required",
                        )
                        is_valid = False

        if analysis.get("enabled", True):
            if has_enabled_provider:
                threshold = analysis.get("static_confidence_threshold", 0.7)
                if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
                    self.add_error(
                        "analysis.static_confidence_threshold",
                        "Threshold must be between 0 and 1",
                        threshold,
                    )
                    is_valid = False

                llm_threshold = analysis.get("llm_confirm_threshold", 0.6)
                if not isinstance(llm_threshold, (int, float)) or not 0 <= llm_threshold <= 1:
                    self.add_error(
                        "analysis.llm_confirm_threshold",
                        "Threshold must be between 0 and 1",
                        llm_threshold,
                    )
                    is_valid = False

        if default_provider not in providers:
            self.add_error(
                "default_provider", f"Unknown provider '{default_provider}'", default_provider
            )
            is_valid = False

        cost_control = config.get("cost_control", {})
        monthly_budget = cost_control.get("monthly_budget", 100.0)
        if not isinstance(monthly_budget, (int, float)) or monthly_budget < 0:
            self.add_error(
                "cost_control.monthly_budget",
                "Budget must be a non-negative number",
                monthly_budget,
            )
            is_valid = False

        return is_valid

    def validate_all(self, config: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
        """
        Validate all configuration.

        Args:
            config: Full configuration dictionary.

        Returns:
            Tuple of (is_valid, list of errors).
        """
        self.errors.clear()
        all_valid = True

        if "database" in config:
            if not self.validate_database_config(config["database"]):
                all_valid = False

        if "llm" in config:
            if not self.validate_llm_config(config["llm"]):
                all_valid = False

        return all_valid, self.errors

    def get_summary(self) -> str:
        """Get a summary of validation errors."""
        if not self.errors:
            return "Configuration is valid."

        lines = ["Configuration validation errors:"]
        for error in self.errors:
            lines.append(f"  - [{error.field}] {error.message}")
            if error.value is not None:
                lines.append(f"    Current value: {error.value}")

        return "\n".join(lines)


_validator: Optional[ConfigValidator] = None


def get_validator() -> ConfigValidator:
    """Get the global validator instance."""
    global _validator
    if _validator is None:
        _validator = ConfigValidator()
    return _validator


def validate_database_config(config: Dict[str, Any]) -> bool:
    """Validate database configuration."""
    return get_validator().validate_database_config(config)


def validate_llm_config(config: Dict[str, Any]) -> bool:
    """Validate LLM configuration."""
    return get_validator().validate_llm_config(config)


def validate_all(config: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
    """Validate all configuration."""
    return get_validator().validate_all(config)
