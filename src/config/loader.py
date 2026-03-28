"""
Configuration loader module for SkillScan.

Loads configuration from YAML files and merges with environment variables.
Environment variables take precedence over YAML configuration.
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union
from functools import lru_cache

import yaml

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Configuration loader that merges YAML files with environment variables."""

    DEFAULT_CONFIG_DIR = Path(__file__).parent.parent.parent / "config"

    def __init__(
        self,
        config_dir: Optional[Union[str, Path]] = None,
        load_yaml: bool = True,
        load_env: bool = True,
    ):
        """
        Initialize the configuration loader.

        Args:
            config_dir: Directory containing YAML configuration files.
            load_yaml: Whether to load YAML configuration files.
            load_env: Whether to apply environment variable overrides.
        """
        self.config_dir = Path(config_dir) if config_dir else self.DEFAULT_CONFIG_DIR
        self.load_yaml = load_yaml
        self.load_env = load_env
        self._cache: Dict[str, Any] = {}

    def load_yaml_file(self, filename: str) -> Dict[str, Any]:
        """
        Load a YAML configuration file.

        Args:
            filename: Name of the YAML file (e.g., 'database_config.yaml')

        Returns:
            Dictionary containing the parsed YAML configuration.
        """
        filepath = self.config_dir / filename
        if not filepath.exists():
            logger.warning(f"Configuration file not found: {filepath}")
            return {}

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                logger.debug(f"Loaded configuration from {filepath}")
                return config or {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {filepath}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error loading configuration file {filepath}: {e}")
            return {}

    def load_database_config(self) -> Dict[str, Any]:
        """Load database configuration from YAML."""
        return self.load_yaml_file("database_config.yaml")

    def load_llm_config(self) -> Dict[str, Any]:
        """Load LLM configuration from YAML."""
        return self.load_yaml_file("llm_config.yaml")

    def _get_env_override(self, config: Dict[str, Any], env_prefix: str = "") -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration.

        Environment variables follow the pattern: {PREFIX}_{SECTION}_{KEY}
        Example: SKILLSCAN_MONGODB_URI overrides mongodb.uri

        Args:
            config: Base configuration dictionary.
            env_prefix: Prefix for environment variables.

        Returns:
            Configuration with environment variable overrides applied.
        """
        if not self.load_env:
            return config

        result = config.copy()

        for section, section_config in config.items():
            if not isinstance(section_config, dict):
                continue

            section_upper = section.upper()
            for key, value in section_config.items():
                key_upper = key.upper()

                env_var = f"{env_prefix}{section_upper}_{key_upper}"
                env_value = os.environ.get(env_var)

                if env_value is not None:
                    result[section][key] = self._convert_env_value(env_value)

        return result

    def _convert_env_value(self, value: str) -> Any:
        """
        Convert environment variable string to appropriate type.

        Args:
            value: String value from environment variable.

        Returns:
            Converted value with appropriate type.
        """
        value_lower = value.lower()

        if value_lower in ("true", "yes", "1"):
            return True
        if value_lower in ("false", "no", "0"):
            return False
        if value_lower == "none" or value_lower == "null":
            return None

        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all configuration files.

        Returns:
            Dictionary containing all configuration sections.
        """
        return {
            "database": self.load_database_config(),
            "llm": self.load_llm_config(),
        }

    def get_config(self, section: str) -> Dict[str, Any]:
        """
        Get configuration for a specific section.

        Args:
            section: Configuration section name ('database' or 'llm').

        Returns:
            Configuration dictionary for the section.
        """
        if section in self._cache:
            return self._cache[section]

        if section == "database":
            config = self.load_database_config()
        elif section == "llm":
            config = self.load_llm_config()
        else:
            logger.warning(f"Unknown configuration section: {section}")
            return {}

        self._cache[section] = config
        return config

    def reload(self, section: Optional[str] = None) -> None:
        """
        Reload configuration from disk.

        Args:
            section: Specific section to reload, or None for all.
        """
        if section:
            self._cache.pop(section, None)
        else:
            self._cache.clear()

        if section == "database" or section is None:
            self.load_database_config()
        if section == "llm" or section is None:
            self.load_llm_config()


_loader: Optional[ConfigLoader] = None


def get_config_loader() -> ConfigLoader:
    """
    Get the global configuration loader instance.

    Returns:
        ConfigLoader instance.
    """
    global _loader
    if _loader is None:
        _loader = ConfigLoader()
    return _loader


def load_yaml_config(filename: str) -> Dict[str, Any]:
    """
    Convenience function to load a YAML configuration file.

    Args:
        filename: Name of the YAML configuration file.

    Returns:
        Parsed configuration dictionary.
    """
    return get_config_loader().load_yaml_file(filename)


def load_database_config() -> Dict[str, Any]:
    """Load database configuration from YAML."""
    return get_config_loader().load_database_config()


def load_llm_config() -> Dict[str, Any]:
    """Load LLM configuration from YAML."""
    return get_config_loader().load_llm_config()
