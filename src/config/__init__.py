"""Configuration management module for SkillScan."""

# Import from settings submodule
from src.config.settings import (
    get_settings,
    reload_settings,
    Settings,
    # Sub-settings classes
    MongoDBSettings,
    RedisSettings,
    CelerySettings,
    LLMSettings,
    CollectorSettings,
    AnalyzerSettings,
    APISettings,
    PerformanceSettings,
    LoggingSettings,
)

# Import loader and validator
from src.config.loader import (
    ConfigLoader,
    get_config_loader,
    load_yaml_config,
    load_database_config,
    load_llm_config,
)

from src.config.validator import (
    ConfigValidator,
    ConfigurationError,
    ValidationError,
    get_validator,
    validate_database_config,
    validate_llm_config,
    validate_all,
)

from src.config.llm_config_manager import (
    LLMConfigManager,
    llm_config_manager,
)


# Copy constants from src/config.py to avoid circular imports
class VulnerabilityCategory:
    """漏洞分类"""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"
    ALL = [PROMPT_INJECTION, DATA_EXFILTRATION, PRIVILEGE_ESCALATION, SUPPLY_CHAIN]


class VulnerabilityPattern:
    """漏洞模式"""

    # Prompt Injection
    P1_INSTRUCTION_OVERRIDE = "P1"
    P2_HIDDEN_INSTRUCTIONS = "P2"
    P3_EXFILTRATION_COMMANDS = "P3"
    P4_BEHAVIOR_MANIPULATION = "P4"
    # Data Exfiltration
    E1_EXTERNAL_TRANSMISSION = "E1"
    E2_ENV_VAR_HARVESTING = "E2"
    E3_FILE_ENUMERATION = "E3"
    E4_CONTEXT_LEAKAGE = "E4"
    # Privilege Escalation
    PE1_EXCESSIVE_PERMISSIONS = "PE1"
    PE2_SUDO_ROOT_EXECUTION = "PE2"
    PE3_CREDENTIAL_ACCESS = "PE3"
    # Supply Chain
    SC1_UNPINNED_DEPENDENCIES = "SC1"
    SC2_EXTERNAL_SCRIPT_FETCHING = "SC2"
    SC3_OBFUSCATED_CODE = "SC3"


class Severity:
    """严重程度"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskLevel:
    """风险等级"""

    SAFE = "safe"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    MALICIOUS = "malicious"


class ScanStatus:
    """扫描状态"""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SourceChannel:
    """数据来源通道"""

    NETWORK_CRAWL = "network_crawl"
    LOCAL_SCAN = "local_scan"


class Platform:
    """技能平台"""

    CLAWHUB = "clawhub"
    SMITHERY = "smithery"
    SKILLSSH = "skillssh"
    LOCAL = "local"


# 多语言配置
LANGUAGE_CONFIG = {
    "zh": {"name": "中文", "encoding": ["utf-8", "gbk", "gb2312", "gb18030"]},
    "en": {"name": "English", "encoding": ["utf-8", "ascii", "latin-1"]},
    "ja": {"name": "日本語", "encoding": ["utf-8", "shift_jis", "euc-jp"]},
    "ko": {"name": "한국어", "encoding": ["utf-8", "euc-kr"]},
}

__all__ = [
    # Main settings
    "get_settings",
    "reload_settings",
    "Settings",
    # Sub-settings
    "MongoDBSettings",
    "RedisSettings",
    "CelerySettings",
    "LLMSettings",
    "CollectorSettings",
    "AnalyzerSettings",
    "APISettings",
    "PerformanceSettings",
    "LoggingSettings",
    # Loader
    "ConfigLoader",
    "get_config_loader",
    "load_yaml_config",
    "load_database_config",
    "load_llm_config",
    # Validator
    "ConfigValidator",
    "ConfigurationError",
    "ValidationError",
    "get_validator",
    "validate_database_config",
    "validate_llm_config",
    "validate_all",
    # LLM Config Manager
    "LLMConfigManager",
    "llm_config_manager",
    # Constants
    "VulnerabilityCategory",
    "VulnerabilityPattern",
    "Severity",
    "RiskLevel",
    "ScanStatus",
    "SourceChannel",
    "Platform",
    "LANGUAGE_CONFIG",
]
