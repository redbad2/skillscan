"""
配置管理模块

管理所有配置项，支持环境变量和配置文件。
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """应用配置"""

    # MongoDB配置
    mongodb_uri: str = Field(default="mongodb://localhost:27017", description="MongoDB连接URI")
    mongodb_database: str = Field(default="skillscan", description="MongoDB数据库名")
    mongodb_max_pool_size: int = Field(default=100, description="MongoDB连接池最大连接数")
    mongodb_min_pool_size: int = Field(default=10, description="MongoDB连接池最小连接数")

    # Redis配置
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis连接URL")
    redis_max_connections: int = Field(default=50, description="Redis最大连接数")

    # Celery配置
    celery_broker_url: str = Field(default="redis://localhost:6379/1", description="Celery Broker URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/2", description="Celery结果后端")

    # LLM配置
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API Key")
    openai_model: str = Field(default="gpt-4-turbo-preview", description="OpenAI模型")
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic API Key")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", description="Anthropic模型")

    # 扫描配置
    max_concurrent_scans: int = Field(default=100, description="最大并发扫描数")
    static_scan_timeout: int = Field(default=5, description="静态扫描超时(秒)")
    llm_scan_timeout: int = Field(default=25, description="LLM扫描超时(秒)")
    confidence_threshold: float = Field(default=0.7, description="静态分析置信度阈值")
    llm_confirm_threshold: float = Field(default=0.6, description="LLM分析确认阈值")
    override_threshold: float = Field(default=0.8, description="推翻静态发现阈值")

    # 爬取配置
    crawl_rate_limit: int = Field(default=10, description="爬取速率限制(请求/秒)")
    crawl_retry_count: int = Field(default=3, description="爬取重试次数")
    crawl_retry_delay: int = Field(default=5, description="爬取重试延迟(秒)")

    # API配置
    api_host: str = Field(default="0.0.0.0", description="API主机")
    api_port: int = Field(default=8000, description="API端口")
    api_key: Optional[str] = Field(default=None, description="API认证密钥")

    # 日志配置
    log_level: str = Field(default="INFO", description="日志级别")
    log_file: str = Field(default="logs/skillscan.log", description="日志文件路径")

    # 性能配置
    batch_size: int = Field(default=100, description="批处理大小")
    worker_count: int = Field(default=4, description="Worker数量")

    # 缓存配置
    enable_result_cache: bool = Field(default=True, description="启用结果缓存")
    cache_ttl: int = Field(default=3600, description="缓存TTL(秒)")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """获取单例配置"""
    return Settings()


# 漏洞分类常量
class VulnerabilityCategory:
    """漏洞分类"""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"

    ALL = [
        PROMPT_INJECTION,
        DATA_EXFILTRATION,
        PRIVILEGE_ESCALATION,
        SUPPLY_CHAIN,
    ]


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
    "zh": {
        "name": "中文",
        "encoding": ["utf-8", "gbk", "gb2312", "gb18030"],
    },
    "en": {
        "name": "English",
        "encoding": ["utf-8", "ascii", "latin-1"],
    },
    "ja": {
        "name": "日本語",
        "encoding": ["utf-8", "shift_jis", "euc-jp"],
    },
    "ko": {
        "name": "한국어",
        "encoding": ["utf-8", "euc-kr"],
    },
}
