"""
配置数据模型

定义检测规则和配置的MongoDB文档结构。
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId

from src.models.skill import PyObjectId


class ConfigType(str, Enum):
    """配置类型枚举"""

    DETECTION_RULES = "detection_rules"
    THRESHOLDS = "thresholds"
    LANGUAGE_RULES = "language_rules"
    PLATFORM_CONFIG = "platform_config"


class DetectionRule(BaseModel):
    """检测规则模型"""

    rule_id: str
    pattern: str  # 正则表达式或匹配模式
    category: str  # 漏洞分类
    pattern_code: str  # 具体模式代码 (P1, E2, etc.)
    severity: str
    enabled: bool = True
    description_zh: Optional[str] = None
    description_en: Optional[str] = None
    language: str = "all"  # 规则适用的语言
    tags: List[str] = Field(default_factory=list)
    confidence_boost: float = 1.0  # 置信度提升因子
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ThresholdConfig(BaseModel):
    """阈值配置模型"""

    name: str
    value: float
    description: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None


class LanguageRulesConfig(BaseModel):
    """语言规则配置模型"""

    language: str
    keywords: List[str] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)
    encoding_detection: bool = True
    description: Optional[str] = None


class ConfigurationModel(BaseModel):
    """配置完整模型"""

    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    config_type: ConfigType
    language: str = "all"  # "zh", "en", "ja", "ko", "all"
    rules: List[DetectionRule] = Field(default_factory=list)
    thresholds: List[ThresholdConfig] = Field(default_factory=list)
    language_rules: Optional[LanguageRulesConfig] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    updated_by: str = "system"
    version: int = 1
    description: Optional[str] = None
    enabled: bool = True

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
    )


class ConfigurationModelDB:
    """配置模型数据库操作"""

    COLLECTION_NAME = "configurations"

    def __init__(self, db_manager):
        self.db_manager = db_manager

    async def create_or_update(self, config: ConfigurationModel) -> str:
        """创建或更新配置"""
        existing = await self.db_manager.find_one(
            self.COLLECTION_NAME,
            {"config_type": config.config_type.value, "language": config.language},
        )

        config_dict = config.model_dump(by_alias=True, exclude={"id"})
        config_dict["updated_at"] = datetime.utcnow()

        if existing:
            config_dict["version"] = existing.get("version", 0) + 1
            await self.db_manager.update_one(
                self.COLLECTION_NAME,
                {"_id": existing["_id"]},
                config_dict,
            )
            return str(existing["_id"])
        else:
            return await self.db_manager.insert_one(self.COLLECTION_NAME, config_dict)

    async def get_config(self, config_type: str, language: str = "all") -> Optional[Dict[str, Any]]:
        """获取配置"""
        return await self.db_manager.find_one(
            self.COLLECTION_NAME,
            {"config_type": config_type, "language": language},
        )

    async def get_detection_rules(
        self, language: Optional[str] = None, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """获取检测规则"""
        filter_dict: Dict[str, Any] = {"config_type": ConfigType.DETECTION_RULES.value}
        if language:
            filter_dict["$or"] = [{"language": language}, {"language": "all"}]

        config = await self.db_manager.find_one(self.COLLECTION_NAME, filter_dict)
        if not config:
            return []

        rules = config.get("rules", [])
        if category:
            rules = [r for r in rules if r.get("category") == category]

        return [r for r in rules if r.get("enabled", True)]

    async def get_threshold(self, name: str) -> Optional[float]:
        """获取阈值配置"""
        config = await self.db_manager.find_one(
            self.COLLECTION_NAME, {"config_type": ConfigType.THRESHOLDS.value}
        )
        if not config:
            return None

        for threshold in config.get("thresholds", []):
            if threshold.get("name") == name:
                return threshold.get("value")
        return None

    async def list_all_configs(self) -> List[Dict[str, Any]]:
        """列出所有配置"""
        return await self.db_manager.find_many(
            self.COLLECTION_NAME,
            {},
            sort=[("config_type", 1), ("language", 1)],
        )


# 默认检测规则配置
DEFAULT_DETECTION_RULES: List[Dict[str, Any]] = [
    # Prompt Injection Rules
    {
        "rule_id": "P1-001",
        "pattern": r"(?i)(ignore|disregard|override|bypass)\s+(previous|prior|all|system|safety)\s+(instructions?|prompts?|rules?|constraints?|checks?)",
        "category": "prompt_injection",
        "pattern_code": "P1",
        "severity": "high",
        "description_zh": "检测到指令覆盖模式",
        "description_en": "Detected instruction override pattern",
        "language": "en",
        "tags": ["instruction_override", "safety_bypass"],
    },
    {
        "rule_id": "P1-002-zh",
        "pattern": r"(?i)(忽略|无视|跳过|绕过|覆盖)\s*(之前的|先前的|所有的|系统|安全|防护)\s*(指令|提示|规则|约束|检查|限制)",
        "category": "prompt_injection",
        "pattern_code": "P1",
        "severity": "high",
        "description_zh": "检测到中文指令覆盖模式",
        "description_en": "Detected Chinese instruction override pattern",
        "language": "zh",
        "tags": ["instruction_override", "chinese"],
    },
    {
        "rule_id": "P2-001",
        "pattern": r"<!--[\s\S]*?(ignore|disregard|override|secret|hidden)[\s\S]*?-->",
        "category": "prompt_injection",
        "pattern_code": "P2",
        "severity": "high",
        "description_zh": "检测到HTML注释中的隐藏指令",
        "description_en": "Detected hidden instructions in HTML comments",
        "language": "all",
        "tags": ["hidden_instructions", "html_comment"],
    },
    {
        "rule_id": "P3-001",
        "pattern": r"(?i)(send|upload|transmit|share|forward)\s+(context|data|information|conversation|history|logs?)\s+to\s+",
        "category": "prompt_injection",
        "pattern_code": "P3",
        "severity": "high",
        "description_zh": "检测到数据外传命令",
        "description_en": "Detected exfiltration commands",
        "language": "en",
        "tags": ["data_exfiltration", "context_sharing"],
    },
    {
        "rule_id": "P3-002-zh",
        "pattern": r"(发送|上传|传输|分享|转发)\s*(上下文|数据|信息|对话|历史|日志)\s*(到|至|给)",
        "category": "prompt_injection",
        "pattern_code": "P3",
        "severity": "high",
        "description_zh": "检测到中文数据外传命令",
        "description_en": "Detected Chinese exfiltration commands",
        "language": "zh",
        "tags": ["data_exfiltration", "chinese"],
    },
    {
        "rule_id": "P4-001",
        "pattern": r"(?i)(don'?t|do\s+not|never)\s+(tell|inform|notify|alert|warn)\s+(the\s+)?user",
        "category": "prompt_injection",
        "pattern_code": "P4",
        "severity": "medium",
        "description_zh": "检测到用户隐瞒行为",
        "description_en": "Detected user concealment behavior",
        "language": "en",
        "tags": ["behavior_manipulation", "concealment"],
    },
    {
        "rule_id": "P4-002-zh",
        "pattern": r"(不要|别|不许|禁止)\s*(告诉|通知|告知|提醒|警告)\s*(用户|使用者|人)",
        "category": "prompt_injection",
        "pattern_code": "P4",
        "severity": "medium",
        "description_zh": "检测到中文用户隐瞒行为",
        "description_en": "Detected Chinese user concealment behavior",
        "language": "zh",
        "tags": ["behavior_manipulation", "chinese"],
    },
    # Data Exfiltration Rules
    {
        "rule_id": "E1-001",
        "pattern": r"(?i)(requests?\.(post|put|patch|get))\s*\(\s*['\"]https?://[^'\"]+['\"]",
        "category": "data_exfiltration",
        "pattern_code": "E1",
        "severity": "high",
        "description_zh": "检测到向外部URL发送数据",
        "description_en": "Detected data transmission to external URL",
        "language": "en",
        "tags": ["http_request", "python"],
    },
    {
        "rule_id": "E1-002",
        "pattern": r"(?i)(curl|wget)\s+.*['\"]https?://[^'\"]+['\"]",
        "category": "data_exfiltration",
        "pattern_code": "E1",
        "severity": "high",
        "description_zh": "检测到curl/wget外部请求",
        "description_en": "Detected curl/wget external request",
        "language": "en",
        "tags": ["http_request", "shell"],
    },
    {
        "rule_id": "E1-003-zh",
        "pattern": r"(发送|传输|上传)\s*(到|至)\s*(http|https|ftp)://",
        "category": "data_exfiltration",
        "pattern_code": "E1",
        "severity": "high",
        "description_zh": "检测到中文描述的外部数据传输",
        "description_en": "Detected Chinese-described external data transmission",
        "language": "zh",
        "tags": ["data_exfiltration", "chinese"],
    },
    {
        "rule_id": "E2-001",
        "pattern": r"(?i)(os\.environ|os\.getenv|process\.env)\s*[\.\[\(]\s*['\"]?(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)",
        "category": "data_exfiltration",
        "pattern_code": "E2",
        "severity": "high",
        "description_zh": "检测到读取敏感环境变量",
        "description_en": "Detected reading of sensitive environment variables",
        "language": "en",
        "tags": ["environment_variable", "sensitive_data"],
    },
    {
        "rule_id": "E2-002",
        "pattern": r"(?i)\$\{?(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)\b",
        "category": "data_exfiltration",
        "pattern_code": "E2",
        "severity": "high",
        "description_zh": "检测到Shell中读取敏感环境变量",
        "description_en": "Detected sensitive environment variable access in shell",
        "language": "en",
        "tags": ["environment_variable", "shell"],
    },
    {
        "rule_id": "E2-003-zh",
        "pattern": r"(读取|获取|访问)\s*(环境变量|密钥|令牌|密码|凭证)",
        "category": "data_exfiltration",
        "pattern_code": "E2",
        "severity": "high",
        "description_zh": "检测到中文描述的环境变量读取",
        "description_en": "Detected Chinese-described environment variable reading",
        "language": "zh",
        "tags": ["environment_variable", "chinese"],
    },
    {
        "rule_id": "E3-001",
        "pattern": r"(?i)(\.ssh|\.aws|\.git/credentials|\.env|credentials|secrets?/)",
        "category": "data_exfiltration",
        "pattern_code": "E3",
        "severity": "high",
        "description_zh": "检测到扫描敏感文件路径",
        "description_en": "Detected scanning of sensitive file paths",
        "language": "en",
        "tags": ["file_enumeration", "sensitive_paths"],
    },
    {
        "rule_id": "E3-002",
        "pattern": r"(?i)(open|read|load)\s*\(\s*['\"]?\~?\/\.\w+",
        "category": "data_exfiltration",
        "pattern_code": "E3",
        "severity": "medium",
        "description_zh": "检测到读取隐藏目录文件",
        "description_en": "Detected reading files from hidden directories",
        "language": "en",
        "tags": ["file_access", "hidden_dirs"],
    },
    {
        "rule_id": "E4-001",
        "pattern": r"(?i)(log|record|save|store|transmit)\s+(conversation|chat|dialog|context|history)",
        "category": "data_exfiltration",
        "pattern_code": "E4",
        "severity": "medium",
        "description_zh": "检测到记录对话上下文",
        "description_en": "Detected conversation context logging",
        "language": "en",
        "tags": ["context_leakage", "logging"],
    },
    # Privilege Escalation Rules
    {
        "rule_id": "PE2-001",
        "pattern": r"(?i)\bsudo\b",
        "category": "privilege_escalation",
        "pattern_code": "PE2",
        "severity": "high",
        "description_zh": "检测到sudo权限提升",
        "description_en": "Detected sudo privilege escalation",
        "language": "en",
        "tags": ["sudo", "privilege_escalation"],
    },
    {
        "rule_id": "PE2-002",
        "pattern": r"(?i)(runas|run\s+as\s+administrator)",
        "category": "privilege_escalation",
        "pattern_code": "PE2",
        "severity": "high",
        "description_zh": "检测到管理员权限执行",
        "description_en": "Detected administrator privilege execution",
        "language": "en",
        "tags": ["admin", "windows"],
    },
    {
        "rule_id": "PE2-003-zh",
        "pattern": r"(提升|获取|请求)\s*(权限|管理员|root|sudo)",
        "category": "privilege_escalation",
        "pattern_code": "PE2",
        "severity": "high",
        "description_zh": "检测到中文描述的权限提升",
        "description_en": "Detected Chinese-described privilege escalation",
        "language": "zh",
        "tags": ["privilege_escalation", "chinese"],
    },
    {
        "rule_id": "PE3-001",
        "pattern": r"(?i)(keychain|keyring|credential\s*manager|vault)\.?(get|read|access|fetch)",
        "category": "privilege_escalation",
        "pattern_code": "PE3",
        "severity": "high",
        "description_zh": "检测到访问密钥存储",
        "description_en": "Detected credential store access",
        "language": "en",
        "tags": ["credential_access", "keychain"],
    },
    {
        "rule_id": "PE3-002-zh",
        "pattern": r"(读取|获取|访问)\s*(密码|密钥|令牌|凭证)",
        "category": "privilege_escalation",
        "pattern_code": "PE3",
        "severity": "high",
        "description_zh": "检测到中文描述的凭据访问",
        "description_en": "Detected Chinese-described credential access",
        "language": "zh",
        "tags": ["credential_access", "chinese"],
    },
    # Supply Chain Rules
    {
        "rule_id": "SC1-001",
        "pattern": r"(?i)(pip|npm|yarn|cargo)\s+install\s+[a-zA-Z0-9_-]+(?!\s*[@=~<>])",
        "category": "supply_chain",
        "pattern_code": "SC1",
        "severity": "medium",
        "description_zh": "检测到未固定版本的依赖安装",
        "description_en": "Detected unpinned dependency installation",
        "language": "en",
        "tags": ["dependency", "unpinned"],
    },
    {
        "rule_id": "SC1-002-zh",
        "pattern": r"(安装|下载)\s*(依赖|包|库)",
        "category": "supply_chain",
        "pattern_code": "SC1",
        "severity": "low",
        "description_zh": "检测到中文描述的依赖安装",
        "description_en": "Detected Chinese-described dependency installation",
        "language": "zh",
        "tags": ["dependency", "chinese"],
    },
    {
        "rule_id": "SC2-001",
        "pattern": r"(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|node)",
        "category": "supply_chain",
        "pattern_code": "SC2",
        "severity": "high",
        "description_zh": "检测到下载并执行远程脚本",
        "description_en": "Detected downloading and executing remote script",
        "language": "en",
        "tags": ["remote_script", "pipe_exec"],
    },
    {
        "rule_id": "SC2-002",
        "pattern": r"(?i)(bash|sh|zsh)\s*<\s*<\s*\(\s*(curl|wget)",
        "category": "supply_chain",
        "pattern_code": "SC2",
        "severity": "high",
        "description_zh": "检测到进程替换执行远程脚本",
        "description_en": "Detected process substitution executing remote script",
        "language": "en",
        "tags": ["remote_script", "process_substitution"],
    },
    {
        "rule_id": "SC2-003-zh",
        "pattern": r"(下载|获取)\s*(脚本|代码)\s*(然后|后)?\s*(执行|运行)",
        "category": "supply_chain",
        "pattern_code": "SC2",
        "severity": "high",
        "description_zh": "检测到中文描述的远程脚本执行",
        "description_en": "Detected Chinese-described remote script execution",
        "language": "zh",
        "tags": ["remote_script", "chinese"],
    },
    {
        "rule_id": "SC3-001",
        "pattern": r"(?i)(base64_decode|atob|eval)\s*\(\s*['\"][A-Za-z0-9+/]{50,}={0,2}['\"]",
        "category": "supply_chain",
        "pattern_code": "SC3",
        "severity": "high",
        "description_zh": "检测到Base64编码执行",
        "description_en": "Detected Base64 encoded execution",
        "language": "en",
        "tags": ["obfuscation", "base64", "eval"],
    },
    {
        "rule_id": "SC3-002",
        "pattern": r"(?i)eval\s*\(\s*.*\.(replace|split|join|map)",
        "category": "supply_chain",
        "pattern_code": "SC3",
        "severity": "medium",
        "description_zh": "检测到动态代码生成",
        "description_en": "Detected dynamic code generation",
        "language": "en",
        "tags": ["obfuscation", "dynamic_code"],
    },
    {
        "rule_id": "SC3-003-zh",
        "pattern": r"(混淆|编码|加密)\s*(代码|脚本|逻辑)",
        "category": "supply_chain",
        "pattern_code": "SC3",
        "severity": "medium",
        "description_zh": "检测到中文描述的代码混淆",
        "description_en": "Detected Chinese-described code obfuscation",
        "language": "zh",
        "tags": ["obfuscation", "chinese"],
    },
]
