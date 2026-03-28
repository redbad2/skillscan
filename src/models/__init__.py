"""
MongoDB数据模型模块

定义技能文件、漏洞和配置的数据模型。
"""

# Import from common module first (enums and base classes)
from src.models.common import (
    Language,
    RiskLevel,
    VulnerabilityCategory,
    VulnerabilityPattern,
    Severity,
    DetectionMethod,
    CollectionChannel,
    ScanStatus,
    ScanPriority,
    Platform,
    TimestampMixin,
    PyObjectId,
    BaseDocument,
)

# Import skill models
from src.models.skill import (
    SkillModel,
    SkillFile,
    ScriptFile,
    SkillMetadata,
    ScanResult,
    CollectionInfo,
)

# Import vulnerability models
from src.models.vulnerability import VulnerabilityModel, VulnerabilityEvidence

# Import configuration models
from src.models.configuration import ConfigurationModel, DetectionRule

# Import database models
from src.models.database import DatabaseManager, get_database

# Index definitions for MongoDB collections
SKILL_INDEXES = [
    {"fields": [("skill_id", 1)], "unique": True},
    {"fields": [("name", 1)]},
    {"fields": [("platform", 1)]},
    {"fields": [("language", 1)]},
    {"fields": [("scan_status", 1)]},
    {"fields": [("scan_result.risk_level", 1)]},
    {"fields": [("created_at", -1)]},
]

VULNERABILITY_INDEXES = [
    {"fields": [("vulnerability_id", 1)], "unique": True},
    {"fields": [("skill_id", 1)]},
    {"fields": [("category", 1)]},
    {"fields": [("pattern", 1)]},
    {"fields": [("severity", 1)]},
    {"fields": [("detected_at", -1)]},
]

CONFIG_INDEXES = [
    {"fields": [("config_type", 1)]},
    {"fields": [("language", 1)]},
    {"fields": [("version", 1)]},
    {"fields": [("updated_at", -1)]},
]

# Aliases for backward compatibility with repository.py
SkillDocument = SkillModel
VulnerabilityDocument = VulnerabilityModel
PlatformConfig = ConfigurationModel

__all__ = [
    # Enums from common
    "Language",
    "RiskLevel",
    "VulnerabilityCategory",
    "VulnerabilityPattern",
    "Severity",
    "DetectionMethod",
    "CollectionChannel",
    "ScanStatus",
    "ScanPriority",
    "Platform",
    "TimestampMixin",
    "PyObjectId",
    "BaseDocument",
    # Skill models
    "SkillModel",
    "SkillFile",
    "ScriptFile",
    "SkillMetadata",
    "ScanResult",
    "CollectionInfo",
    # Vulnerability models
    "VulnerabilityModel",
    "VulnerabilityEvidence",
    # Configuration models
    "ConfigurationModel",
    "DetectionRule",
    # Database
    "DatabaseManager",
    "get_database",
    # Indexes
    "SKILL_INDEXES",
    "VULNERABILITY_INDEXES",
    "CONFIG_INDEXES",
    # Aliases for backward compatibility
    "SkillDocument",
    "VulnerabilityDocument",
    "PlatformConfig",
]
