"""
Common enums and base models for SkillScan.
"""

from enum import Enum
from typing import Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class Language(str, Enum):
    """Supported languages for skill files."""

    ENGLISH = "en"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk levels for scanned skills."""

    SAFE = "safe"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    MALICIOUS = "malicious"


class VulnerabilityCategory(str, Enum):
    """Categories of vulnerabilities (from paper taxonomy)."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"


class VulnerabilityPattern(str, Enum):
    """Specific vulnerability patterns (14 patterns from paper)."""

    # Prompt Injection patterns
    P1_INSTRUCTION_OVERRIDE = "P1"
    P2_HIDDEN_INSTRUCTIONS = "P2"
    P3_EXFILTRATION_COMMANDS = "P3"
    P4_BEHAVIOR_MANIPULATION = "P4"

    # Data Exfiltration patterns
    E1_EXTERNAL_DATA_TRANSMISSION = "E1"
    E2_ENVIRONMENT_VARIABLE_HARVESTING = "E2"
    E3_FILE_SYSTEM_ENUMERATION = "E3"
    E4_CONTEXT_LEAKAGE = "E4"

    # Privilege Escalation patterns
    PE1_EXCESSIVE_PERMISSIONS = "PE1"
    PE2_SUDO_ROOT_EXECUTION = "PE2"
    PE3_CREDENTIAL_ACCESS = "PE3"

    # Supply Chain patterns
    SC1_UNPINNED_DEPENDENCIES = "SC1"
    SC2_EXTERNAL_SCRIPT_FETCHING = "SC2"
    SC3_OBFUSCATED_CODE = "SC3"


class Severity(str, Enum):
    """Severity levels for vulnerabilities."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DetectionMethod(str, Enum):
    """Method used to detect vulnerability."""

    STATIC = "static"
    LLM = "llm"
    HYBRID = "hybrid"


class CollectionChannel(str, Enum):
    """Data collection channel type."""

    NETWORK_CRAWL = "network_crawl"
    LOCAL_SCAN = "local_scan"


class ScanStatus(str, Enum):
    """Status of scan tasks."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPriority(int, Enum):
    """Priority levels for scan tasks."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class Platform(str, Enum):
    """Supported skill platforms."""

    CLAWHUB = "clawhub"
    SMITHERY = "smithery"
    SKILLSSH = "skillssh"
    LOCAL = "local"
    UNKNOWN = "unknown"


class TimestampMixin(BaseModel):
    """Mixin for adding timestamps to documents."""

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.utcnow()


class PyObjectId(str):
    """Custom type for MongoDB ObjectId."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, field):
        if not isinstance(v, str):
            raise TypeError("ObjectId must be a string")
        return v


class BaseDocument(BaseModel):
    """Base class for MongoDB documents."""

    id: Optional[PyObjectId] = Field(default=None, alias="_id")

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={datetime: lambda v: v.isoformat()},
    )
