"""
Configuration models for detection rules and settings.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field, BaseModel

from .common import (
    BaseDocument, TimestampMixin, Language, 
    VulnerabilityCategory, VulnerabilityPattern, Severity
)


class DetectionRulePattern(BaseModel):
    """Pattern definition for a detection rule."""
    regex: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=lambda: ["all"])
    file_types: List[str] = Field(default_factory=lambda: [".py", ".sh", ".js", ".md"])
    case_sensitive: bool = False
    multiline: bool = False


class DetectionRule(BaseModel):
    """Detection rule model."""
    rule_id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(default="", description="Rule description")
    
    # Classification
    category: VulnerabilityCategory
    pattern: VulnerabilityPattern
    severity: Severity
    
    # Pattern matching
    patterns: List[DetectionRulePattern] = Field(default_factory=list)
    
    # Configuration
    enabled: bool = True
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    language: Language = Field(default=Language.ENGLISH)
    
    # Metadata
    version: str = Field(default="1.0.0")
    author: str = Field(default="skillscan")
    references: List[str] = Field(default_factory=list)
    
    # Detection settings
    requires_llm: bool = False
    llm_prompt: Optional[str] = None
    
    class Config:
        populate_by_name = True


class LanguageConfig(BaseModel):
    """Language-specific configuration."""
    language: Language
    name: str
    native_name: str
    
    # Language-specific patterns
    prompt_injection_keywords: List[str] = Field(default_factory=list)
    exfiltration_keywords: List[str] = Field(default_factory=list)
    privilege_keywords: List[str] = Field(default_factory=list)
    supply_chain_keywords: List[str] = Field(default_factory=list)
    
    # Common sensitive paths for this language
    sensitive_paths: List[str] = Field(default_factory=list)
    
    # Character sets and encoding
    char_encoding: str = "utf-8"
    common_encodings: List[str] = Field(default_factory=list)
    
    class Config:
        populate_by_name = True


class ThresholdConfig(BaseModel):
    """Threshold configuration for detection."""
    # Static analysis thresholds
    static_confidence_threshold: float = Field(default=0.7)
    
    # LLM analysis thresholds
    llm_confirm_threshold: float = Field(default=0.6)
    llm_override_threshold: float = Field(default=0.8)
    
    # Risk score thresholds
    risk_warning_threshold: float = Field(default=0.3)
    risk_dangerous_threshold: float = Field(default=0.6)
    risk_malicious_threshold: float = Field(default=0.8)
    
    # Performance thresholds
    max_scan_time_ms: int = Field(default=30000)
    max_file_size_bytes: int = Field(default=10 * 1024 * 1024)  # 10MB
    
    class Config:
        populate_by_name = True


class PlatformConfig(BaseDocument, TimestampMixin):
    """Platform configuration model for MongoDB storage."""
    
    config_type: str = Field(..., description="Configuration type")
    language: str = Field(default="all", description="Language scope")
    
    # Rules and settings
    rules: List[DetectionRule] = Field(default_factory=list)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    language_configs: List[LanguageConfig] = Field(default_factory=list)
    
    # Metadata
    version: str = Field(default="1.0.0")
    enabled: bool = True
    description: Optional[str] = None
    
    class Config:
        populate_by_name = True


# MongoDB index definitions
CONFIG_INDEXES = [
    [("config_type", 1)],
    [("language", 1)],
    [("version", 1)],
    [("enabled", 1)],
    [("updated_at", -1)],
]