"""
规则模块

提供威胁检测规则的管理功能。
"""

from .detection_rules import (
    COMPREHENSIVE_DETECTION_RULES,
    get_rules_by_pattern,
    get_rules_by_category,
    get_rules_by_language,
    get_all_pattern_codes,
    get_rules_count,
)

from .rule_config_manager import (
    RuleConfigManager,
    RuleVersion,
    RuleTemplate,
    RuleEffectiveness,
    LanguageType,
    RuleCategory,
    RuleSeverity,
    rule_config_manager,
)

__all__ = [
    "COMPREHENSIVE_DETECTION_RULES",
    "get_rules_by_pattern",
    "get_rules_by_category",
    "get_rules_by_language",
    "get_all_pattern_codes",
    "get_rules_count",
    "RuleConfigManager",
    "RuleVersion",
    "RuleTemplate",
    "RuleEffectiveness",
    "LanguageType",
    "RuleCategory",
    "RuleSeverity",
    "rule_config_manager",
]
