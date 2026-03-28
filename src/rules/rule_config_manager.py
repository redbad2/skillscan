"""
规则配置管理器

提供多语言规则配置管理和版本管理功能，支持规则的增删改查、版本回滚、
模板管理和效果统计。
"""

import copy
import hashlib
import json
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
import threading


class LanguageType(str, Enum):
    """支持的语言类型"""

    ENGLISH = "en"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"
    MIXED = "mixed"
    ALL = "all"


class RuleCategory(str, Enum):
    """漏洞分类"""

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUPPLY_CHAIN = "supply_chain"


class RuleSeverity(str, Enum):
    """漏洞严重程度"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleVersion:
    """规则版本记录"""

    def __init__(
        self,
        version_id: str,
        rules: List[Dict[str, Any]],
        created_at: datetime,
        created_by: str = "system",
        comment: str = "",
    ):
        self.version_id = version_id
        self.rules = copy.deepcopy(rules)
        self.created_at = created_at
        self.created_by = created_by
        self.comment = comment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "rules": self.rules,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "comment": self.comment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleVersion":
        return cls(
            version_id=data["version_id"],
            rules=data["rules"],
            created_at=datetime.fromisoformat(data["created_at"]),
            created_by=data.get("created_by", "system"),
            comment=data.get("comment", ""),
        )


class RuleTemplate:
    """规则模板"""

    def __init__(
        self,
        template_id: str,
        name: str,
        description: str,
        language: str,
        rules: List[Dict[str, Any]],
        category: str = "",
        is_builtin: bool = False,
    ):
        self.template_id = template_id
        self.name = name
        self.description = description
        self.language = language
        self.rules = rules
        self.category = category
        self.is_builtin = is_builtin

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "language": self.language,
            "rules": self.rules,
            "category": self.category,
            "is_builtin": self.is_builtin,
        }


class RuleEffectiveness:
    """规则效果统计"""

    def __init__(
        self,
        rule_id: str,
        total_matches: int = 0,
        true_positives: int = 0,
        false_positives: int = 0,
        last_used: Optional[datetime] = None,
        last_updated: Optional[datetime] = None,
    ):
        self.rule_id = rule_id
        self.total_matches = total_matches
        self.true_positives = true_positives
        self.false_positives = false_positives
        self.last_used = last_updated or datetime.now()
        self.last_updated = last_updated or datetime.now()

    @property
    def precision(self) -> float:
        """精确率"""
        total = self.true_positives + self.false_positives
        if total == 0:
            return 0.0
        return self.true_positives / total

    @property
    def recall_contribution(self) -> float:
        """召回贡献"""
        return self.true_positives / max(self.total_matches, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "total_matches": self.total_matches,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "precision": round(self.precision, 4),
            "recall_contribution": round(self.recall_contribution, 4),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }

    def record_match(self):
        """记录一次匹配"""
        self.total_matches += 1
        self.last_used = datetime.now()

    def record_true_positive(self):
        """记录真阳性"""
        self.total_matches += 1
        self.true_positives += 1
        self.last_used = datetime.now()
        self.last_updated = datetime.now()

    def record_false_positive(self):
        """记录假阳性"""
        self.total_matches += 1
        self.false_positives += 1
        self.last_used = datetime.now()
        self.last_updated = datetime.now()


class RuleConfigManager:
    """
    规则配置管理器

    提供以下功能：
    - 多语言规则分组管理
    - 规则版本控制和支持回滚
    - 规则模板管理
    - 规则效果统计
    - 规则验证和测试
    """

    _instance: Optional["RuleConfigManager"] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self._rules: List[Dict[str, Any]] = []
        self._rule_index: Dict[str, Dict[str, Any]] = {}
        self._versions: List[RuleVersion] = []
        self._templates: List[RuleTemplate] = []
        self._effectiveness: Dict[str, RuleEffectiveness] = {}
        self._language_thresholds: Dict[str, float] = {
            LanguageType.ENGLISH: 0.7,
            LanguageType.CHINESE: 0.65,
            LanguageType.JAPANESE: 0.65,
            LanguageType.KOREAN: 0.65,
            LanguageType.MIXED: 0.6,
            LanguageType.ALL: 0.7,
        }
        self._enabled_rules: Dict[str, bool] = {}
        self._version_counter = 0

        self._init_builtin_templates()

    def _init_builtin_templates(self):
        """初始化内置模板"""
        self._templates = [
            RuleTemplate(
                template_id="template_balanced",
                name="平衡检测模板",
                description="平衡精确率和召回率的通用检测模板",
                language="all",
                rules=[],
                category="general",
                is_builtin=True,
            ),
            RuleTemplate(
                template_id="template_high_precision",
                name="高精度模板",
                description="高精确率模板，减少误报但可能增加漏报",
                language="all",
                rules=[],
                category="precision",
                is_builtin=True,
            ),
            RuleTemplate(
                template_id="template_chinese_only",
                name="中文专用模板",
                description="针对中文技能文件的检测模板",
                language="zh",
                rules=[],
                category="language_specific",
                is_builtin=True,
            ),
            RuleTemplate(
                template_id="template_high_recall",
                name="高召回模板",
                description="高召回率模板，减少漏报但可能增加误报",
                language="all",
                rules=[],
                category="recall",
                is_builtin=True,
            ),
        ]

    def _generate_version_id(self) -> str:
        """生成版本ID"""
        self._version_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"v{timestamp}_{self._version_counter:04d}"

    def _generate_rule_id(self, pattern_code: str, language: str) -> str:
        """生成规则ID"""
        existing = [r for r in self._rules if r["rule_id"].startswith(f"{pattern_code}-")]
        suffix = len(existing) + 1
        return f"{pattern_code}-{suffix:03d}-{language}"

    def _rebuild_index(self):
        """重建规则索引"""
        self._rule_index = {r["rule_id"]: r for r in self._rules}
        self._enabled_rules = {r["rule_id"]: r.get("enabled", True) for r in self._rules}

    def load_rules(
        self, rules: List[Dict[str, Any]], created_by: str = "system", comment: str = ""
    ):
        """
        加载规则集

        Args:
            rules: 规则列表
            created_by: 创建者
            comment: 备注
        """
        self._rules = copy.deepcopy(rules)
        self._rebuild_index()

        version = RuleVersion(
            version_id=self._generate_version_id(),
            rules=self._rules,
            created_at=datetime.now(),
            created_by=created_by,
            comment=comment,
        )
        self._versions.append(version)

        for rule in self._rules:
            rule_id = rule["rule_id"]
            if rule_id not in self._effectiveness:
                self._effectiveness[rule_id] = RuleEffectiveness(rule_id=rule_id)

    def add_rule(
        self, rule: Dict[str, Any], created_by: str = "system", auto_generate_id: bool = True
    ) -> Dict[str, Any]:
        """
        添加规则

        Args:
            rule: 规则配置
            created_by: 创建者
            auto_generate_id: 是否自动生成ID

        Returns:
            添加的规则
        """
        rule = copy.deepcopy(rule)
        if auto_generate_id and "rule_id" not in rule:
            pattern_code = rule.get("pattern_code", "CUSTOM")
            language = rule.get("language", "all")
            rule["rule_id"] = self._generate_rule_id(pattern_code, language)

        rule["enabled"] = rule.get("enabled", True)
        rule["created_at"] = datetime.now().isoformat()
        rule["updated_at"] = datetime.now().isoformat()

        self._rules.append(rule)
        self._rule_index[rule["rule_id"]] = rule
        self._enabled_rules[rule["rule_id"]] = rule["enabled"]
        self._effectiveness[rule["rule_id"]] = RuleEffectiveness(rule_id=rule["rule_id"])

        return rule

    def update_rule(
        self, rule_id: str, updates: Dict[str, Any], updated_by: str = "system"
    ) -> Optional[Dict[str, Any]]:
        """
        更新规则

        Args:
            rule_id: 规则ID
            updates: 更新内容
            updated_by: 更新者

        Returns:
            更新后的规则，失败返回None
        """
        if rule_id not in self._rule_index:
            return None

        rule = self._rule_index[rule_id]
        for key, value in updates.items():
            if key not in ["rule_id", "created_at"]:
                rule[key] = value

        rule["updated_at"] = datetime.now().isoformat()
        self._enabled_rules[rule_id] = rule.get("enabled", True)

        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """
        删除规则

        Args:
            rule_id: 规则ID

        Returns:
            是否成功
        """
        if rule_id not in self._rule_index:
            return False

        self._rules = [r for r in self._rules if r["rule_id"] != rule_id]
        del self._rule_index[rule_id]
        del self._enabled_rules[rule_id]
        return True

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """获取规则"""
        return self._rule_index.get(rule_id)

    def get_all_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """
        获取所有规则

        Args:
            enabled_only: 只返回启用的规则

        Returns:
            规则列表
        """
        if enabled_only:
            return [r for r in self._rules if r.get("enabled", True)]
        return copy.deepcopy(self._rules)

    def get_rules_by_language(self, language: str) -> List[Dict[str, Any]]:
        """
        按语言获取规则

        Args:
            language: 语言代码

        Returns:
            规则列表
        """
        return [
            r for r in self._rules if r.get("language") == language or r.get("language") == "all"
        ]

    def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按分类获取规则"""
        return [r for r in self._rules if r.get("category") == category]

    def get_rules_by_pattern(self, pattern_code: str) -> List[Dict[str, Any]]:
        """按模式代码获取规则"""
        return [r for r in self._rules if r.get("pattern_code") == pattern_code]

    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """启用/禁用规则"""
        if rule_id not in self._rule_index:
            return False
        self._rule_index[rule_id]["enabled"] = enabled
        self._enabled_rules[rule_id] = enabled
        return True

    def set_language_threshold(self, language: str, threshold: float) -> bool:
        """
        设置语言特定的检测阈值

        Args:
            language: 语言代码
            threshold: 阈值 (0.0-1.0)

        Returns:
            是否成功
        """
        if not 0.0 <= threshold <= 1.0:
            return False
        self._language_thresholds[language] = threshold
        return True

    def get_language_threshold(self, language: str) -> float:
        """获取语言特定阈值"""
        return self._language_thresholds.get(language, 0.7)

    def get_all_thresholds(self) -> Dict[str, float]:
        """获取所有语言阈值"""
        return copy.deepcopy(self._language_thresholds)

    def create_version(self, comment: str = "", created_by: str = "system") -> RuleVersion:
        """
        创建规则版本快照

        Args:
            comment: 备注
            created_by: 创建者

        Returns:
            版本对象
        """
        version = RuleVersion(
            version_id=self._generate_version_id(),
            rules=self._rules,
            created_at=datetime.now(),
            created_by=created_by,
            comment=comment,
        )
        self._versions.append(version)
        return version

    def get_versions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取版本历史

        Args:
            limit: 返回数量限制

        Returns:
            版本列表
        """
        versions = sorted(self._versions, key=lambda v: v.created_at, reverse=True)
        return [v.to_dict() for v in versions[:limit]]

    def get_version(self, version_id: str) -> Optional[Dict[str, Any]]:
        """获取指定版本"""
        for v in self._versions:
            if v.version_id == version_id:
                return v.to_dict()
        return None

    def rollback(self, version_id: str) -> bool:
        """
        回滚到指定版本

        Args:
            version_id: 版本ID

        Returns:
            是否成功
        """
        for v in self._versions:
            if v.version_id == version_id:
                self._rules = copy.deepcopy(v.rules)
                self._rebuild_index()
                self.create_version(comment=f"Rollback to {version_id}", created_by="system")
                return True
        return False

    def rollback_version(self, version_id: str) -> bool:
        """回滚到指定版本的别名方法"""
        return self.rollback(version_id)

    def record_true_positive(self, rule_id: str):
        """记录规则的真阳性"""
        if rule_id in self._effectiveness:
            self._effectiveness[rule_id].record_true_positive()
        elif rule_id in self._rule_index:
            self._effectiveness[rule_id] = RuleEffectiveness(
                rule_id=rule_id, total_matches=1, true_positives=1
            )

    def record_false_positive(self, rule_id: str):
        """记录规则的假阳性"""
        if rule_id in self._effectiveness:
            self._effectiveness[rule_id].record_false_positive()
        elif rule_id in self._rule_index:
            self._effectiveness[rule_id] = RuleEffectiveness(
                rule_id=rule_id, total_matches=1, false_positives=1
            )

    def compare_versions(self, version_id1: str, version_id2: str) -> Optional[Dict[str, Any]]:
        """
        比较两个版本的差异

        Args:
            version_id1: 第一个版本ID
            version_id2: 第二个版本ID

        Returns:
            差异信息
        """
        v1 = v2 = None
        for v in self._versions:
            if v.version_id == version_id1:
                v1 = v
            if v.version_id == version_id2:
                v2 = v

        if not v1 or not v2:
            return None

        rules1 = {r["rule_id"]: r for r in v1.rules}
        rules2 = {r["rule_id"]: r for r in v2.rules}

        added = [rid for rid in rules2 if rid not in rules1]
        removed = [rid for rid in rules1 if rid not in rules2]
        modified = []

        for rid in set(rules1) & set(rules2):
            if rules1[rid] != rules2[rid]:
                modified.append({"rule_id": rid, "before": rules1[rid], "after": rules2[rid]})

        return {
            "version1": v1.version_id,
            "version2": v2.version_id,
            "added_rules": added,
            "removed_rules": removed,
            "modified_rules": modified,
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified),
            },
        }

    def diff_versions(self, version_id1: str, version_id2: str) -> Optional[Dict[str, Any]]:
        """比较两个版本的差异 - compare_versions的别名"""
        return self.compare_versions(version_id1, version_id2)

    def add_template(self, template: RuleTemplate) -> RuleTemplate:
        """添加规则模板"""
        self._templates.append(template)
        return template

    def get_templates(
        self, language: Optional[str] = None, builtin_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        获取规则模板

        Args:
            language: 语言过滤
            builtin_only: 只返回内置模板

        Returns:
            模板列表
        """
        templates = self._templates
        if builtin_only:
            templates = [t for t in templates if t.is_builtin]
        if language:
            templates = [t for t in templates if t.language == language or t.language == "all"]
        return [t.to_dict() for t in templates]

    def apply_template(
        self, template_id: str, target_language: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        应用模板创建规则

        Args:
            template_id: 模板ID
            target_language: 目标语言

        Returns:
            从模板创建的规则列表
        """
        template = None
        for t in self._templates:
            if t.template_id == template_id:
                template = t
                break

        if not template:
            return []

        rules = copy.deepcopy(template.rules)
        for rule in rules:
            rule["rule_id"] = self._generate_rule_id(
                rule.get("pattern_code", "CUSTOM"), target_language or rule.get("language", "all")
            )
            rule["template_id"] = template_id
            self.add_rule(rule, created_by=f"template:{template_id}")

        return rules

    def record_rule_match(self, rule_id: str):
        """记录规则匹配"""
        if rule_id in self._effectiveness:
            self._effectiveness[rule_id].record_match()

    def record_rule_result(self, rule_id: str, is_true_positive: bool):
        """
        记录规则检测结果

        Args:
            rule_id: 规则ID
            is_true_positive: 是否为真阳性
        """
        if rule_id in self._effectiveness:
            if is_true_positive:
                self._effectiveness[rule_id].record_true_positive()
            else:
                self._effectiveness[rule_id].record_false_positive()

    def get_effectiveness_stats(
        self, limit: int = 20, sort_by: str = "total_matches"
    ) -> List[Dict[str, Any]]:
        """
        获取规则效果统计

        Args:
            limit: 返回数量
            sort_by: 排序字段 (total_matches, precision, recall_contribution)

        Returns:
            统计列表
        """
        stats = [e.to_dict() for e in self._effectiveness.values()]

        if sort_by == "precision":
            stats.sort(key=lambda x: x["precision"], reverse=True)
        elif sort_by == "recall_contribution":
            stats.sort(key=lambda x: x["recall_contribution"], reverse=True)
        else:
            stats.sort(key=lambda x: x["total_matches"], reverse=True)

        return stats[:limit]

    def get_effectiveness_by_category(self) -> Dict[str, Any]:
        """按分类获取规则效果统计"""
        category_stats = {}
        for rule in self._rules:
            rule_id = rule["rule_id"]
            category = rule.get("category", "unknown")
            if category not in category_stats:
                category_stats[category] = {
                    "rule_count": 0,
                    "total_matches": 0,
                    "true_positives": 0,
                    "false_positives": 0,
                    "avg_precision": 0.0,
                }

            stats = self._effectiveness.get(rule_id)
            if stats:
                category_stats[category]["rule_count"] += 1
                category_stats[category]["total_matches"] += stats.total_matches
                category_stats[category]["true_positives"] += stats.true_positives
                category_stats[category]["false_positives"] += stats.false_positives

        for cat in category_stats:
            stats = category_stats[cat]
            total = stats["true_positives"] + stats["false_positives"]
            if total > 0:
                stats["avg_precision"] = round(stats["true_positives"] / total, 4)

        return category_stats

    def validate_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证规则配置

        Args:
            rule: 规则配置

        Returns:
            验证结果
        """
        errors = []
        warnings = []

        if "pattern" not in rule:
            errors.append("缺少必需字段: pattern")
        else:
            try:
                re.compile(rule["pattern"])
            except re.error as e:
                errors.append(f"正则表达式错误: {e}")

        if "rule_id" in rule:
            if not re.match(r"^[A-Z0-9]+-[0-9]+(-[a-z]+)?$", rule["rule_id"]):
                warnings.append("rule_id 格式不符合建议规范")

        if "category" in rule:
            valid_categories = [c.value for c in RuleCategory]
            if rule["category"] not in valid_categories:
                errors.append(f"无效的分类: {rule['category']}")

        if "severity" in rule:
            valid_severities = [s.value for s in RuleSeverity]
            if rule["severity"] not in valid_severities:
                errors.append(f"无效的严重程度: {rule['severity']}")

        if "language" in rule:
            valid_languages = [l.value for l in LanguageType]
            if rule["language"] not in valid_languages:
                errors.append(f"无效的语言: {rule['language']}")

        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    def test_rule(self, rule: Dict[str, Any], test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        测试规则

        Args:
            rule: 规则配置
            test_cases: 测试用例 [{"input": "...", "should_match": bool}]

        Returns:
            测试结果
        """
        if "pattern" not in rule:
            return {"valid": False, "error": "缺少 pattern 字段"}

        try:
            pattern = re.compile(rule["pattern"])
        except re.error as e:
            return {"valid": False, "error": f"正则表达式错误: {e}"}

        results = []
        passed = 0
        failed = 0

        for case in test_cases:
            text = case.get("input", "")
            should_match = case.get("should_match", True)

            matches = bool(pattern.search(text))
            match_result = matches == should_match

            results.append(
                {
                    "input": text[:100] + "..." if len(text) > 100 else text,
                    "should_match": should_match,
                    "matched": matches,
                    "passed": match_result,
                }
            )

            if match_result:
                passed += 1
            else:
                failed += 1

        return {
            "valid": True,
            "passed": passed,
            "failed": failed,
            "total": len(test_cases),
            "pass_rate": round(passed / max(len(test_cases), 1), 4),
            "results": results,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取规则统计信息"""
        total = len(self._rules)
        enabled = sum(1 for r in self._rules if r.get("enabled", True))

        by_category = {}
        by_language = {}
        by_severity = {}
        by_pattern = {}

        for rule in self._rules:
            cat = rule.get("category", "unknown")
            lang = rule.get("language", "unknown")
            sev = rule.get("severity", "unknown")
            pat = rule.get("pattern_code", "unknown")

            by_category[cat] = by_category.get(cat, 0) + 1
            by_language[lang] = by_language.get(lang, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_pattern[pat] = by_pattern.get(pat, 0) + 1

        return {
            "total_rules": total,
            "enabled_rules": enabled,
            "disabled_rules": total - enabled,
            "versions_count": len(self._versions),
            "templates_count": len(self._templates),
            "by_category": by_category,
            "by_language": by_language,
            "by_severity": by_severity,
            "by_pattern": by_pattern,
            "effectiveness": {
                "tracked_rules": len(self._effectiveness),
                "total_matches": sum(e.total_matches for e in self._effectiveness.values()),
                "total_true_positives": sum(e.true_positives for e in self._effectiveness.values()),
                "total_false_positives": sum(
                    e.false_positives for e in self._effectiveness.values()
                ),
            },
        }

    def export_rules(
        self, format: str = "json", language: Optional[str] = None, category: Optional[str] = None
    ) -> str:
        """
        导出规则

        Args:
            format: 导出格式 (json, yaml)
            language: 语言过滤
            category: 分类过滤

        Returns:
            导出的规则字符串
        """
        rules = self._rules
        if language:
            rules = [
                r for r in rules if r.get("language") == language or r.get("language") == "all"
            ]
        if category:
            rules = [r for r in rules if r.get("category") == category]

        if format == "yaml":
            try:
                import yaml

                return yaml.dump(rules, allow_unicode=True, default_flow_style=False)
            except ImportError:
                format = "json"

        return json.dumps(rules, ensure_ascii=False, indent=2)

    def import_rules(
        self, rules_data: str, format: str = "json", merge: bool = True, created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        导入规则

        Args:
            rules_data: 规则数据
            format: 数据格式 (json, yaml)
            merge: 是否合并到现有规则
            created_by: 创建者

        Returns:
            导入结果
        """
        try:
            if format == "yaml":
                import yaml

                rules = yaml.safe_load(rules_data)
            else:
                rules = json.loads(rules_data)
        except Exception as e:
            return {"success": False, "error": f"解析失败: {e}"}

        if not isinstance(rules, list):
            rules = [rules]

        imported = 0
        skipped = 0
        errors = []

        if not merge:
            self._rules = []
            self._rule_index = {}
            self._enabled_rules = {}

        for rule in rules:
            validation = self.validate_rule(rule)
            if not validation["valid"]:
                errors.append(
                    {"rule_id": rule.get("rule_id", "unknown"), "errors": validation["errors"]}
                )
                skipped += 1
                continue

            existing_id = rule.get("rule_id")
            if existing_id and existing_id in self._rule_index:
                self.update_rule(existing_id, rule, updated_by=created_by)
            else:
                self.add_rule(rule, created_by=created_by)
            imported += 1

        return {
            "success": True,
            "imported": imported,
            "skipped": skipped,
            "errors": errors,
            "total": len(rules),
        }

    def reset_to_default(self):
        """重置为默认规则"""
        from .detection_rules import COMPREHENSIVE_DETECTION_RULES

        self.load_rules(
            COMPREHENSIVE_DETECTION_RULES, created_by="system", comment="Reset to default rules"
        )


rule_config_manager = RuleConfigManager()
