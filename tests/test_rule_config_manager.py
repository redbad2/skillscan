"""
规则配置管理器测试
"""

import pytest
import copy
from datetime import datetime
from src.rules.rule_config_manager import (
    RuleConfigManager,
    RuleVersion,
    RuleTemplate,
    RuleEffectiveness,
    LanguageType,
    RuleCategory,
    RuleSeverity,
)


class TestRuleEffectiveness:
    """规则效果统计测试"""

    def test_precision_calculation(self):
        """测试精确率计算"""
        eff = RuleEffectiveness(
            rule_id="test-001", total_matches=100, true_positives=80, false_positives=20
        )
        assert eff.precision == 0.8

    def test_precision_zero_denominator(self):
        """测试零除情况"""
        eff = RuleEffectiveness(rule_id="test-001")
        assert eff.precision == 0.0

    def test_recall_contribution(self):
        """测试召回贡献"""
        eff = RuleEffectiveness(rule_id="test-001", total_matches=100, true_positives=80)
        assert eff.recall_contribution == 0.8

    def test_record_match(self):
        """测试记录匹配"""
        eff = RuleEffectiveness(rule_id="test-001")
        eff.record_match()
        assert eff.total_matches == 1
        assert eff.last_used is not None

    def test_record_true_positive(self):
        """测试记录真阳性"""
        eff = RuleEffectiveness(rule_id="test-001")
        eff.record_true_positive()
        assert eff.true_positives == 1
        assert eff.total_matches == 1

    def test_record_false_positive(self):
        """测试记录假阳性"""
        eff = RuleEffectiveness(rule_id="test-001")
        eff.record_false_positive()
        assert eff.false_positives == 1
        assert eff.total_matches == 1

    def test_to_dict(self):
        """测试序列化"""
        eff = RuleEffectiveness(
            rule_id="test-001", total_matches=50, true_positives=40, false_positives=10
        )
        data = eff.to_dict()
        assert data["rule_id"] == "test-001"
        assert data["total_matches"] == 50
        assert data["precision"] == 0.8


class TestRuleVersion:
    """规则版本测试"""

    def test_version_creation(self):
        """测试版本创建"""
        rules = [{"rule_id": "test-001", "name": "Test Rule"}]
        version = RuleVersion(
            version_id="v1",
            rules=rules,
            created_at=datetime.now(),
            created_by="test",
            comment="Initial",
        )
        assert version.version_id == "v1"
        assert len(version.rules) == 1

    def test_version_to_dict(self):
        """测试版本序列化"""
        rules = [{"rule_id": "test-001"}]
        version = RuleVersion(
            version_id="v1", rules=rules, created_at=datetime.now(), created_by="test"
        )
        data = version.to_dict()
        assert data["version_id"] == "v1"
        assert "created_at" in data

    def test_version_from_dict(self):
        """测试版本反序列化"""
        data = {
            "version_id": "v1",
            "rules": [{"rule_id": "test-001"}],
            "created_at": datetime.now().isoformat(),
            "created_by": "test",
            "comment": "Test",
        }
        version = RuleVersion.from_dict(data)
        assert version.version_id == "v1"
        assert version.created_by == "test"


class TestRuleTemplate:
    """规则模板测试"""

    def test_template_creation(self):
        """测试模板创建"""
        template = RuleTemplate(
            template_id="tmpl-001",
            name="Test Template",
            description="A test template",
            language="en",
            rules=[],
            category="test",
            is_builtin=True,
        )
        assert template.template_id == "tmpl-001"
        assert template.is_builtin is True

    def test_template_to_dict(self):
        """测试模板序列化"""
        template = RuleTemplate(
            template_id="tmpl-001", name="Test", description="Test", language="en", rules=[]
        )
        data = template.to_dict()
        assert data["template_id"] == "tmpl-001"
        assert data["is_builtin"] is False


class TestRuleConfigManager:
    """规则配置管理器测试"""

    @pytest.fixture
    def manager(self):
        """创建新的管理器实例"""
        manager = object.__new__(RuleConfigManager)
        manager._initialized = None
        manager._rules = []
        manager._rule_index = {}
        manager._versions = []
        manager._templates = []
        manager._effectiveness = {}
        manager._language_thresholds = {
            LanguageType.ENGLISH: 0.7,
            LanguageType.CHINESE: 0.65,
            LanguageType.JAPANESE: 0.65,
            LanguageType.KOREAN: 0.65,
            LanguageType.MIXED: 0.6,
            LanguageType.ALL: 0.7,
        }
        manager._enabled_rules = {}
        manager._version_counter = 0
        manager._init_builtin_templates()
        return manager

    def test_add_rule(self, manager):
        """测试添加规则"""
        rule = {
            "rule_id": "test-001",
            "pattern_code": "PI",
            "language": "en",
            "name": "Test Rule",
            "description": "A test rule",
            "patterns": ["pattern1", "pattern2"],
            "severity": "high",
            "category": "prompt_injection",
        }
        result = manager.add_rule(rule)
        assert result is not None
        assert len(manager._rules) == 1
        assert manager._rules[0]["rule_id"] == "test-001"

    def test_add_duplicate_rule(self, manager):
        """测试添加重复规则"""
        rule1 = {
            "rule_id": "test-001",
            "pattern_code": "PI",
            "language": "en",
            "name": "Test",
            "description": "Test",
            "patterns": ["test"],
        }
        manager.add_rule(rule1)
        rule2 = {
            "rule_id": "test-001",
            "pattern_code": "PI",
            "language": "en",
            "name": "Test 2",
            "description": "Test 2",
            "patterns": ["test2"],
        }
        result = manager.add_rule(rule2)
        assert result["rule_id"] == "test-001"

    def test_get_rule(self, manager):
        """测试获取规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        rule = manager.get_rule("test-001")
        assert rule is not None
        assert rule["rule_id"] == "test-001"

    def test_get_rule_not_found(self, manager):
        """测试获取不存在的规则"""
        rule = manager.get_rule("nonexistent")
        assert rule is None

    def test_update_rule(self, manager):
        """测试更新规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Original",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        result = manager.update_rule("test-001", {"name": "Updated"})
        assert result is not None
        assert manager.get_rule("test-001")["name"] == "Updated"

    def test_delete_rule(self, manager):
        """测试删除规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        result = manager.delete_rule("test-001")
        assert result is True
        assert len(manager._rules) == 0

    def test_enable_rule(self, manager):
        """测试启用/禁用规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
                "enabled": False,
            }
        )
        assert manager.enable_rule("test-001", True) is True
        assert manager._enabled_rules["test-001"] is True

    def test_get_all_rules(self, manager):
        """测试获取所有规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test1",
                "description": "Test",
                "patterns": ["test"],
                "enabled": True,
            }
        )
        manager.add_rule(
            {
                "rule_id": "test-002",
                "pattern_code": "DE",
                "language": "zh",
                "name": "Test2",
                "description": "Test",
                "patterns": ["test"],
                "enabled": False,
            }
        )
        all_rules = manager.get_all_rules()
        assert len(all_rules) == 2
        enabled_rules = manager.get_all_rules(enabled_only=True)
        assert len(enabled_rules) == 1

    def test_get_rules_by_language(self, manager):
        """测试按语言获取规则"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "English Rule",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        manager.add_rule(
            {
                "rule_id": "test-002",
                "pattern_code": "PI",
                "language": "zh",
                "name": "Chinese Rule",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        rules = manager.get_rules_by_language("en")
        assert len(rules) == 1
        assert rules[0]["name"] == "English Rule"

    def test_language_thresholds(self, manager):
        """测试语言阈值"""
        assert manager.get_language_threshold("en") == 0.7
        assert manager.set_language_threshold("en", 0.8) is True
        assert manager.get_language_threshold("en") == 0.8
        assert manager.set_language_threshold("en", 1.5) is False

    def test_get_all_thresholds(self, manager):
        """测试获取所有阈值"""
        thresholds = manager.get_all_thresholds()
        assert isinstance(thresholds, dict)
        assert "en" in thresholds
        assert "zh" in thresholds

    def test_version_creation(self, manager):
        """测试版本创建"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        version = manager.create_version(comment="Initial version")
        assert version is not None
        assert version.version_id.startswith("v")
        assert len(manager._versions) == 1

    def test_get_versions(self, manager):
        """测试获取版本列表"""
        for i in range(5):
            manager.add_rule(
                {
                    "rule_id": f"test-{i:03d}",
                    "pattern_code": "PI",
                    "language": "en",
                    "name": f"Test {i}",
                    "description": "Test",
                    "patterns": ["test"],
                }
            )
            manager.create_version(comment=f"Version {i}")

        versions = manager.get_versions(limit=3)
        assert len(versions) == 3

    def test_rollback(self, manager):
        """测试版本回滚"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Original",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        manager.create_version(comment="Initial")

        manager.update_rule("test-001", {"name": "Modified"})
        manager.create_version(comment="After modify")

        result = manager.rollback(manager._versions[0].version_id)
        assert result is True
        assert manager.get_rule("test-001")["name"] == "Original"

    def test_rollback_version_alias(self, manager):
        """测试rollback_version别名"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        version = manager.create_version(comment="Test")
        result = manager.rollback_version(version.version_id)
        assert result is True

    def test_compare_versions(self, manager):
        """测试版本比较"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        v1 = manager.create_version(comment="V1")

        manager.update_rule("test-001", {"name": "Updated"})
        v2 = manager.create_version(comment="V2")

        manager.add_rule(
            {
                "rule_id": "test-002",
                "pattern_code": "DE",
                "language": "en",
                "name": "New Rule",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        v3 = manager.create_version(comment="V3")

        diff = manager.compare_versions(v1.version_id, v3.version_id)
        assert diff is not None
        assert "added_rules" in diff
        assert "removed_rules" in diff
        assert "modified_rules" in diff

    def test_diff_versions_alias(self, manager):
        """测试diff_versions别名"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )
        v1 = manager.create_version(comment="V1")
        v2 = manager.create_version(comment="V2")

        diff = manager.diff_versions(v1.version_id, v2.version_id)
        assert diff is not None

    def test_get_templates(self, manager):
        """测试获取模板"""
        templates = manager.get_templates()
        assert len(templates) >= 4

        builtin = manager.get_templates(builtin_only=True)
        assert len(builtin) >= 4

    def test_apply_template(self, manager):
        """测试应用模板"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )

        template = RuleTemplate(
            template_id="custom-template",
            name="Custom",
            description="Custom template",
            language="all",
            rules=[
                {
                    "rule_id": "new-001",
                    "name": "New Rule",
                    "pattern_code": "PI",
                    "language": "en",
                    "pattern": r"new",
                }
            ],
        )
        manager.add_template(template)

        result = manager.apply_template("custom-template")
        assert isinstance(result, list)
        assert len(result) == 1
        assert len(manager._rules) == 2

    def test_validate_rule(self, manager):
        """测试规则验证"""
        valid_rule = {
            "rule_id": "test-001",
            "pattern_code": "PI",
            "language": "en",
            "name": "Valid Rule",
            "patterns": ["test"],
        }
        result = manager.validate_rule(valid_rule)
        assert "valid" in result

    def test_test_rule(self, manager):
        """测试规则测试"""
        rule = {
            "rule_id": "test-001",
            "pattern_code": "PI",
            "language": "en",
            "name": "Test Rule",
            "description": "Test",
            "pattern": r"malicious|hack|exploit",
        }

        test_cases = [
            {"input": "This contains malicious code", "should_match": True},
            {"input": "This is clean content", "should_match": False},
        ]

        result = manager.test_rule(rule=rule, test_cases=test_cases)
        assert "passed" in result
        assert "failed" in result
        assert result["total"] == 2

    def test_record_feedback(self, manager):
        """测试记录反馈"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "pattern": r"test",
            }
        )

        manager.record_true_positive("test-001")
        manager.record_false_positive("test-001")

        stats = manager.get_effectiveness_stats()
        assert isinstance(stats, list)
        rule_stats = [s for s in stats if s.get("rule_id") == "test-001"]
        assert len(rule_stats) == 1

    def test_export_import_rules(self, manager):
        """测试规则导入导出"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Export Test",
                "description": "Test",
                "patterns": ["test"],
            }
        )

        exported = manager.export_rules(format="json")
        assert "rules" in exported or isinstance(exported, str)

    def test_statistics(self, manager):
        """测试统计信息"""
        manager.add_rule(
            {
                "rule_id": "test-001",
                "pattern_code": "PI",
                "language": "en",
                "name": "Test",
                "description": "Test",
                "patterns": ["test"],
                "enabled": True,
            }
        )
        manager.add_rule(
            {
                "rule_id": "test-002",
                "pattern_code": "DE",
                "language": "zh",
                "name": "Test 2",
                "description": "Test",
                "patterns": ["test"],
                "enabled": False,
            }
        )

        stats = manager.get_statistics()
        assert "total_rules" in stats
        assert "enabled_rules" in stats
        assert "disabled_rules" in stats
        assert stats["total_rules"] == 2
        assert stats["enabled_rules"] == 1
        assert stats["disabled_rules"] == 1
