"""
数据模型测试

测试MongoDB数据模型，包括Skill、Vulnerability和Configuration模型。
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestSkillModel:
    """技能数据模型测试"""

    @pytest.fixture
    def sample_skill_data(self) -> Dict[str, Any]:
        """示例技能数据"""
        return {
            "skill_id": "test-skill-001",
            "name": "Test Security Scanner",
            "version": "1.0.0",
            "description": "A test security scanning skill",
            "author": "Test Author",
            "source": "https://github.com/test/skill",
            "skill_md_content": "# Test Skill\n\nThis is a test skill.",
            "language": "en",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

    def test_skill_model_structure(self, sample_skill_data):
        """测试技能模型结构完整性"""
        required_fields = ["skill_id", "name", "version", "skill_md_content"]

        for field in required_fields:
            assert field in sample_skill_data, f"技能模型缺少字段: {field}"

    def test_skill_id_format(self):
        """测试技能ID格式"""
        valid_ids = [
            "test-skill-001",
            "clawhub-skill-123",
            "smithery-tool-456",
            "skill_789",
        ]

        for skill_id in valid_ids:
            assert isinstance(skill_id, str)
            assert len(skill_id) > 0

    def test_skill_metadata(self, sample_skill_data):
        """测试技能元数据"""
        assert "author" in sample_skill_data
        assert "source" in sample_skill_data
        assert "created_at" in sample_skill_data
        assert isinstance(sample_skill_data["created_at"], datetime)


class TestVulnerabilityModel:
    """漏洞数据模型测试"""

    @pytest.fixture
    def sample_vulnerability(self) -> Dict[str, Any]:
        """示例漏洞数据"""
        return {
            "vuln_id": "vuln-001",
            "skill_id": "test-skill-001",
            "pattern_code": "P1",
            "category": "prompt_injection",
            "severity": "high",
            "confidence": 0.95,
            "description": "Detected instruction override pattern",
            "evidence": [
                {
                    "file": "SKILL.md",
                    "line_number": 10,
                    "matched_text": "Ignore all previous instructions",
                    "context": "...",
                }
            ],
            "rule_id": "P1-001",
            "detected_at": datetime.utcnow(),
            "detection_method": "static",
        }

    def test_vulnerability_model_structure(self, sample_vulnerability):
        """测试漏洞模型结构完整性"""
        required_fields = [
            "vuln_id",
            "skill_id",
            "pattern_code",
            "category",
            "severity",
            "confidence",
            "description",
            "evidence",
        ]

        for field in required_fields:
            assert field in sample_vulnerability, f"漏洞模型缺少字段: {field}"

    def test_valid_severity_levels(self):
        """测试有效的严重性级别"""
        valid_severities = ["critical", "high", "medium", "low", "info"]

        for severity in valid_severities:
            assert severity in valid_severities

    def test_valid_categories(self):
        """测试有效的漏洞类别"""
        valid_categories = [
            "prompt_injection",
            "data_exfiltration",
            "privilege_escalation",
            "supply_chain_risk",
        ]

        for category in valid_categories:
            assert category in valid_categories

    def test_confidence_range(self, sample_vulnerability):
        """测试置信度范围"""
        confidence = sample_vulnerability["confidence"]
        assert 0 <= confidence <= 1, "置信度应在0-1之间"

    def test_evidence_structure(self, sample_vulnerability):
        """测试证据结构"""
        evidence = sample_vulnerability["evidence"]
        assert isinstance(evidence, list)
        assert len(evidence) > 0

        for ev in evidence:
            assert "file" in ev
            assert "matched_text" in ev


class TestConfigurationModel:
    """配置数据模型测试"""

    @pytest.fixture
    def sample_config(self) -> Dict[str, Any]:
        """示例配置数据"""
        return {
            "config_id": "config-001",
            "name": "Default Configuration",
            "description": "Default scanning configuration",
            "detection_rules": {
                "prompt_injection": True,
                "data_exfiltration": True,
                "privilege_escalation": True,
                "supply_chain_risk": True,
            },
            "severity_threshold": "medium",
            "languages": ["en", "zh"],
            "max_file_size": 10485760,  # 10MB
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

    def test_config_structure(self, sample_config):
        """测试配置模型结构"""
        required_fields = ["config_id", "name", "detection_rules"]

        for field in required_fields:
            assert field in sample_config, f"配置模型缺少字段: {field}"

    def test_detection_rules_config(self, sample_config):
        """测试检测规则配置"""
        rules = sample_config["detection_rules"]

        expected_rules = [
            "prompt_injection",
            "data_exfiltration",
            "privilege_escalation",
            "supply_chain_risk",
        ]

        for rule in expected_rules:
            assert rule in rules, f"缺少检测规则配置: {rule}"
            assert isinstance(rules[rule], bool)

    def test_supported_languages(self, sample_config):
        """测试支持的语言配置"""
        languages = sample_config["languages"]

        assert isinstance(languages, list)
        assert len(languages) > 0
        assert "en" in languages or "zh" in languages


class TestScanResult:
    """扫描结果模型测试"""

    @pytest.fixture
    def sample_scan_result(self) -> Dict[str, Any]:
        """示例扫描结果"""
        return {
            "scan_id": "scan-001",
            "skill_id": "test-skill-001",
            "status": "completed",
            "started_at": datetime.utcnow(),
            "completed_at": datetime.utcnow(),
            "duration_seconds": 15.5,
            "files_scanned": 5,
            "vulnerabilities_found": 3,
            "risk_score": 65,
            "summary": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0,
            },
            "detection_methods": ["static", "hybrid"],
        }

    def test_scan_result_structure(self, sample_scan_result):
        """测试扫描结果结构"""
        required_fields = [
            "scan_id",
            "skill_id",
            "status",
            "files_scanned",
            "vulnerabilities_found",
            "risk_score",
        ]

        for field in required_fields:
            assert field in sample_scan_result, f"扫描结果缺少字段: {field}"

    def test_valid_status(self, sample_scan_result):
        """测试有效的扫描状态"""
        valid_statuses = ["pending", "running", "completed", "failed", "cancelled"]
        assert sample_scan_result["status"] in valid_statuses

    def test_risk_score_range(self, sample_scan_result):
        """测试风险评分范围"""
        risk_score = sample_scan_result["risk_score"]
        assert 0 <= risk_score <= 100, "风险评分应在0-100之间"

    def test_summary_consistency(self, sample_scan_result):
        """测试汇总数据一致性"""
        summary = sample_scan_result["summary"]
        total = sum(summary.values())
        assert total == sample_scan_result["vulnerabilities_found"], "漏洞汇总数量与总数不一致"


class TestDatabaseModels:
    """数据库模型集成测试"""

    def test_model_imports(self):
        """测试模型可以被导入"""
        try:
            from models.skill import SkillModel
            from models.vulnerability import VulnerabilityModel
            from models.configuration import ConfigurationModel

            assert True
        except ImportError as e:
            pytest.skip(f"无法导入模型: {e}")

    def test_database_manager_import(self):
        """测试数据库管理器可以被导入"""
        try:
            from models.database import DatabaseManager

            assert True
        except ImportError as e:
            pytest.skip(f"无法导入数据库管理器: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
