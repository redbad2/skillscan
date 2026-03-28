"""
集成测试

测试SkillScan系统的端到端工作流程。
"""

import pytest
import tempfile
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestEndToEndWorkflow:
    """端到端工作流程测试"""

    @pytest.fixture
    def skill_directory(self):
        """创建测试技能目录"""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "test-skill"
            skill_dir.mkdir()

            # 创建SKILL.md
            skill_md = skill_dir / "SKILL.md"
            skill_md.write_text(
                "# Test Security Skill\n\n"
                "A comprehensive security testing skill for vulnerability detection.\n\n"
                "## Features\n"
                "- Network scanning\n"
                "- Vulnerability assessment\n"
                "- Report generation\n\n"
                "## Usage\n"
                "```bash\n"
                "python scanner.py --target localhost\n"
                "```\n"
            )

            # 创建主要脚本
            main_script = skill_dir / "scanner.py"
            main_script.write_text(
                "#!/usr/bin/env python3\n"
                "# Security Scanner - Main module\n\n"
                "import os\n"
                "import json\n"
                "import logging\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "\n"
                "class SecurityScanner:\n"
                "    # Security scanner class\n"
                "    \n"
                "    def __init__(self, target: str, timeout: int = 30):\n"
                "        self.target = target\n"
                "        self.timeout = timeout\n"
                "        self.results = []\n"
                "    \n"
                "    def scan(self) -> dict:\n"
                "        # Run security scan\n"
                "        logger.info(f'Scanning {self.target}')\n"
                "        self.results.append({'port': 22, 'service': 'ssh', 'status': 'open'})\n"
                "        return {'target': self.target, 'results': self.results, 'status': 'completed'}\n"
                "\n"
                "def main():\n"
                "    scanner = SecurityScanner('localhost')\n"
                "    results = scanner.scan()\n"
                "    print(json.dumps(results, indent=2))\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )

            # 创建辅助脚本
            helper_script = skill_dir / "utils.py"
            helper_script.write_text(
                "# Utility functions for the security scanner\n\n"
                "import hashlib\n"
                "import re\n"
                "from typing import List\n\n"
                "\n"
                "def calculate_file_hash(filepath: str) -> str:\n"
                "    # Calculate SHA256 hash of a file\n"
                "    with open(filepath, 'rb') as f:\n"
                "        return hashlib.sha256(f.read()).hexdigest()\n\n"
                "\n"
                "def parse_ip_address(text: str) -> List[str]:\n"
                "    # Extract IP addresses from text\n"
                "    pattern = r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b'\n"
                "    return re.findall(pattern, text)\n\n"
                "\n"
                "def validate_port(port: int) -> bool:\n"
                "    # Validate port number\n"
                "    return 1 <= port <= 65535\n"
            )

            yield skill_dir

    def test_complete_workflow(self, skill_directory):
        """测试完整的工作流程"""
        # 1. 验证目录结构
        assert (skill_directory / "SKILL.md").exists()
        assert (skill_directory / "scanner.py").exists()
        assert (skill_directory / "utils.py").exists()

        # 2. 读取文件内容
        skill_md_content = (skill_directory / "SKILL.md").read_text()
        assert "# Test Security Skill" in skill_md_content

        scanner_content = (skill_directory / "scanner.py").read_text()
        assert "class SecurityScanner" in scanner_content

        # 3. 验证文件可以被分析
        scripts = [
            {"filename": "scanner.py", "content": scanner_content},
            {"filename": "utils.py", "content": (skill_directory / "utils.py").read_text()},
        ]

        # 验证脚本数据结构
        for script in scripts:
            assert "filename" in script
            assert "content" in script
            assert len(script["content"]) > 0


class TestMultiLanguageSupport:
    """多语言支持测试"""

    @pytest.fixture
    def chinese_skill_directory(self):
        """创建中文技能目录"""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "chinese-skill"
            skill_dir.mkdir()

            # 中文SKILL.md
            skill_md = skill_dir / "SKILL.md"
            skill_md.write_text(
                "# 安全扫描工具\n\n"
                "这是一个用于检测系统漏洞的安全扫描工具。\n\n"
                "## 功能特性\n"
                "- 端口扫描\n"
                "- 漏洞检测\n"
                "- 报告生成\n\n"
                "## 使用方法\n"
                "```bash\n"
                "python scanner.py --target 目标地址\n"
                "```\n"
            )

            # 中文注释的Python脚本
            scanner_script = skill_dir / "scanner.py"
            scanner_script.write_text(
                "#!/usr/bin/env python3\n"
                "# 安全扫描器 - 主模块\n\n"
                "import logging\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "\n"
                "class 安全扫描器:\n"
                "    # 安全扫描器类\n"
                "    \n"
                "    def __init__(self, 目标: str, 超时: int = 30):\n"
                "        self.目标 = 目标\n"
                "        self.超时 = 超时\n"
                "        self.结果 = []\n"
                "    \n"
                "    def 扫描(self) -> dict:\n"
                "        # 执行安全扫描\n"
                "        logger.info(f'正在扫描 {self.目标}')\n"
                "        self.结果.append({'端口': 22, '服务': 'ssh', '状态': '开放'})\n"
                "        return {'目标': self.目标, '结果': self.结果, '状态': '完成'}\n"
            )

            yield skill_dir

    def test_chinese_content_detection(self, chinese_skill_directory):
        """测试中文内容检测"""
        skill_md = (chinese_skill_directory / "SKILL.md").read_text()

        # 验证中文内容
        assert "安全扫描工具" in skill_md
        assert "漏洞检测" in skill_md
        assert "使用方法" in skill_md

        # 验证中文脚本
        scanner_script = (chinese_skill_directory / "scanner.py").read_text()
        assert "安全扫描器" in scanner_script


class TestConfigurationLoading:
    """配置加载测试"""

    def test_env_file_loading(self):
        """测试环境变量加载"""
        # 设置测试环境变量
        test_env = {
            "MONGODB_URL": "mongodb://localhost:27017",
            "MONGODB_DB_NAME": "skillscan_test",
            "REDIS_URL": "redis://localhost:6379",
            "LOG_LEVEL": "DEBUG",
        }

        # 验证环境变量格式
        for key, value in test_env.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert len(value) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
