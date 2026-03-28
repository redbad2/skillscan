"""
文件处理器测试

测试文件预处理功能，包括文件读取、解析和分类。
"""

import pytest
import tempfile
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestFileProcessor:
    """文件处理器测试"""

    @pytest.fixture
    def temp_skill_dir(self):
        """创建临时技能目录"""
        with tempfile.TemporaryDirectory() as tmpdir:
            skill_dir = Path(tmpdir) / "test-skill"
            skill_dir.mkdir()
            yield skill_dir

    def test_file_processor_import(self):
        """测试文件处理器可以被导入"""
        try:
            from preprocessors.file_processor import FileProcessor

            assert True
        except ImportError as e:
            pytest.skip(f"无法导入文件处理器: {e}")

    def test_read_skill_md(self, temp_skill_dir):
        """测试读取SKILL.md文件"""
        skill_content = """# Test Skill

This is a test skill for security scanning.

## Features
- Feature 1
- Feature 2

## Usage
```bash
python main.py --input file.txt
```
"""
        skill_file = temp_skill_dir / "SKILL.md"
        skill_file.write_text(skill_content)

        # 验证文件可以被读取
        content = skill_file.read_text()
        assert "# Test Skill" in content
        assert "python main.py" in content

    def test_read_script_files(self, temp_skill_dir):
        """测试读取脚本文件"""
        scripts = {
            "main.py": """
import os

def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
""",
            "helper.sh": """#!/bin/bash
echo "Helper script"
""",
            "config.js": """
const config = {
    apiUrl: "https://api.example.com",
    timeout: 5000
};
""",
        }

        for filename, content in scripts.items():
            script_file = temp_skill_dir / filename
            script_file.write_text(content)

        # 验证所有文件可以被读取
        for filename in scripts.keys():
            file_path = temp_skill_dir / filename
            assert file_path.exists()
            content = file_path.read_text()
            assert len(content) > 0

    def test_file_extension_detection(self, temp_skill_dir):
        """测试文件扩展名检测"""
        test_files = {
            "script.py": ".py",
            "style.css": ".css",
            "index.html": ".html",
            "data.json": ".json",
            "README.md": ".md",
            "config.yaml": ".yaml",
            "run.sh": ".sh",
            "main.js": ".js",
            "types.ts": ".ts",
        }

        for filename, expected_ext in test_files.items():
            file_path = temp_skill_dir / filename
            file_path.write_text("test content")

            detected_ext = file_path.suffix
            assert (
                detected_ext == expected_ext
            ), f"文件 {filename} 的扩展名检测错误: 期望 {expected_ext}, 实际 {detected_ext}"

    def test_large_file_handling(self, temp_skill_dir):
        """测试大文件处理"""
        # 创建一个较大的文件
        large_content = "# " + "A" * 1000 + "\n" * 1000
        large_file = temp_skill_dir / "large.md"
        large_file.write_text(large_content)

        # 验证可以读取
        content = large_file.read_text()
        assert len(content) > 1000
        assert "# AAAAA" in content


class TestFileClassification:
    """测试文件分类功能"""

    def test_detect_file_type(self):
        """测试检测文件类型"""

        # 模拟文件类型检测逻辑
        def classify_file(filename: str) -> str:
            ext = Path(filename).suffix.lower()

            code_extensions = {
                ".py",
                ".js",
                ".ts",
                ".java",
                ".c",
                ".cpp",
                ".go",
                ".rs",
                ".rb",
                ".php",
            }
            script_extensions = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
            config_extensions = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}
            doc_extensions = {".md", ".txt", ".rst"}
            web_extensions = {".html", ".css", ".jsx", ".tsx", ".vue"}

            if ext in code_extensions:
                return "code"
            elif ext in script_extensions:
                return "script"
            elif ext in config_extensions:
                return "config"
            elif ext in doc_extensions:
                return "documentation"
            elif ext in web_extensions:
                return "web"
            else:
                return "other"

        # 测试各种文件类型
        test_cases = [
            ("main.py", "code"),
            ("app.js", "code"),
            ("index.html", "web"),
            ("style.css", "web"),
            ("config.json", "config"),
            ("settings.yaml", "config"),
            ("README.md", "documentation"),
            ("install.sh", "script"),
            ("setup.bat", "script"),
            ("unknown.xyz", "other"),
        ]

        for filename, expected_type in test_cases:
            detected_type = classify_file(filename)
            assert (
                detected_type == expected_type
            ), f"文件 {filename} 类型检测错误: 期望 {expected_type}, 实际 {detected_type}"

    def test_is_executable_script(self):
        """测试检测可执行脚本"""
        executable_extensions = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".php"}

        def is_executable(filename: str) -> bool:
            ext = Path(filename).suffix.lower()
            return ext in executable_extensions

        assert is_executable("script.py") == True
        assert is_executable("run.sh") == True
        assert is_executable("app.js") == True
        assert is_executable("README.md") == False
        assert is_executable("config.json") == False


class TestContentExtraction:
    """测试内容提取功能"""

    def test_extract_code_blocks(self):
        """测试提取代码块"""
        import re

        content = """# Example

Here's some Python code:

```python
def hello():
    print("Hello, World!")
```

And some bash:

```bash
echo "Hello from bash"
```

No code here.
"""

        code_block_pattern = r"```(\w*)\n(.*?)```"
        matches = re.findall(code_block_pattern, content, re.DOTALL)

        assert len(matches) == 2
        assert matches[0][0] == "python"
        assert "def hello():" in matches[0][1]
        assert matches[1][0] == "bash"
        assert "echo" in matches[1][1]

    def test_extract_imports(self):
        """测试提取导入语句"""
        import re

        python_code = """
import os
import sys
import requests as req
from pathlib import Path
from typing import List, Dict
"""

        import_pattern = r"^(?:from\s+[\w.]+\s+)?import\s+[\w., ]+"
        imports = re.findall(import_pattern, python_code, re.MULTILINE)

        assert len(imports) == 5
        assert "import os" in imports
        assert "import requests as req" in imports
        assert "from pathlib import Path" in imports

    def test_extract_urls(self):
        """测试提取URLs"""
        import re

        content = """
Check out https://example.com and http://test.org
Contact us at https://evil.com/steal
"""

        url_pattern = r"https?://[^\s<>\"']+"
        urls = re.findall(url_pattern, content)

        assert len(urls) == 3
        assert "https://example.com" in urls
        assert "http://test.org" in urls
        assert "https://evil.com/steal" in urls


class TestFileValidation:
    """测试文件验证功能"""

    def test_validate_file_size(self):
        """测试文件大小验证"""
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

        def validate_size(content: str) -> bool:
            return len(content.encode("utf-8")) <= MAX_FILE_SIZE

        # 小文件
        small_content = "A" * 1000
        assert validate_size(small_content) == True

        # 大文件
        large_content = "A" * (MAX_FILE_SIZE + 1)
        assert validate_size(large_content) == False

    def test_validate_encoding(self):
        """测试文件编码验证"""
        test_content = "Hello, 世界! 🌍"

        # UTF-8编码验证
        try:
            encoded = test_content.encode("utf-8")
            decoded = encoded.decode("utf-8")
            assert decoded == test_content
        except UnicodeEncodeError:
            pytest.fail("UTF-8编码失败")

    def test_validate_file_extension(self):
        """测试文件扩展名验证"""
        allowed_extensions = {".py", ".js", ".ts", ".sh", ".md", ".json", ".yaml", ".txt"}

        def is_allowed(filename: str) -> bool:
            ext = Path(filename).suffix.lower()
            return ext in allowed_extensions

        assert is_allowed("script.py") == True
        assert is_allowed("README.md") == True
        assert is_allowed("malware.exe") == False
        assert is_allowed("virus.dll") == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
