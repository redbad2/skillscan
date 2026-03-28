"""
文件处理器模块

处理技能文件的预处理，包括语言检测、编码标准化、元数据提取。
"""

import re
import hashlib
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

from loguru import logger

from src.config import LANGUAGE_CONFIG


class LanguageDetector:
    """语言检测器"""

    # 语言特征模式
    LANGUAGE_PATTERNS = {
        "zh": {
            "chars": re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]"),
            "keywords": ["函数", "类", "方法", "参数", "返回", "导入", "模块", "文件", "目录", "变量"],
        },
        "ja": {
            "chars": re.compile(r"[\u3040-\u309f\u30a0-\u30ff\uff00-\uff9f\u4e00-\u9faf]"),
            "keywords": ["関数", "クラス", "メソッド", "引数", "戻り値", "インポート", "モジュール"],
        },
        "ko": {
            "chars": re.compile(r"[\uac00-\ud7af\u1100-\u11ff\u3130-\u318f]"),
            "keywords": ["함수", "클래스", "메서드", "매개변수", "반환", "가져오기", "모듈"],
        },
        "en": {
            "chars": re.compile(r"[a-zA-Z]"),
            "keywords": ["function", "class", "method", "parameter", "return", "import", "module"],
        },
    }

    @classmethod
    def detect(cls, text: str) -> Tuple[str, float]:
        """
        检测文本的主要语言

        Args:
            text: 要检测的文本

        Returns:
            (语言代码, 置信度)
        """
        if not text:
            return "en", 0.0

        scores: Dict[str, float] = {}

        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            # 字符匹配得分
            char_matches = len(patterns["chars"].findall(text))
            char_score = char_matches / max(len(text), 1)

            # 关键词匹配得分
            keyword_matches = sum(1 for kw in patterns["keywords"] if kw in text)
            keyword_score = keyword_matches / max(len(patterns["keywords"]), 1)

            # 综合得分
            scores[lang] = char_score * 0.7 + keyword_score * 0.3

        if not scores:
            return "en", 0.5

        # 找出得分最高的语言
        best_lang = max(scores, key=scores.get)
        total_score = sum(scores.values())
        confidence = scores[best_lang] / total_score if total_score > 0 else 0.5

        return best_lang, confidence

    @classmethod
    def detect_encoding(cls, text: bytes) -> str:
        """
        检测文本编码

        Args:
            text: 原始字节数据

        Returns:
            编码名称
        """
        # 尝试常见编码
        encodings = ["utf-8", "gbk", "gb2312", "gb18030", "shift_jis", "euc-jp", "euc-kr", "latin-1"]

        for encoding in encodings:
            try:
                text.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue

        return "utf-8"  # 默认

    @classmethod
    def is_mixed_language(cls, text: str, threshold: float = 0.3) -> bool:
        """
        检测是否为混合语言

        Args:
            text: 要检测的文本
            threshold: 混合语言阈值

        Returns:
            是否为混合语言
        """
        scores = {}
        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            char_matches = len(patterns["chars"].findall(text))
            scores[lang] = char_matches

        total = sum(scores.values())
        if total == 0:
            return False

        # 检查是否有两种以上语言占比超过阈值
        significant_langs = sum(1 for s in scores.values() if s / total > threshold)
        return significant_langs > 1


class FileProcessor:
    """文件处理器"""

    def __init__(self):
        self.language_detector = LanguageDetector()

    def process_content(self, content: str) -> Dict[str, Any]:
        """
        处理SKILL.md内容

        Args:
            content: SKILL.md文件内容

        Returns:
            处理结果
        """
        result = {
            "language": "unknown",
            "language_confidence": 0.0,
            "is_mixed_language": False,
            "encoding": "utf-8",
            "content_hash": "",
            "metadata": {},
            "clean_content": content,
            "file_size": len(content.encode("utf-8")),
        }

        if not content:
            return result

        # 计算内容哈希
        result["content_hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # 语言检测
        lang, confidence = self.language_detector.detect(content)
        result["language"] = lang
        result["language_confidence"] = confidence
        result["is_mixed_language"] = self.language_detector.is_mixed_language(content)

        # 提取元数据
        result["metadata"] = self._extract_metadata(content)

        # 清理内容
        result["clean_content"] = self._clean_content(content)

        return result

    def _extract_metadata(self, content: str) -> Dict[str, Any]:
        """从内容提取元数据"""
        metadata = {}

        # 提取YAML frontmatter
        yaml_pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
        match = yaml_pattern.match(content)

        if match:
            try:
                import yaml
                metadata = yaml.safe_load(match.group(1)) or {}
            except Exception:
                pass

        # 提取标题
        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if title_match and "name" not in metadata:
            metadata["name"] = title_match.group(1).strip()

        # 提取描述
        desc_match = re.search(r"^##\s+Description\s*\n(.+?)(?=\n#|\Z)", content, re.DOTALL | re.MULTILINE)
        if desc_match and "description" not in metadata:
            metadata["description"] = desc_match.group(1).strip()[:500]

        # 提取权限
        perm_match = re.search(r"(?i)(?:permissions?|权限)[:\s]*\n((?:\s*[-*].*\n?)+)", content)
        if perm_match:
            permissions = re.findall(r"[-*]\s*(.+)", perm_match.group(1))
            if permissions:
                metadata["permissions"] = permissions

        return metadata

    def _clean_content(self, content: str) -> str:
        """清理内容"""
        # 移除BOM
        content = content.lstrip("\ufeff")

        # 标准化换行符
        content = content.replace("\r\n", "\n").replace("\r", "\n")

        # 移除尾部空白
        content = content.rstrip()

        return content

    def process_script(
        self, filename: str, content: bytes, declared_language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        处理脚本文件

        Args:
            filename: 文件名
            content: 文件内容（字节）
            declared_language: 声明的语言类型

        Returns:
            处理结果
        """
        # 检测编码
        encoding = self.language_detector.detect_encoding(content)

        # 解码内容
        try:
            decoded_content = content.decode(encoding)
        except Exception:
            decoded_content = content.decode("utf-8", errors="replace")

        # 检测语言
        detected_language = self._detect_script_language(filename)

        return {
            "filename": filename,
            "content": decoded_content,
            "language": declared_language or detected_language,
            "encoding": encoding,
            "file_hash": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "is_executable": self._is_executable_script(filename, decoded_content),
        }

    def _detect_script_language(self, filename: str) -> str:
        """根据文件名检测脚本语言"""
        ext_map = {
            ".py": "python",
            ".pyw": "python",
            ".sh": "shell",
            ".bash": "shell",
            ".zsh": "shell",
            ".js": "javascript",
            ".mjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".rb": "ruby",
            ".pl": "perl",
            ".php": "php",
            ".go": "go",
            ".rs": "rust",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
        }

        import os
        _, ext = os.path.splitext(filename.lower())
        return ext_map.get(ext, "unknown")

    def _is_executable_script(self, filename: str, content: str) -> bool:
        """判断是否为可执行脚本"""
        # 检查shebang
        if content.startswith("#!"):
            return True

        # 检查已知可执行文件扩展名
        executable_exts = {".py", ".sh", ".bash", ".js", ".rb", ".pl"}
        import os
        _, ext = os.path.splitext(filename.lower())
        return ext in executable_exts

    def detect_hidden_content(self, content: str) -> List[Dict[str, Any]]:
        """
        检测隐藏内容（零宽度字符、隐藏Unicode等）

        Args:
            content: 要检测的文本

        Returns:
            检测到的隐藏内容列表
        """
        findings = []

        # 零宽度字符模式
        zero_width_chars = [
            ("\u200b", "ZERO WIDTH SPACE"),
            ("\u200c", "ZERO WIDTH NON-JOINER"),
            ("\u200d", "ZERO WIDTH JOINER"),
            ("\ufeff", "ZERO WIDTH NO-BREAK SPACE (BOM)"),
            ("\u2028", "LINE SEPARATOR"),
            ("\u2029", "PARAGRAPH SEPARATOR"),
        ]

        for char, name in zero_width_chars:
            if char in content:
                positions = [i for i, c in enumerate(content) if c == char]
                findings.append({
                    "type": "zero_width_char",
                    "name": name,
                    "count": len(positions),
                    "positions": positions[:10],  # 只记录前10个位置
                })

        # HTML注释
        html_comment_pattern = re.compile(r"<!--[\s\S]*?-->")
        for match in html_comment_pattern.finditer(content):
            comment = match.group()
            if len(comment) > 100:  # 长注释可能隐藏指令
                findings.append({
                    "type": "long_html_comment",
                    "position": match.start(),
                    "length": len(comment),
                    "preview": comment[:100] + "...",
                })

        return findings
