"""
文件预处理模块

负责技能文件的预处理，包括语言检测、编码标准化、元数据提取。
"""

from src.preprocessors.file_processor import FileProcessor, LanguageDetector

__all__ = [
    "FileProcessor",
    "LanguageDetector",
]
