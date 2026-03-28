"""
报告生成模块

生成安全扫描报告，支持多种格式（JSON、HTML、Markdown）。
"""

from src.reporters.report_generator import ReportGenerator

__all__ = [
    "ReportGenerator",
]
