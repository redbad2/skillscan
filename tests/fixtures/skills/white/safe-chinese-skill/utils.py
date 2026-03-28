"""
安全的中文工具模块

提供文件分析和统计功能。
"""

import os
from pathlib import Path
from typing import Dict, List, Optional


def analyze_file(file_path: str) -> Dict:
    """
    分析文件内容，返回统计信息。

    参数:
        file_path: 要分析的文件路径

    返回:
        包含分析结果的字典
    """
    result = {
        "path": file_path,
        "exists": False,
        "size": 0,
        "lines": 0,
        "words": 0,
        "extension": "",
    }

    path = Path(file_path)
    if not path.exists():
        return result

    result["exists"] = True
    result["size"] = path.stat().st_size
    result["extension"] = path.suffix

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            result["lines"] = content.count("\n") + 1
            result["words"] = len(content.split())
    except UnicodeDecodeError:
        # 二进制文件，只统计基本信息
        pass

    return result


def format_report(results: List[Dict], title: str = "分析报告") -> str:
    """
    格式化分析报告。

    参数:
        results: 分析结果列表
        title: 报告标题

    返回:
        格式化后的报告字符串
    """
    lines = ["=" * 50, f"{title}", "=" * 50, ""]

    total_size = 0
    total_files = len(results)

    for r in results:
        if r["exists"]:
            total_size += r["size"]
            lines.append(f"文件: {r['path']}")
            lines.append(f"  大小: {r['size']} 字节")
            lines.append(f"  行数: {r['lines']}")
            lines.append(f"  扩展名: {r['extension']}")
            lines.append("")

    lines.append("-" * 50)
    lines.append(f"总计: {total_files} 个文件")
    lines.append(f"总大小: {total_size} 字节")

    return "\n".join(lines)


def list_directory(directory: str, recursive: bool = False) -> List[str]:
    """
    列出目录中的文件。

    参数:
        directory: 目录路径
        recursive: 是否递归列出子目录

    返回:
        文件路径列表
    """
    files = []
    path = Path(directory)

    if not path.exists():
        return files

    pattern = "**/*" if recursive else "*"
    for item in path.glob(pattern):
        if item.is_file():
            files.append(str(item))

    return sorted(files)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        result = analyze_file(sys.argv[1])
        print(f"文件: {result['path']}")
        print(f"大小: {result['size']} 字节")
        print(f"行数: {result['lines']}")
    else:
        print("用法: python utils.py <文件路径>")
