"""
Safe file scanner utility.

This module provides functionality to scan directories for files
and generate summary reports.
"""

import os
from pathlib import Path
from typing import List, Dict, Optional


def scan(directory: str, extension: Optional[str] = None) -> Dict:
    """
    Scan directory for files.

    Args:
        directory: Path to the directory to scan
        extension: Optional file extension filter (e.g., '.py')

    Returns:
        Dictionary containing scan results with file list and count
    """
    results = {"files": [], "count": 0, "directory": directory}

    target_dir = Path(directory)
    if not target_dir.exists():
        return results

    for item in target_dir.rglob("*"):
        if item.is_file():
            if extension is None or item.suffix == extension:
                results["files"].append(
                    {"path": str(item), "name": item.name, "size": item.stat().st_size}
                )
                results["count"] += 1

    return results


def count_by_extension(directory: str) -> Dict[str, int]:
    """
    Count files by extension in a directory.

    Args:
        directory: Path to the directory to analyze

    Returns:
        Dictionary mapping extensions to counts
    """
    extension_counts = {}

    for item in Path(directory).rglob("*"):
        if item.is_file():
            ext = item.suffix or "(no extension)"
            extension_counts[ext] = extension_counts.get(ext, 0) + 1

    return extension_counts


def get_total_size(directory: str) -> int:
    """
    Calculate total size of all files in directory.

    Args:
        directory: Path to the directory

    Returns:
        Total size in bytes
    """
    total = 0
    for item in Path(directory).rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        results = scan(sys.argv[1])
        print(f"Found {results['count']} files")
    else:
        print("Usage: python scanner.py <directory>")
