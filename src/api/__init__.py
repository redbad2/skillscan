"""
REST API模块

提供API接口供外部系统调用。
"""

from src.api.app import create_app, app

__all__ = [
    "create_app",
    "app",
]
