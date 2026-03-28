"""
数据收集模块

支持双通道数据收集：
- 网络爬取：从多个平台爬取技能文件
- 本地读取：递归扫描本地目录
"""

from src.collectors.base import BaseCollector, SkillSource
from src.collectors.local_collector import LocalCollector
from src.collectors.network_collector import NetworkCollector

__all__ = [
    "BaseCollector",
    "SkillSource",
    "LocalCollector",
    "NetworkCollector",
]
