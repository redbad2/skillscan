"""
基础收集器模块

定义数据收集器的通用接口和数据结构。
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import hashlib


class SourceChannel(str, Enum):
    """数据来源通道"""
    NETWORK_CRAWL = "network_crawl"
    LOCAL_SCAN = "local_scan"


@dataclass
class SkillSource:
    """技能数据源"""
    name: str
    content: str  # SKILL.md内容
    scripts: List[Dict[str, str]] = field(default_factory=list)  # 脚本文件列表
    source_path: str = ""  # 来源路径或URL
    platform: str = "unknown"
    channel: SourceChannel = SourceChannel.LOCAL_SCAN
    file_size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def content_hash(self) -> str:
        """计算内容哈希"""
        hasher = hashlib.sha256()
        hasher.update(self.content.encode("utf-8"))
        for script in sorted(self.scripts, key=lambda x: x.get("filename", "")):
            hasher.update(script.get("content", "").encode("utf-8"))
        return hasher.hexdigest()

    @property
    def script_hashes(self) -> List[str]:
        """计算脚本文件哈希列表"""
        hashes = []
        for script in self.scripts:
            hasher = hashlib.sha256()
            hasher.update(script.get("content", "").encode("utf-8"))
            hashes.append(hasher.hexdigest())
        return hashes


class BaseCollector(ABC):
    """基础收集器抽象类"""

    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self._stats = {
            "collected": 0,
            "duplicates": 0,
            "errors": 0,
        }

    @property
    @abstractmethod
    def name(self) -> str:
        """收集器名称"""
        pass

    @property
    @abstractmethod
    def channel(self) -> SourceChannel:
        """数据来源通道"""
        pass

    @abstractmethod
    async def collect(self, limit: Optional[int] = None) -> List[SkillSource]:
        """执行收集，返回技能列表"""
        pass

    @abstractmethod
    async def validate_source(self, source: SkillSource) -> bool:
        """验证数据源有效性"""
        pass

    async def is_duplicate(self, source: SkillSource) -> bool:
        """检查是否重复"""
        if not self.db_manager:
            return False

        existing = await self.db_manager.find_one(
            "skills",
            {"files.scripts.file_hash": {"$in": source.script_hashes}},
        )
        return existing is not None

    async def save(self, source: SkillSource) -> Optional[str]:
        """保存技能到数据库"""
        if not self.db_manager:
            return None

        skill_doc = self._create_skill_document(source)
        return await self.db_manager.insert_one("skills", skill_doc)

    def _create_skill_document(self, source: SkillSource) -> Dict[str, Any]:
        """创建技能文档"""
        return {
            "skill_id": source.content_hash[:16],
            "name": source.name,
            "version": source.metadata.get("version", "1.0.0"),
            "source": "network" if self.channel == SourceChannel.NETWORK_CRAWL else "local",
            "platform": source.platform,
            "language": "unknown",  # 将在预处理阶段检测
            "metadata": {
                "author": source.metadata.get("author"),
                "description": source.metadata.get("description"),
                "permissions": source.metadata.get("permissions", []),
                "triggers": source.metadata.get("triggers", []),
                "created_at": source.collected_at,
                "updated_at": source.collected_at,
                "tags": source.metadata.get("tags", []),
            },
            "files": {
                "skill_md": source.content,
                "scripts": [
                    {
                        "filename": s.get("filename", ""),
                        "content": s.get("content", ""),
                        "language": s.get("language", "unknown"),
                        "file_hash": hashlib.sha256(s.get("content", "").encode()).hexdigest(),
                        "size": len(s.get("content", "").encode()),
                    }
                    for s in source.scripts
                ],
            },
            "scan_status": "pending",
            "scan_result": {
                "scan_time": None,
                "status": "pending",
                "vulnerabilities": [],
                "risk_score": 0.0,
                "risk_level": "safe",
                "scan_duration_ms": 0,
                "scanner_version": "1.0.0",
            },
            "collection_info": {
                "channel": self.channel.value,
                "collected_at": source.collected_at,
                "original_path": source.source_path,
                "file_size": source.file_size,
            },
            "created_at": source.collected_at,
            "updated_at": source.collected_at,
        }

    @property
    def stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return self._stats.copy()

    def reset_stats(self) -> None:
        """重置统计信息"""
        self._stats = {"collected": 0, "duplicates": 0, "errors": 0}
