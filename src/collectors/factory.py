"""
Factory for creating collector instances.

提供双通道收集器工厂，包括：
- DualCollector: 本地 + 网络双通道收集
- EnhancedDualCollector: 增强版，支持 Git 和文件监控
- TaskQueue: 任务队列管理
- Deduplicator: 跨通道去重
"""

import asyncio
import hashlib
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .base import BaseCollector, SkillSource
from .git_collector import GitCollector
from .local import LocalCollector
from .local_collector import LocalCollector as NewLocalCollector
from .network import NetworkCollector
from .network_collector import NetworkCollector as NewNetworkCollector
from .watcher import FileWatcher, SkillWatcher

logger = logging.getLogger(__name__)


class TaskPriority(int, Enum):
    """任务优先级"""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class CollectionTask:
    """收集任务"""

    task_id: str
    task_type: str  # "collect", "update", "delete"
    source: str  # "local", "network", "git"
    source_path: str  # URL 或文件路径
    priority: TaskPriority = TaskPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.utcnow)
    retry_count: int = 0
    max_retries: int = 3
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def priority_score(self) -> float:
        """计算优先级分数"""
        base_score = self.priority.value * 1000
        age_seconds = (datetime.utcnow() - self.created_at).total_seconds()
        age_factor = min(age_seconds / 3600, 1.0) * 100
        return base_score + age_factor


class TaskQueue:
    """任务队列管理器"""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._pending: deque[CollectionTask] = deque()
        self._processing: dict[str, CollectionTask] = {}
        self._completed: deque[CollectionTask] = deque(maxlen=1000)
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Condition(self._lock)

    async def enqueue(self, task: CollectionTask) -> bool:
        """入队任务"""
        async with self._lock:
            if len(self._pending) >= self.max_size:
                logger.warning(f"Task queue full, dropping task: {task.task_id}")
                return False

            self._pending.append(task)
            self._pending = deque(
                sorted(self._pending, key=lambda t: t.priority_score, reverse=True),
                maxlen=self.max_size,
            )
            self._not_empty.notify()
            return True

    async def dequeue(self) -> CollectionTask | None:
        """出队任务"""
        async with self._not_empty:
            while not self._pending:
                await self._not_empty.wait()

            task = self._pending.popleft()
            self._processing[task.task_id] = task
            return task

    async def mark_completed(self, task: CollectionTask) -> None:
        """标记任务完成"""
        async with self._lock:
            if task.task_id in self._processing:
                del self._processing[task.task_id]
            self._completed.append(task)

    async def mark_failed(self, task: CollectionTask, error: str) -> CollectionTask | None:
        """标记任务失败，可重试"""
        async with self._lock:
            if task.task_id in self._processing:
                del self._processing[task.task_id]

            task.retry_count += 1
            if task.retry_count < task.max_retries:
                logger.info(f"Retrying task {task.task_id} ({task.retry_count}/{task.max_retries})")
                self._pending.append(task)
                return None
            else:
                logger.error(f"Task {task.task_id} failed permanently: {error}")
                task.metadata["error"] = error
                self._completed.append(task)
                return None

    async def get_stats(self) -> dict[str, int]:
        """获取队列统计"""
        async with self._lock:
            return {
                "pending": len(self._pending),
                "processing": len(self._processing),
                "completed": len(self._completed),
            }


class Deduplicator:
    """跨通道去重器"""

    def __init__(self, max_cache_size: int = 10000):
        self.max_cache_size = max_cache_size
        self._content_hashes: set[str] = set()
        self._source_hashes: set[str] = set()
        self._lock = asyncio.Lock()
        self._stats = {"seen": 0, "duplicates": 0, "new": 0}

    async def check_and_add(self, skill: SkillSource) -> bool:
        """
        检查是否重复，如果是新内容则添加到缓存

        使用 content_hash 进行去重：相同内容（无论来源）视为重复
        source_hash 用于来源追踪，但不参与去重判断

        Returns:
            True 如果是重复，False 如果是新内容
        """
        async with self._lock:
            self._stats["seen"] += 1

            content_hash = skill.content_hash
            source_hash = self._compute_source_hash(skill)

            is_dup = content_hash in self._content_hashes

            if is_dup:
                self._stats["duplicates"] += 1
                return True

            self._add_to_cache(content_hash, source_hash)
            self._stats["new"] += 1
            return False

    def _compute_source_hash(self, skill: SkillSource) -> str:
        """计算来源哈希（用于来源去重）"""
        parts = [
            skill.name,
            skill.source_path,
            str(skill.file_size),
        ]
        combined = "|".join(parts)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32]

    def _add_to_cache(self, content_hash: str, source_hash: str) -> None:
        """添加到缓存，自动清理过期项"""
        self._content_hashes.add(content_hash)
        self._source_hashes.add(source_hash)

        total = len(self._content_hashes) + len(self._source_hashes)
        if total > self.max_cache_size:
            self._cleanup()

    def _cleanup(self) -> None:
        """清理一半缓存"""
        target_size = self.max_cache_size // 2
        current_size = len(self._content_hashes) + len(self._source_hashes)
        to_remove = current_size - target_size

        content_list = list(self._content_hashes)
        source_list = list(self._source_hashes)

        remove_from_content = min(to_remove // 2, len(content_list))
        remove_from_source = to_remove - remove_from_content

        if remove_from_content > 0:
            for h in content_list[:remove_from_content]:
                self._content_hashes.discard(h)
        if remove_from_source > 0:
            for h in source_list[:remove_from_source]:
                self._source_hashes.discard(h)

    async def get_stats(self) -> dict[str, Any]:
        """获取去重统计"""
        async with self._lock:
            return {
                **self._stats.copy(),
                "cache_size": len(self._content_hashes) + len(self._source_hashes),
            }

    async def clear(self) -> None:
        """清空缓存"""
        async with self._lock:
            self._content_hashes.clear()
            self._source_hashes.clear()
            self._stats = {"seen": 0, "duplicates": 0, "new": 0}


class CollectorFactory:
    """Factory for creating collector instances."""

    @staticmethod
    def create_collector(collector_type: str, **kwargs) -> BaseCollector:
        """Create a collector instance based on type."""

        collectors = {
            "network": NetworkCollector,
            "local": LocalCollector,
            "new_network": NewNetworkCollector,
            "new_local": NewLocalCollector,
            "git": GitCollector,
        }

        collector_class = collectors.get(collector_type)
        if not collector_class:
            raise ValueError(f"Unknown collector type: {collector_type}")

        return collector_class(**kwargs)

    @staticmethod
    def create_file_watcher(
        watch_paths: list[str | Any], local_collector: LocalCollector | None = None, **kwargs
    ) -> FileWatcher:
        """Create a file watcher instance."""
        return FileWatcher(watch_paths=watch_paths, **kwargs)

    @staticmethod
    def create_skill_watcher(
        watch_paths: list[str | Any], local_collector: LocalCollector, **kwargs
    ) -> SkillWatcher:
        """Create a skill watcher instance."""
        return SkillWatcher(watch_paths=watch_paths, local_collector=local_collector, **kwargs)

    @staticmethod
    def create_dual_collector(
        local_config: dict[str, Any] | None = None,
        network_config: dict[str, Any] | None = None,
    ) -> "DualCollector":
        """Create a dual collector that runs both local and network collectors."""

        local = LocalCollector(**(local_config or {}))
        network = NetworkCollector(**(network_config or {}))
        return DualCollector(local=local, network=network)

    @staticmethod
    def create_enhanced_dual_collector(
        local_config: dict[str, Any] | None = None,
        network_config: dict[str, Any] | None = None,
        git_config: dict[str, Any] | None = None,
        watch_paths: list[str] | None = None,
        db_manager=None,
    ) -> "EnhancedDualCollector":
        """Create an enhanced dual collector with Git and file watching support."""
        local = NewLocalCollector(**(local_config or {})) if local_config else None
        network = NewNetworkCollector(**(network_config or {})) if network_config else None
        git = GitCollector(db_manager=db_manager, **(git_config or {})) if git_config else None
        watcher = (
            SkillWatcher(watch_paths=watch_paths, local_collector=local)
            if watch_paths and local
            else None
        )

        return EnhancedDualCollector(
            local=local,
            network=network,
            git=git,
            watcher=watcher,
            db_manager=db_manager,
        )

        return DualCollector(local=local, network=network)


class DualCollector:
    """Collector that combines local and network collection."""

    def __init__(
        self,
        local: LocalCollector | None = None,
        network: NetworkCollector | None = None,
        use_enhanced_dedup: bool = True,
    ):
        self.local = local
        self.network = network
        self._deduplicator = Deduplicator() if use_enhanced_dedup else None
        self._seen_hashes = set() if not use_enhanced_dedup else None
        self.stats = {
            "local": {"total": 0, "success": 0, "failed": 0},
            "network": {"total": 0, "success": 0, "failed": 0},
            "combined": {"total": 0, "success": 0, "failed": 0, "duplicates": 0},
        }

    async def test_connection(self) -> dict[str, bool]:
        """Test connections for all configured collectors."""
        results = {}

        if self.local:
            results["local"] = await self.local.test_connection()

        if self.network:
            results["network"] = await self.network.test_connection()

        return results

    async def collect_all(self, **kwargs):
        """Collect from all configured channels."""

        async def process_skill(skill, channel: str):
            self.stats["combined"]["total"] += 1

            if self._deduplicator:
                is_dup = await self._deduplicator.check_and_add(skill)
            else:
                content_hash = self._calculate_hash(skill)
                is_dup = content_hash in self._seen_hashes
                if not is_dup:
                    self._seen_hashes.add(content_hash)

            if is_dup:
                self.stats["combined"]["duplicates"] += 1
                return None

            self.stats["combined"]["success"] += 1
            self.stats[channel]["success"] += 1
            return skill, channel

        tasks = []

        if self.local:
            local_task = self._collect_from_local(**kwargs)
            tasks.append(self._run_channel(local_task, "local"))

        if self.network:
            network_task = self._collect_from_network(**kwargs)
            tasks.append(self._run_channel(network_task, "network"))

        for results in asyncio.as_completed(tasks):
            async for item in await results:
                if item:
                    yield item

    async def _run_channel(self, channel_coro, channel: str):
        """运行单个通道的收集协程"""
        try:
            async for skill in channel_coro:
                yield skill, channel
        except Exception as e:
            logger.error(f"Error in {channel} collection: {e}")
            self.stats[channel]["failed"] += 1

    async def _collect_from_local(self, **kwargs):
        """从本地收集"""
        if self.local:
            async for skill in self.local.collect(**kwargs):
                yield skill

    async def _collect_from_network(self, **kwargs):
        """从网络收集"""
        if self.network:
            async with self.network:
                async for skill in self.network.collect(**kwargs):
                    yield skill

    async def collect_local_only(self, **kwargs):
        """Collect only from local sources."""
        if self.local:
            async for skill in self.local.collect(**kwargs):
                yield skill

    async def collect_network_only(self, **kwargs):
        """Collect only from network sources."""
        if self.network:
            async with self.network:
                async for skill in self.network.collect(**kwargs):
                    yield skill

    def _calculate_hash(self, skill) -> str:
        """Calculate content hash for deduplication."""
        content_parts = [
            skill.name,
            skill.version,
            skill.skill_md_content or "",
        ]
        combined = "\n".join(content_parts)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    async def get_full_stats(self) -> dict[str, Any]:
        """Get full collection statistics including deduplicator stats."""
        stats = self.get_stats()
        if self._deduplicator:
            stats["deduplicator"] = await self._deduplicator.get_stats()
        return stats

    def get_stats(self) -> dict[str, Any]:
        """Get collection statistics."""
        stats = {k: v.copy() for k, v in self.stats.items()}

        if self.local:
            stats["local"].update(self.local.get_stats())

        if self.network:
            stats["network"].update(self.network.get_stats())

        return stats

    async def clear_dedup_cache(self) -> None:
        """清除去重缓存"""
        if self._deduplicator:
            await self._deduplicator.clear()
        if self._seen_hashes is not None:
            self._seen_hashes.clear()


class EnhancedDualCollector:
    """
    增强版双通道收集器

    支持：
    - 本地文件系统扫描
    - Git 仓库克隆和更新
    - 文件系统实时监控
    - 跨通道任务队列
    - 增强的去重
    """

    def __init__(
        self,
        local: NewLocalCollector | None = None,
        network: NewNetworkCollector | None = None,
        git: GitCollector | None = None,
        watcher: SkillWatcher | None = None,
        db_manager=None,
        task_queue: TaskQueue | None = None,
        deduplicator: Deduplicator | None = None,
    ):
        self.local = local
        self.network = network
        self.git = git
        self.watcher = watcher
        self.db_manager = db_manager
        self._task_queue = task_queue or TaskQueue()
        self._deduplicator = deduplicator or Deduplicator()
        self._running = False
        self._watch_task = None

        self.stats = {
            "local": {"total": 0, "success": 0, "failed": 0},
            "network": {"total": 0, "success": 0, "failed": 0},
            "git": {"total": 0, "success": 0, "failed": 0},
            "watch": {"events": 0, "skills_added": 0, "skills_modified": 0},
            "combined": {"total": 0, "success": 0, "failed": 0, "duplicates": 0},
        }

    async def test_connection(self) -> dict[str, bool]:
        """Test connections for all configured collectors."""
        results = {}

        if self.local:
            results["local"] = await self.local.test_connection()

        if self.network:
            results["network"] = await self.network.test_connection()

        if self.git:
            results["git"] = True

        return results

    async def collect_all(
        self,
        repo_urls: list[str] | None = None,
        **kwargs,
    ):
        """
        从所有通道收集技能

        Args:
            repo_urls: Git 仓库 URL 列表
            **kwargs: 其他参数
        """
        tasks = []

        if self.local:
            tasks.append(self._collect_local(**kwargs))

        if self.network:
            tasks.append(self._collect_network(**kwargs))

        if self.git and repo_urls:
            tasks.append(self._collect_git_repos(repo_urls))

        for coro in asyncio.as_completed(tasks):
            try:
                async for skill, channel in await coro:
                    yield skill, channel
            except Exception as e:
                logger.error(f"Collection task error: {e}")

    async def _collect_local(self, **kwargs):
        """从本地收集"""
        if not self.local:
            return

        try:
            async for skill in self.local.collect(**kwargs):
                if await self._deduplicator.check_and_add(skill):
                    self.stats["combined"]["duplicates"] += 1
                    continue

                self.stats["local"]["success"] += 1
                self.stats["combined"]["success"] += 1
                yield skill, "local"
        except Exception as e:
            logger.error(f"Local collection error: {e}")
            self.stats["local"]["failed"] += 1

    async def _collect_network(self, **kwargs):
        """从网络收集"""
        if not self.network:
            return

        try:
            async with self.network:
                async for skill in self.network.collect(**kwargs):
                    if await self._deduplicator.check_and_add(skill):
                        self.stats["combined"]["duplicates"] += 1
                        continue

                    self.stats["network"]["success"] += 1
                    self.stats["combined"]["success"] += 1
                    yield skill, "network"
        except Exception as e:
            logger.error(f"Network collection error: {e}")
            self.stats["network"]["failed"] += 1

    async def _collect_git_repos(self, repo_urls: list[str]):
        """从 Git 仓库收集"""
        if not self.git:
            return

        for repo_url in repo_urls:
            try:
                skills = await self.git.collect(repo_url)
                for skill in skills:
                    self.stats["git"]["total"] += 1

                    if await self._deduplicator.check_and_add(skill):
                        self.stats["combined"]["duplicates"] += 1
                        continue

                    self.stats["git"]["success"] += 1
                    self.stats["combined"]["success"] += 1
                    yield skill, "git"
            except Exception as e:
                logger.error(f"Git collection error for {repo_url}: {e}")
                self.stats["git"]["failed"] += 1

    async def start_watching(self) -> None:
        """启动文件监控"""
        if not self.watcher:
            return

        self._running = True

        if self.watcher.on_skill_added:
            original_cb = self.watcher.on_skill_added

            async def wrapped_added(skill):
                if not await self._deduplicator.check_and_add(skill):
                    self.stats["watch"]["skills_added"] += 1
                    await original_cb(skill)
                else:
                    logger.debug(f"Skipping duplicate from watch: {skill.name}")

            self.watcher.on_skill_added = wrapped_added

        if self.watcher.on_skill_modified:
            original_cb = self.watcher.on_skill_modified

            async def wrapped_modified(skill):
                self.stats["watch"]["skills_modified"] += 1
                await original_cb(skill)

            self.watcher.on_skill_modified = wrapped_modified

        self._watch_task = asyncio.create_task(self.watcher.start())

    async def stop_watching(self) -> None:
        """停止文件监控"""
        self._running = False
        if self.watcher:
            await self.watcher.stop()
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass

    async def queue_task(self, task: CollectionTask) -> bool:
        """添加入队任务"""
        return await self._task_queue.enqueue(task)

    async def process_queue(self) -> None:
        """处理任务队列"""
        while self._running:
            task = await self._task_queue.dequeue()

            try:
                if task.task_type == "collect":
                    await self._process_collect_task(task)
                elif task.task_type == "update":
                    await self._process_update_task(task)
                elif task.task_type == "delete":
                    await self._process_delete_task(task)

                await self._task_queue.mark_completed(task)

            except Exception as e:
                logger.error(f"Task {task.task_id} failed: {e}")
                await self._task_queue.mark_failed(task, str(e))

    async def _process_collect_task(self, task: CollectionTask) -> None:
        """处理收集任务"""
        if task.source == "git":
            skills = await self.git.collect(task.source_path) if self.git else []
        elif task.source == "local":
            skills = await self.local.collect() if self.local else []
        else:
            return

        for skill in skills:
            if not await self._deduplicator.check_and_add(skill):
                if self.db_manager:
                    await self.db_manager.insert_one("skills", skill)

    async def _process_update_task(self, task: CollectionTask) -> None:
        """处理更新任务"""
        if task.source == "git" and self.git:
            dest_path = self.git.clone_dir / self.git._get_repo_name(task.source_path)
            if dest_path.exists():
                await self.git._pull_repository(dest_path)

    async def _process_delete_task(self, task: CollectionTask) -> None:
        """处理删除任务"""
        if self.db_manager:
            await self.db_manager.delete_one("skills", {"source_path": task.source_path})

    async def get_full_stats(self) -> dict[str, Any]:
        """获取完整统计信息"""
        stats = {k: v.copy() for k, v in self.stats.items()}
        stats["task_queue"] = await self._task_queue.get_stats()
        stats["deduplicator"] = await self._deduplicator.get_stats()
        return stats

    def get_stats(self) -> dict[str, Any]:
        """获取收集统计"""
        return {k: v.copy() for k, v in self.stats.items()}

    async def clear_dedup_cache(self) -> None:
        """清除去重缓存"""
        await self._deduplicator.clear()

    async def shutdown(self) -> None:
        """关闭收集器"""
        self._running = False
        await self.stop_watching()
