"""
测试收集器工厂和双通道收集器
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.collectors.factory import (
    CollectorFactory,
    DualCollector,
    EnhancedDualCollector,
    TaskQueue,
    Deduplicator,
    CollectionTask,
    TaskPriority,
)
from src.collectors.base import SkillSource, SourceChannel


class TestTaskQueue:
    """测试任务队列"""

    @pytest.fixture
    def task_queue(self):
        return TaskQueue(max_size=10)

    def test_sync_enqueue_dequeue(self, task_queue):
        """测试入队和出队（同步测试）"""
        task = CollectionTask(
            task_id="task-1",
            task_type="collect",
            source="local",
            source_path="/path/to/skills",
        )

        result = asyncio.run(task_queue.enqueue(task))
        assert result is True

        dequeued = asyncio.run(task_queue.dequeue())
        assert dequeued.task_id == "task-1"

    def test_sync_priority_ordering(self, task_queue):
        """测试优先级排序"""
        low_task = CollectionTask(
            task_id="low",
            task_type="collect",
            source="local",
            source_path="/low",
            priority=TaskPriority.LOW,
        )
        high_task = CollectionTask(
            task_id="high",
            task_type="collect",
            source="local",
            source_path="/high",
            priority=TaskPriority.HIGH,
        )

        asyncio.run(task_queue.enqueue(low_task))
        asyncio.run(task_queue.enqueue(high_task))

        first = asyncio.run(task_queue.dequeue())
        assert first.task_id == "high"

    def test_sync_mark_completed(self, task_queue):
        """测试标记完成"""
        task = CollectionTask(
            task_id="task-1",
            task_type="collect",
            source="local",
            source_path="/path",
        )

        asyncio.run(task_queue.enqueue(task))
        dequeued = asyncio.run(task_queue.dequeue())
        asyncio.run(task_queue.mark_completed(dequeued))

        stats = asyncio.run(task_queue.get_stats())
        assert stats["completed"] == 1
        assert stats["processing"] == 0

    def test_sync_mark_failed_with_retry(self, task_queue):
        """测试失败重试"""
        task = CollectionTask(
            task_id="task-1",
            task_type="collect",
            source="local",
            source_path="/path",
            max_retries=3,
        )

        asyncio.run(task_queue.enqueue(task))

        for i in range(3):
            dequeued = asyncio.run(task_queue.dequeue())
            asyncio.run(task_queue.mark_failed(dequeued, "Test error"))

        stats = asyncio.run(task_queue.get_stats())
        assert stats["pending"] == 0
        assert stats["completed"] == 1

    def test_sync_queue_full(self, task_queue):
        """测试队列满时拒绝任务"""
        for i in range(10):
            task = CollectionTask(
                task_id=f"task-{i}",
                task_type="collect",
                source="local",
                source_path=f"/path-{i}",
            )
            asyncio.run(task_queue.enqueue(task))

        extra_task = CollectionTask(
            task_id="extra",
            task_type="collect",
            source="local",
            source_path="/extra",
        )
        result = asyncio.run(task_queue.enqueue(extra_task))
        assert result is False


class TestDeduplicator:
    """测试去重器"""

    @pytest.fixture
    def deduplicator(self):
        return Deduplicator(max_cache_size=100)

    @pytest.fixture
    def sample_skill(self):
        return SkillSource(
            name="test-skill",
            content="# Test Skill Content",
            source_path="/path/to/skill",
            platform="local",
            channel=SourceChannel.LOCAL_SCAN,
        )

    def test_sync_new_content_not_duplicate(self, deduplicator, sample_skill):
        """测试新内容不是重复"""
        is_dup = asyncio.run(deduplicator.check_and_add(sample_skill))
        assert is_dup is False

        stats = asyncio.run(deduplicator.get_stats())
        assert stats["new"] == 1
        assert stats["duplicates"] == 0

    def test_sync_duplicate_content(self, deduplicator, sample_skill):
        """测试重复内容"""
        asyncio.run(deduplicator.check_and_add(sample_skill))
        is_dup = asyncio.run(deduplicator.check_and_add(sample_skill))

        assert is_dup is True

        stats = asyncio.run(deduplicator.get_stats())
        assert stats["duplicates"] == 1

    def test_sync_different_source_same_content(self, deduplicator, sample_skill):
        """测试不同来源相同内容（按来源哈希去重）"""
        asyncio.run(deduplicator.check_and_add(sample_skill))

        sample_skill.source_path = "/different/path"
        is_dup = asyncio.run(deduplicator.check_and_add(sample_skill))

        assert is_dup is True

    def test_sync_same_source_different_content(self, deduplicator, sample_skill):
        """测试相同来源不同内容"""
        asyncio.run(deduplicator.check_and_add(sample_skill))

        sample_skill.content = "# Different Content"
        is_dup = asyncio.run(deduplicator.check_and_add(sample_skill))

        assert is_dup is False

    def test_sync_clear_cache(self, deduplicator, sample_skill):
        """测试清空缓存"""
        asyncio.run(deduplicator.check_and_add(sample_skill))
        asyncio.run(deduplicator.clear())

        is_dup = asyncio.run(deduplicator.check_and_add(sample_skill))
        assert is_dup is False


class TestDualCollector:
    """测试双通道收集器"""

    @pytest.fixture
    def mock_local_collector(self):
        collector = MagicMock()
        collector.test_connection = AsyncMock(return_value=True)
        collector.get_stats = MagicMock(return_value={})
        return collector

    @pytest.fixture
    def mock_network_collector(self):
        collector = MagicMock()
        collector.test_connection = AsyncMock(return_value=True)
        collector.get_stats = MagicMock(return_value={})
        return collector

    def test_test_connection(self, mock_local_collector, mock_network_collector):
        """测试连接测试"""
        collector = DualCollector(
            local=mock_local_collector,
            network=mock_network_collector,
        )

        results = asyncio.run(collector.test_connection())
        assert results["local"] is True
        assert results["network"] is True

    def test_test_connection_local_only(self, mock_local_collector):
        """测试仅本地连接"""
        collector = DualCollector(local=mock_local_collector, network=None)

        results = asyncio.run(collector.test_connection())
        assert results["local"] is True
        assert "network" not in results


class TestEnhancedDualCollector:
    """测试增强版双通道收集器"""

    @pytest.fixture
    def mock_local(self):
        collector = MagicMock()
        collector.test_connection = AsyncMock(return_value=True)
        collector.get_stats = MagicMock(return_value={})
        return collector

    @pytest.fixture
    def mock_git(self):
        return MagicMock()

    def test_test_connection_all_channels(self, mock_local, mock_git):
        """测试所有通道的连接测试"""
        collector = EnhancedDualCollector(
            local=mock_local,
            git=mock_git,
        )

        results = asyncio.run(collector.test_connection())
        assert results["local"] is True
        assert results["git"] is True

    def test_get_full_stats(self, mock_local):
        """测试获取完整统计"""
        collector = EnhancedDualCollector(local=mock_local)

        stats = asyncio.run(collector.get_full_stats())
        assert "local" in stats
        assert "git" in stats
        assert "task_queue" in stats
        assert "deduplicator" in stats

    def test_clear_dedup_cache(self):
        """测试清除去重缓存"""
        collector = EnhancedDualCollector()

        skill = SkillSource(
            name="test",
            content="# Test",
            source_path="/test",
            platform="local",
            channel=SourceChannel.LOCAL_SCAN,
        )

        asyncio.run(collector._deduplicator.check_and_add(skill))
        asyncio.run(collector.clear_dedup_cache())

        stats = asyncio.run(collector._deduplicator.get_stats())
        assert stats["new"] == 0

    def test_queue_task(self):
        """测试添加入队任务"""
        collector = EnhancedDualCollector()

        task = CollectionTask(
            task_id="test-task",
            task_type="collect",
            source="local",
            source_path="/skills",
        )

        result = asyncio.run(collector.queue_task(task))
        assert result is True

        queue_stats = asyncio.run(collector._task_queue.get_stats())
        assert queue_stats["pending"] == 1

    def test_shutdown(self, mock_local):
        """测试关闭收集器"""
        collector = EnhancedDualCollector(local=mock_local)
        collector._running = True

        asyncio.run(collector.shutdown())

        assert collector._running is False


class TestCollectorFactory:
    """测试收集器工厂"""

    def test_create_collector_git(self):
        """测试创建 Git 收集器"""
        collector = CollectorFactory.create_collector("git")
        assert collector is not None
        assert collector.name == "git_collector"

    def test_create_collector_unknown_type(self):
        """测试创建未知类型收集器"""
        with pytest.raises(ValueError, match="Unknown collector type"):
            CollectorFactory.create_collector("unknown_type")

    def test_create_enhanced_dual_collector(self):
        """测试创建增强版双通道收集器"""
        collector = CollectorFactory.create_enhanced_dual_collector(
            local_config={},
            git_config={},
            watch_paths=["/path/to/skills"],
        )
        assert collector is not None
        assert isinstance(collector, EnhancedDualCollector)

    def test_create_skill_watcher_requires_local(self):
        """测试 SkillWatcher 需要 local collector"""
        with pytest.raises(TypeError):
            CollectorFactory.create_skill_watcher(watch_paths=["/path"])
