"""
监控和日志模块

提供结构化日志、性能指标和健康检查功能。
"""

import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import json

from loguru import logger


class MetricType(str, Enum):
    """指标类型"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """指标数据"""

    name: str
    value: float
    metric_type: MetricType
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class MetricsCollector:
    """指标收集器"""

    def __init__(self):
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._start_times: Dict[str, float] = {}

    def increment(self, name: str, value: float = 1, tags: Optional[Dict[str, str]] = None):
        """
        增加计数器

        Args:
            name: 指标名称
            value: 增加的值
            tags: 标签
        """
        key = self._make_key(name, tags)
        self._counters[key] += value
        logger.debug(f"Counter {name} incremented to {self._counters[key]}")

    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """
        设置仪表值

        Args:
            name: 指标名称
            value: 值
            tags: 标签
        """
        key = self._make_key(name, tags)
        self._gauges[key] = value
        logger.debug(f"Gauge {name} set to {value}")

    def observe(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """
        记录观测值

        Args:
            name: 指标名称
            value: 观测值
            tags: 标签
        """
        key = self._make_key(name, tags)
        self._histograms[key].append(value)
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-1000:]

    def start_timer(self, name: str, tags: Optional[Dict[str, str]] = None):
        """
        开始计时

        Args:
            name: 指标名称
            tags: 标签
        """
        key = self._make_key(name, tags)
        self._start_times[key] = time.time()

    def stop_timer(self, name: str, tags: Optional[Dict[str, str]] = None):
        """
        停止计时并记录

        Args:
            name: 指标名称
            tags: 标签
        """
        key = self._make_key(name, tags)
        if key in self._start_times:
            duration = time.time() - self._start_times[key]
            self._timers[key].append(duration)
            del self._start_times[key]

            if len(self._timers[key]) > 1000:
                self._timers[key] = self._timers[key][-1000:]

            logger.debug(f"Timer {name} recorded {duration:.4f}s")
            return duration
        return None

    def _make_key(self, name: str, tags: Optional[Dict[str, str]]) -> str:
        """生成指标键"""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"

    def get_metrics(self) -> Dict[str, Any]:
        """
        获取所有指标

        Returns:
            指标数据
        """
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: {
                    "count": len(v),
                    "min": min(v) if v else 0,
                    "max": max(v) if v else 0,
                    "mean": sum(v) / len(v) if v else 0,
                    "p50": self._percentile(v, 0.5),
                    "p95": self._percentile(v, 0.95),
                    "p99": self._percentile(v, 0.99),
                }
                for k, v in self._histograms.items()
            },
            "timers": {
                k: {
                    "count": len(v),
                    "min": min(v) if v else 0,
                    "max": max(v) if v else 0,
                    "mean": sum(v) / len(v) if v else 0,
                    "p50": self._percentile(v, 0.5),
                    "p95": self._percentile(v, 0.95),
                    "p99": self._percentile(v, 0.99),
                }
                for k, v in self._timers.items()
            },
        }

    def _percentile(self, values: List[float], percentile: float) -> float:
        """计算百分位数"""
        if not values:
            return 0
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile)
        return sorted_values[min(index, len(sorted_values) - 1)]

    def reset(self):
        """重置所有指标"""
        self._counters.clear()
        self._gauges.clear()
        self._histograms.clear()
        self._timers.clear()
        self._start_times.clear()


class OperationLogger:
    """操作日志记录器"""

    def __init__(self):
        self._operations: List[Dict[str, Any]] = []
        self._max_operations = 10000

    def log_operation(
        self,
        operation: str,
        status: str,
        duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        记录操作

        Args:
            operation: 操作名称
            status: 操作状态 (success/failed/pending)
            duration: 持续时间(秒)
            metadata: 额外元数据
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "status": status,
            "duration": duration,
            "metadata": metadata or {},
        }

        self._operations.append(entry)

        if len(self._operations) > self._max_operations:
            self._operations = self._operations[-self._max_operations :]

        log_level = "info" if status == "success" else "error" if status == "failed" else "warning"
        getattr(logger, log_level)(
            f"Operation: {operation}, Status: {status}, Duration: {duration:.4f}s"
        )

    def get_operations(
        self,
        operation: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        获取操作记录

        Args:
            operation: 过滤操作名称
            status: 过滤状态
            since: 过滤时间
            limit: 返回数量限制

        Returns:
            操作记录列表
        """
        results = self._operations

        if operation:
            results = [r for r in results if r["operation"] == operation]

        if status:
            results = [r for r in results if r["status"] == status]

        if since:
            results = [r for r in results if datetime.fromisoformat(r["timestamp"]) >= since]

        return results[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取操作统计

        Returns:
            统计数据
        """
        if not self._operations:
            return {
                "total": 0,
                "by_status": {},
                "avg_duration": 0,
            }

        by_status = defaultdict(int)
        total_duration = 0
        duration_count = 0

        for op in self._operations:
            by_status[op["status"]] += 1
            if op.get("duration"):
                total_duration += op["duration"]
                duration_count += 1

        return {
            "total": len(self._operations),
            "by_status": dict(by_status),
            "avg_duration": total_duration / duration_count if duration_count > 0 else 0,
            "success_rate": by_status.get("success", 0) / len(self._operations) * 100,
        }


metrics_collector = MetricsCollector()
operation_logger = OperationLogger()


class MonitoredOperation:
    """监控操作上下文管理器"""

    def __init__(self, operation: str, tags: Optional[Dict[str, str]] = None):
        self.operation = operation
        self.tags = tags or {}
        self.start_time = None
        self.error = None

    def __enter__(self):
        self.start_time = time.time()
        metrics_collector.start_timer(self.operation, self.tags)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        metrics_collector.stop_timer(self.operation, self.tags)

        if exc_type is None:
            operation_logger.log_operation(
                self.operation,
                "success",
                duration,
                self.tags,
            )
            metrics_collector.increment(f"{self.operation}.success", 1, self.tags)
        else:
            self.error = str(exc_val)
            operation_logger.log_operation(
                self.operation,
                "failed",
                duration,
                {**self.tags, "error": self.error},
            )
            metrics_collector.increment(f"{self.operation}.failed", 1, self.tags)

        return False


def log_scan_start(skill_id: str, scan_type: str):
    """记录扫描开始"""
    operation_logger.log_operation(
        "scan",
        "pending",
        metadata={"skill_id": skill_id, "scan_type": scan_type},
    )
    metrics_collector.increment("scan.started", tags={"type": scan_type})


def log_scan_complete(
    skill_id: str,
    vulnerabilities: int,
    duration: float,
    risk_level: str,
):
    """记录扫描完成"""
    operation_logger.log_operation(
        "scan",
        "success",
        duration,
        {
            "skill_id": skill_id,
            "vulnerabilities": vulnerabilities,
            "risk_level": risk_level,
        },
    )
    metrics_collector.increment("scan.completed")
    metrics_collector.observe("scan.vulnerabilities", vulnerabilities)
    metrics_collector.set_gauge(
        "scan.last_risk_level",
        {"safe": 0, "warning": 1, "dangerous": 2, "malicious": 3}.get(risk_level, 0),
    )


def log_scan_failed(skill_id: str, error: str, duration: float):
    """记录扫描失败"""
    operation_logger.log_operation(
        "scan",
        "failed",
        duration,
        {"skill_id": skill_id, "error": error},
    )
    metrics_collector.increment("scan.failed")
