"""
Webhook回调模块

管理扫描完成后的回调通知。
"""

import asyncio
import hashlib
import time
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
import httpx

from loguru import logger


class WebhookEvent(str, Enum):
    """Webhook事件类型"""

    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SKILL_DETECTED = "skill.detected"
    VULNERABILITY_FOUND = "vulnerability.found"
    HIGH_RISK_DETECTED = "high_risk.detected"
    MALICIOUS_DETECTED = "malicious.detected"


class WebhookManager:
    """Webhook管理器"""

    def __init__(self):
        self._webhooks: Dict[str, Dict[str, Any]] = {}
        self._event_handlers: Dict[str, List[Callable]] = {
            event.value: [] for event in WebhookEvent
        }
        self._retry_queue: List[Dict[str, Any]] = []
        self._max_retries = 3
        self._retry_delay = 5

    def register_webhook(
        self,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        注册Webhook

        Args:
            url: Webhook回调URL
            events: 订阅的事件列表
            secret: 用于签名的密钥
            headers: 自定义请求头

        Returns:
            Webhook ID
        """
        webhook_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:16]

        self._webhooks[webhook_id] = {
            "id": webhook_id,
            "url": url,
            "events": events,
            "secret": secret,
            "headers": headers or {},
            "created_at": datetime.utcnow().isoformat(),
            "status": "active",
            "success_count": 0,
            "failure_count": 0,
        }

        logger.info(f"Registered webhook {webhook_id} for URL: {url}")
        return webhook_id

    def unregister_webhook(self, webhook_id: str) -> bool:
        """
        注销Webhook

        Args:
            webhook_id: Webhook ID

        Returns:
            是否成功注销
        """
        if webhook_id in self._webhooks:
            del self._webhooks[webhook_id]
            logger.info(f"Unregistered webhook {webhook_id}")
            return True
        return False

    def get_webhook(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """
        获取Webhook信息

        Args:
            webhook_id: Webhook ID

        Returns:
            Webhook信息
        """
        return self._webhooks.get(webhook_id)

    def list_webhooks(self) -> List[Dict[str, Any]]:
        """
        列出所有Webhook

        Returns:
            Webhook列表
        """
        return list(self._webhooks.values())

    async def trigger_event(
        self,
        event: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        触发Webhook事件

        Args:
            event: 事件类型
            payload: 事件数据

        Returns:
            触发结果统计
        """
        results = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "webhooks": [],
        }

        for webhook_id, webhook in self._webhooks.items():
            if webhook["status"] != "active":
                continue

            if event not in webhook["events"]:
                continue

            results["total"] += 1

            try:
                success = await self._send_webhook(webhook, event, payload)
                if success:
                    results["success"] += 1
                    webhook["success_count"] += 1
                else:
                    results["failed"] += 1
                    webhook["failure_count"] += 1

                results["webhooks"].append(
                    {
                        "webhook_id": webhook_id,
                        "url": webhook["url"],
                        "success": success,
                    }
                )
            except Exception as e:
                logger.error(f"Error triggering webhook {webhook_id}: {e}")
                results["failed"] += 1
                webhook["failure_count"] += 1
                results["webhooks"].append(
                    {
                        "webhook_id": webhook_id,
                        "url": webhook["url"],
                        "success": False,
                        "error": str(e),
                    }
                )

        return results

    async def _send_webhook(
        self,
        webhook: Dict[str, Any],
        event: str,
        payload: Dict[str, Any],
    ) -> bool:
        """
        发送Webhook请求

        Args:
            webhook: Webhook配置
            event: 事件类型
            payload: 事件数据

        Returns:
            是否成功
        """
        import hmac
        import json

        headers = {
            "Content-Type": "application/json",
            "X-SkillScan-Event": event,
            "X-SkillScan-Timestamp": str(int(time.time())),
        }
        headers.update(webhook.get("headers", {}))

        body = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat(),
            "data": payload,
        }

        body_json = json.dumps(body, default=str)

        if webhook.get("secret"):
            signature = hmac.new(
                webhook["secret"].encode(),
                body_json.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-SkillScan-Signature"] = f"sha256={signature}"

        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        webhook["url"],
                        content=body_json,
                        headers=headers,
                    )

                    if response.status_code in (200, 201, 202, 204):
                        logger.debug(f"Webhook {webhook['id']} sent successfully")
                        return True
                    elif response.status_code >= 500:
                        logger.warning(
                            f"Webhook {webhook['id']} returned {response.status_code}, "
                            f"retrying ({attempt + 1}/{self._max_retries})"
                        )
                        await asyncio.sleep(self._retry_delay)
                        continue
                    else:
                        logger.warning(
                            f"Webhook {webhook['id']} returned {response.status_code}: "
                            f"{response.text[:200]}"
                        )
                        return False

            except httpx.TimeoutException:
                logger.warning(
                    f"Webhook {webhook['id']} timeout, "
                    f"retrying ({attempt + 1}/{self._max_retries})"
                )
                await asyncio.sleep(self._retry_delay)
            except httpx.RequestError as e:
                logger.error(f"Webhook {webhook['id']} request error: {e}")
                return False

        return False

    def add_event_handler(self, event: str, handler: Callable):
        """
        添加事件处理器

        Args:
            event: 事件类型
            handler: 处理函数
        """
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
        else:
            self._event_handlers[event] = [handler]

    def remove_event_handler(self, event: str, handler: Callable):
        """
        移除事件处理器

        Args:
            event: 事件类型
            handler: 处理函数
        """
        if event in self._event_handlers:
            try:
                self._event_handlers[event].remove(handler)
            except ValueError:
                pass


webhook_manager = WebhookManager()
