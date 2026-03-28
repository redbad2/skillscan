"""
Webhook回调模块

管理扫描完成后的 callback通知。
"""

import asyncio
import hashlib
import re
import time
import ipaddress
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
import httpx
from urllib.parse import urlparse

from loguru import logger


class WebhookEvent(str, Enum):
    """Webhook事件类型"""

    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SKILL_DETECTED = "skill.detected"
    VULNERABILITY_FOUND = "vulnerability.found"
    HIGH_RISK_DETECTED = "high_risk.detected"
    MALICIOUS_DETECTED = "malicious.detected"


class WebhookSecurityError(Exception):
    """Webhook安全校验异常"""

    pass


class WebhookManager:
    """Webhook管理器"""

    BLOCKED_IP_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("::1/128"),
    ]

    def __init__(self):
        self._webhooks: Dict[str, Dict[str, Any]] = {}
        self._event_handlers: Dict[str, List[Callable]] = {
            event.value: [] for event in WebhookEvent
        }
        self._retry_queue: List[Dict[str, Any]] = []
        self._max_retries = 3
        self._retry_delay = 5
        self._allowed_domains: List[str] = []
        self._max_response_size = 1024 * 1024

    def _validate_url(self, url: str) -> bool:
        """
        校验URL是否安全，防止SSRF攻击

        Args:
            url: 待校验的URL

        Returns:
            是否安全
        """
        try:
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https"):
                logger.warning(f"Blocked webhook URL with invalid scheme: {url}")
                return False

            if not parsed.netloc:
                logger.warning(f"Blocked webhook URL without netloc: {url}")
                return False

            hostname = parsed.hostname
            if not hostname:
                logger.warning(f"Blocked webhook URL without hostname: {url}")
                return False

            if hostname.lower() in ("localhost", "localhost.localdomain"):
                logger.warning(f"Blocked webhook URL with localhost: {url}")
                return False

            try:
                ip = ipaddress.ip_address(hostname)
                for blocked_range in self.BLOCKED_IP_RANGES:
                    if ip in blocked_range:
                        logger.warning(f"Blocked webhook URL with private IP: {url}")
                        return False
            except ValueError:
                pass

            if self._allowed_domains:
                domain_allowed = False
                for allowed in self._allowed_domains:
                    if hostname == allowed or hostname.endswith(f".{allowed}"):
                        domain_allowed = True
                        break
                if not domain_allowed:
                    logger.warning(f"Blocked webhook URL not in allowed domains: {url}")
                    return False

            return True

        except Exception as e:
            logger.warning(f"Error validating webhook URL {url}: {e}")
            return False

    def set_allowed_domains(self, domains: List[str]):
        """设置允许的域名白名单"""
        self._allowed_domains = domains

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

        Raises:
            WebhookSecurityError: URL校验失败时抛出
        """
        if not self._validate_url(url):
            raise WebhookSecurityError(
                "Webhook URL validation failed: only HTTPS URLs to public domains are allowed"
            )

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
                async with httpx.AsyncClient(
                    timeout=10.0,
                    limits=httpx.Limits(
                        max_connections=10,
                        max_keepalive_connections=5,
                    ),
                    follow_redirects=False,
                ) as client:
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
