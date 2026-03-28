"""
网络收集器模块

支持从多个平台爬取技能文件，包括ClawHub、Smithery、skills.sh等。
"""

import asyncio
import re
from typing import Optional, List, Dict, Any, AsyncGenerator
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from src.collectors.base import BaseCollector, SkillSource, SourceChannel
from src.config.settings import get_settings


class PlatformConfig:
    """平台配置"""

    PLATFORMS = {
        "clawhub": {
            "base_url": "https://clawhub.com",
            "api_url": "https://api.clawhub.com/v1",
            "skills_endpoint": "/skills",
            "skill_detail_endpoint": "/skills/{id}",
        },
        "smithery": {
            "base_url": "https://smithery.ai",
            "api_url": "https://api.smithery.ai/v1",
            "skills_endpoint": "/tools",
            "skill_detail_endpoint": "/tools/{id}",
        },
        "skillssh": {
            "base_url": "https://skills.sh",
            "api_url": "https://api.skills.sh/v1",
            "skills_endpoint": "/skills",
            "skill_detail_endpoint": "/skills/{id}",
        },
    }


class NetworkCollector(BaseCollector):
    """网络爬取收集器"""

    def __init__(self, db_manager=None, platforms: Optional[List[str]] = None):
        super().__init__(db_manager)
        self.settings = get_settings()
        self.platforms = platforms or list(PlatformConfig.PLATFORMS.keys())
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter = AsyncSemaphore(self.settings.crawl_rate_limit)

    @property
    def name(self) -> str:
        return "network_collector"

    @property
    def channel(self) -> SourceChannel:
        return SourceChannel.NETWORK_CRAWL

    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={
                    "User-Agent": "SkillScan/1.0 (Security Scanner)",
                    "Accept": "application/json, text/html, text/markdown",
                },
            )
        return self._client

    async def close(self) -> None:
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def collect(self, limit: Optional[int] = None) -> List[SkillSource]:
        """
        从多个平台爬取技能文件

        Args:
            limit: 每个平台最大爬取数量

        Returns:
            技能文件列表
        """
        skills: List[SkillSource] = []

        logger.info(f"Starting network crawl for platforms: {self.platforms}")

        for platform in self.platforms:
            try:
                platform_skills = await self._collect_from_platform(platform, limit)
                skills.extend(platform_skills)
                self._stats["collected"] += len(platform_skills)
                logger.info(f"Collected {len(platform_skills)} skills from {platform}")
            except Exception as e:
                logger.error(f"Error collecting from {platform}: {e}")
                self._stats["errors"] += 1

        logger.info(f"Network crawl completed: {len(skills)} skills collected")
        return skills

    async def _collect_from_platform(
        self, platform: str, limit: Optional[int] = None
    ) -> List[SkillSource]:
        """从单个平台爬取技能"""
        if platform not in PlatformConfig.PLATFORMS:
            logger.warning(f"Unknown platform: {platform}")
            return []

        config = PlatformConfig.PLATFORMS[platform]
        skills: List[SkillSource] = []

        try:
            # 获取技能列表
            skill_ids = await self._fetch_skill_list(config, limit)

            # 逐个获取技能详情
            for skill_id in skill_ids:
                async with self._rate_limiter:
                    skill = await self._fetch_skill_detail(platform, config, skill_id)
                    if skill and await self.validate_source(skill):
                        skills.append(skill)

                    # 避免过快请求
                    await asyncio.sleep(1.0 / self.settings.crawl_rate_limit)

        except Exception as e:
            logger.error(f"Error collecting from {platform}: {e}")

        return skills

    async def _fetch_skill_list(
        self, config: Dict[str, str], limit: Optional[int] = None
    ) -> List[str]:
        """获取技能ID列表"""
        skill_ids = []

        try:
            client = await self._get_client()
            url = config["api_url"] + config["skills_endpoint"]
            params = {"limit": limit or 100, "offset": 0}

            while True:
                response = await client.get(url, params=params)

                if response.status_code != 200:
                    logger.warning(f"Failed to fetch skill list: {response.status_code}")
                    break

                data = response.json()

                # 提取技能ID
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("items", data.get("skills", data.get("data", [])))
                else:
                    break

                for item in items:
                    if isinstance(item, dict):
                        skill_id = item.get("id") or item.get("skill_id") or item.get("name")
                        if skill_id:
                            skill_ids.append(str(skill_id))

                # 检查是否有更多数据
                if len(items) < params["limit"]:
                    break

                params["offset"] += params["limit"]

                if limit and len(skill_ids) >= limit:
                    skill_ids = skill_ids[:limit]
                    break

        except Exception as e:
            logger.error(f"Error fetching skill list: {e}")

        return skill_ids

    async def _fetch_skill_detail(
        self, platform: str, config: Dict[str, str], skill_id: str
    ) -> Optional[SkillSource]:
        """获取技能详情"""
        try:
            client = await self._get_client()
            url = config["api_url"] + config["skill_detail_endpoint"].format(id=skill_id)

            response = await client.get(url)

            if response.status_code != 200:
                logger.warning(f"Failed to fetch skill {skill_id}: {response.status_code}")
                return None

            data = response.json()
            return self._parse_skill_data(platform, skill_id, data)

        except Exception as e:
            logger.error(f"Error fetching skill {skill_id} from {platform}: {e}")
            return None

    def _parse_skill_data(
        self, platform: str, skill_id: str, data: Dict[str, Any]
    ) -> Optional[SkillSource]:
        """解析技能数据"""
        try:
            # 提取SKILL.md内容
            content = data.get("content") or data.get("skill_md") or data.get("description") or ""

            # 提取脚本文件
            scripts = []
            script_files = data.get("scripts") or data.get("files") or []
            for script in script_files:
                if isinstance(script, dict):
                    scripts.append(
                        {
                            "filename": script.get("name", script.get("filename", "")),
                            "content": script.get("content", ""),
                            "language": script.get(
                                "language", self._detect_language(script.get("name", ""))
                            ),
                        }
                    )

            # 提取元数据
            metadata = {
                "author": data.get("author") or data.get("creator"),
                "description": data.get("description"),
                "version": data.get("version", "1.0.0"),
                "permissions": data.get("permissions", []),
                "triggers": data.get("triggers", []),
                "tags": data.get("tags", []),
            }

            # 计算文件大小
            file_size = len(content.encode("utf-8"))
            for script in scripts:
                file_size += len(script.get("content", "").encode("utf-8"))

            return SkillSource(
                name=data.get("name", skill_id),
                content=content,
                scripts=scripts,
                source_path=f"{config.get('base_url', '')}/skills/{skill_id}",
                platform=platform,
                channel=SourceChannel.NETWORK_CRAWL,
                file_size=file_size,
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error parsing skill data: {e}")
            return None

    def _detect_language(self, filename: str) -> str:
        """检测脚本语言"""
        ext_map = {
            ".py": "python",
            ".sh": "shell",
            ".bash": "shell",
            ".js": "javascript",
            ".ts": "typescript",
            ".rb": "ruby",
            ".pl": "perl",
        }
        for ext, lang in ext_map.items():
            if filename.endswith(ext):
                return lang
        return "unknown"

    async def validate_source(self, source: SkillSource) -> bool:
        """验证技能源有效性"""
        if not source.content:
            return False

        # 最小内容长度
        if len(source.content) < 50:
            return False

        return True

    async def crawl_url(self, url: str) -> Optional[SkillSource]:
        """爬取单个URL的技能文件"""
        try:
            client = await self._get_client()
            response = await client.get(url)

            if response.status_code != 200:
                return None

            content_type = response.headers.get("content-type", "")

            # 尝试解析为技能文件
            if "markdown" in content_type or "text/plain" in content_type:
                content = response.text
                parsed = urlparse(url)
                skill = SkillSource(
                    name=parsed.path.split("/")[-1].replace(".md", ""),
                    content=content,
                    source_path=url,
                    platform="web",
                    channel=SourceChannel.NETWORK_CRAWL,
                    file_size=len(content.encode("utf-8")),
                )
                if await self.validate_source(skill):
                    return skill

            return None

        except Exception as e:
            logger.error(f"Error crawling URL {url}: {e}")
            return None


class AsyncSemaphore:
    """异步信号量，用于速率限制"""

    def __init__(self, value: int = 10):
        self._semaphore = asyncio.Semaphore(value)

    async def __aenter__(self):
        await self._semaphore.acquire()
        return self

    async def __aexit__(self, *args):
        self._semaphore.release()
