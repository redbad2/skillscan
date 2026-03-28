"""
网络收集器模块

支持从多个平台爬取技能文件，包括ClawHub、Smithery、skills.sh等。
"""

import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx
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
        "skillsmp": {
            "base_url": "https://skillsmp.com",
            "api_url": "https://skillsmp.com/api/v1",
            "search_endpoint": "/skills/search",
            "ai_search_endpoint": "/skills/ai-search",
            "skill_detail_endpoint": "/skills/{id}",
            "requires_auth": True,
            "daily_limit": 500,
        },
        "agentskillhub": {
            "base_url": "https://agentskillhub.dev",
            "api_url": "https://agentskillhub.dev/api/v1",
            "search_endpoint": "/search",
            "skill_detail_endpoint": "/skills/{id}",
            "requires_auth": False,
        },
        "aiskillstore": {
            "base_url": "https://skillstore.io",
            "api_url": "https://skillstore.io/api/v1",
            "skills_endpoint": "/skills",
            "skill_detail_endpoint": "/skills/{id}",
            "requires_auth": False,
        },
        "skillhub": {
            "base_url": "https://skillhub.ai",
            "api_url": "https://skillhub.ai/api/v1",
            "skills_endpoint": "/skills",
            "skill_detail_endpoint": "/skills/{id}",
            "requires_auth": False,
        },
    }


class NetworkCollector(BaseCollector):
    """网络爬取收集器"""

    def __init__(self, db_manager=None, platforms: list[str] | None = None):
        super().__init__(db_manager)
        self.settings = get_settings()
        self.platforms = platforms or list(PlatformConfig.PLATFORMS.keys())
        self._client: httpx.AsyncClient | None = None
        self._rate_limiter = AsyncSemaphore(self.settings.collector.crawl_concurrency)

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

    async def collect(self, limit: int | None = None) -> list[SkillSource]:
        """
        从多个平台爬取技能文件

        Args:
            limit: 每个平台最大爬取数量

        Returns:
            技能文件列表
        """
        skills: list[SkillSource] = []

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
        self, platform: str, limit: int | None = None
    ) -> list[SkillSource]:
        """从单个平台爬取技能"""
        if platform not in PlatformConfig.PLATFORMS:
            logger.warning(f"Unknown platform: {platform}")
            return []

        # 使用平台特定的获取方法
        if platform == "skillsmp":
            return await self._fetch_skillsmp_skills(limit)
        elif platform == "agentskillhub":
            return await self._fetch_agentskillhub_skills(limit)
        elif platform == "aiskillstore":
            return await self._fetch_aiskillstore_skills(limit)
        elif platform == "skillhub":
            return await self._fetch_skillhub_skills(limit)

        config = PlatformConfig.PLATFORMS[platform]
        skills: list[SkillSource] = []

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
                    await asyncio.sleep(1.0 / self.settings.crawl_concurrency)

        except Exception as e:
            logger.error(f"Error collecting from {platform}: {e}")

        return skills

    async def _fetch_skill_list(
        self, config: dict[str, str], limit: int | None = None
    ) -> list[str]:
        """获取技能ID列表"""
        skill_ids = []

        try:
            client = await self._get_client()

            # 根据平台选择合适的端点
            if "search_endpoint" in config:
                url = config["api_url"] + config["search_endpoint"]
            else:
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
                    if not items and "results" in data:
                        items = data["results"]
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

    async def _fetch_skillsmp_skills(self, limit: int | None = None) -> list[SkillSource]:
        """从 SkillsMP 平台爬取技能"""
        skills: list[SkillSource] = []

        try:
            client = await self._get_client()
            config = PlatformConfig.PLATFORMS["skillsmp"]
            api_key = self.settings.collector.skillsmp_api_key

            url = config["api_url"] + config["search_endpoint"]

            headers: dict[str, str] = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
                logger.debug("Using SkillsMP API key for authenticated requests")
            else:
                logger.warning(
                    "SkillsMP API key not configured. Set SKILLSMP_API_KEY env var. "
                    "Search requests may be limited."
                )

            search_terms = ["security", "api", "web", "data", "cloud", "devops", "test", "code"]
            total_fetched = 0

            for term in search_terms:
                if limit and total_fetched >= limit:
                    break

                params = {
                    "q": term,
                    "limit": min(limit or 50, 50),
                    "sortBy": "popular",
                }
                page = 1

                while page <= 5:
                    if limit and total_fetched >= limit:
                        break

                    params["page"] = page
                    response = await client.get(url, params=params, headers=headers)

                    if response.status_code == 401:
                        logger.error(
                            "SkillsMP API authentication failed. Please check your API key."
                        )
                        return skills
                    elif response.status_code == 400:
                        error_msg = response.json().get("error", {}).get("message", "")
                        logger.error(f"SkillsMP API error: {error_msg}")
                        break
                    elif response.status_code != 200:
                        logger.warning(f"Failed to fetch from SkillsMP: {response.status_code}")
                        break

                    resp_data = response.json()
                    data_container = resp_data.get("data", {})
                    items = data_container.get("skills", [])
                    pagination = data_container.get("pagination", {})

                    if not items:
                        break

                    for item in items:
                        if limit and total_fetched >= limit:
                            break
                        skill = self._parse_skillsmp_skill(item)
                        if skill and await self.validate_source(skill):
                            skills.append(skill)
                            total_fetched += 1

                    if not pagination.get("hasNext", False):
                        break

                    page += 1
                    await asyncio.sleep(0.5)

            logger.info(f"Collected {len(skills)} skills from SkillsMP")

        except Exception as e:
            logger.error(f"Error fetching from SkillsMP: {e}")

        return skills[:limit] if limit else skills

    def _parse_skillsmp_skill(self, data: dict[str, Any]) -> SkillSource | None:
        """解析 SkillsMP 技能数据"""
        try:
            config = PlatformConfig.PLATFORMS["skillsmp"]

            name = data.get("name", "unknown")
            skill_id = data.get("id", name)
            description = data.get("description", "")
            github_url = data.get("githubUrl", "")
            skill_url = data.get("skillUrl", "")
            author = data.get("author", "")
            stars = data.get("stars", 0)

            content = data.get("skill_md") or data.get("content") or description or ""

            scripts: list[dict[str, str]] = []
            script_files = data.get("scripts", data.get("files", []))
            for script in script_files:
                if isinstance(script, dict):
                    scripts.append(
                        {
                            "filename": script.get("name", script.get("filename", "")),
                            "content": script.get("content", script.get("code", "")),
                            "language": script.get(
                                "language", self._detect_language(script.get("name", ""))
                            ),
                        }
                    )

            metadata = {
                "author": author,
                "description": description,
                "github_url": github_url,
                "stars": stars,
                "version": data.get("version", "1.0.0"),
                "permissions": data.get("permissions", []),
                "triggers": data.get("triggers", []),
                "tags": data.get("tags", []),
                "source": "skillsmp",
            }

            file_size = len(content.encode("utf-8"))
            for script in scripts:
                file_size += len(script.get("content", "").encode("utf-8"))

            source_path = skill_url or f"{config['base_url']}/skills/{skill_id}"

            return SkillSource(
                name=name,
                content=content,
                scripts=scripts,
                source_path=source_path,
                platform="skillsmp",
                channel=SourceChannel.NETWORK_CRAWL,
                file_size=file_size,
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error parsing SkillsMP skill data: {e}")
            return None

    async def _fetch_agentskillhub_skills(self, limit: int | None = None) -> list[SkillSource]:
        """从 AgentSkillHub 平台爬取技能"""
        skills: list[SkillSource] = []

        try:
            client = await self._get_client()
            config = PlatformConfig.PLATFORMS["agentskillhub"]

            url = config["api_url"] + config["search_endpoint"]
            params = {"q": "", "limit": min(limit or 50, 50)}

            page = 1
            max_pages = 10 if not limit else (limit // 50) + 1

            while page <= max_pages:
                params["page"] = page
                response = await client.get(url, params=params)

                if response.status_code != 200:
                    logger.warning(f"Failed to fetch from AgentSkillHub: {response.status_code}")
                    break

                data = response.json()
                items = data.get("items", data.get("skills", data.get("results", [])))

                if not items:
                    break

                for item in items:
                    skill = self._parse_agentskillhub_skill(item)
                    if skill and await self.validate_source(skill):
                        skills.append(skill)

                page += 1
                await asyncio.sleep(1.0)

                if limit and len(skills) >= limit:
                    break

            logger.info(f"Collected {len(skills)} skills from AgentSkillHub")

        except Exception as e:
            logger.error(f"Error fetching from AgentSkillHub: {e}")

        return skills[:limit] if limit else skills

    def _parse_agentskillhub_skill(self, data: dict[str, Any]) -> SkillSource | None:
        """解析 AgentSkillHub 技能数据"""
        try:
            config = PlatformConfig.PLATFORMS["agentskillhub"]

            name = data.get("name") or data.get("title", "unknown")
            skill_id = data.get("id", name)

            content = (
                data.get("content")
                or data.get("skill_md")
                or data.get("description")
                or data.get("readme", "")
            )

            scripts = []
            for script in data.get("scripts", data.get("files", [])):
                if isinstance(script, dict):
                    scripts.append(
                        {
                            "filename": script.get("name", ""),
                            "content": script.get("content", ""),
                            "language": script.get(
                                "language", self._detect_language(script.get("name", ""))
                            ),
                        }
                    )

            metadata = {
                "author": data.get("author"),
                "description": data.get("description"),
                "version": data.get("version", "1.0.0"),
                "permissions": data.get("permissions", []),
                "triggers": data.get("triggers", []),
                "tags": data.get("tags", []),
                "source": "agentskillhub",
            }

            file_size = len(content.encode("utf-8"))
            for script in scripts:
                file_size += len(script.get("content", "").encode("utf-8"))

            return SkillSource(
                name=name,
                content=content,
                scripts=scripts,
                source_path=f"{config['base_url']}/skills/{skill_id}",
                platform="agentskillhub",
                channel=SourceChannel.NETWORK_CRAWL,
                file_size=file_size,
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error parsing AgentSkillHub skill data: {e}")
            return None

    async def _fetch_aiskillstore_skills(self, limit: int | None = None) -> list[SkillSource]:
        """从 AISkillStore 平台爬取技能"""
        skills: list[SkillSource] = []

        try:
            client = await self._get_client()
            config = PlatformConfig.PLATFORMS["aiskillstore"]

            url = config["api_url"] + config["skills_endpoint"]
            params = {"limit": min(limit or 50, 50), "offset": 0}

            while True:
                response = await client.get(url, params=params)

                if response.status_code != 200:
                    logger.warning(f"Failed to fetch from AISkillStore: {response.status_code}")
                    break

                data = response.json()
                items = data.get(
                    "items", data.get("skills", data.get("results", data.get("data", [])))
                )

                if not items:
                    break

                for item in items:
                    skill = self._parse_aiskillstore_skill(item)
                    if skill and await self.validate_source(skill):
                        skills.append(skill)

                if len(items) < params["limit"]:
                    break

                params["offset"] += params["limit"]

                if limit and len(skills) >= limit:
                    break

                await asyncio.sleep(1.0)

            logger.info(f"Collected {len(skills)} skills from AISkillStore")

        except Exception as e:
            logger.error(f"Error fetching from AISkillStore: {e}")

        return skills[:limit] if limit else skills

    def _parse_aiskillstore_skill(self, data: dict[str, Any]) -> SkillSource | None:
        """解析 AISkillStore 技能数据"""
        try:
            config = PlatformConfig.PLATFORMS["aiskillstore"]

            name = data.get("name") or data.get("title", "unknown")
            skill_id = data.get("id", name)

            content = (
                data.get("content")
                or data.get("skill_md")
                or data.get("description")
                or data.get("readme", "")
            )

            scripts = []
            for script in data.get("scripts", data.get("files", [])):
                if isinstance(script, dict):
                    scripts.append(
                        {
                            "filename": script.get("name", ""),
                            "content": script.get("content", ""),
                            "language": script.get(
                                "language", self._detect_language(script.get("name", ""))
                            ),
                        }
                    )

            metadata = {
                "author": data.get("author"),
                "description": data.get("description"),
                "version": data.get("version", "1.0.0"),
                "permissions": data.get("permissions", []),
                "triggers": data.get("triggers", []),
                "tags": data.get("tags", []),
                "source": "aiskillstore",
            }

            file_size = len(content.encode("utf-8"))
            for script in scripts:
                file_size += len(script.get("content", "").encode("utf-8"))

            return SkillSource(
                name=name,
                content=content,
                scripts=scripts,
                source_path=f"{config['base_url']}/skills/{skill_id}",
                platform="aiskillstore",
                channel=SourceChannel.NETWORK_CRAWL,
                file_size=file_size,
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error parsing AISkillStore skill data: {e}")
            return None

    async def _fetch_skillhub_skills(self, limit: int | None = None) -> list[SkillSource]:
        """从 SkillHub 平台爬取技能"""
        skills: list[SkillSource] = []

        try:
            client = await self._get_client()
            config = PlatformConfig.PLATFORMS["skillhub"]

            url = config["api_url"] + config["skills_endpoint"]
            params = {"limit": min(limit or 50, 50), "offset": 0}

            while True:
                response = await client.get(url, params=params)

                if response.status_code != 200:
                    logger.warning(f"Failed to fetch from SkillHub: {response.status_code}")
                    break

                data = response.json()
                items = data.get(
                    "items", data.get("skills", data.get("results", data.get("data", [])))
                )

                if not items:
                    break

                for item in items:
                    skill = self._parse_skillhub_skill(item)
                    if skill and await self.validate_source(skill):
                        skills.append(skill)

                if len(items) < params["limit"]:
                    break

                params["offset"] += params["limit"]

                if limit and len(skills) >= limit:
                    break

                await asyncio.sleep(1.0)

            logger.info(f"Collected {len(skills)} skills from SkillHub")

        except Exception as e:
            logger.error(f"Error fetching from SkillHub: {e}")

        return skills[:limit] if limit else skills

    def _parse_skillhub_skill(self, data: dict[str, Any]) -> SkillSource | None:
        """解析 SkillHub 技能数据"""
        try:
            config = PlatformConfig.PLATFORMS["skillhub"]

            name = data.get("name") or data.get("title", "unknown")
            skill_id = data.get("id", name)

            content = (
                data.get("content")
                or data.get("skill_md")
                or data.get("description")
                or data.get("readme", "")
            )

            scripts = []
            for script in data.get("scripts", data.get("files", [])):
                if isinstance(script, dict):
                    scripts.append(
                        {
                            "filename": script.get("name", ""),
                            "content": script.get("content", ""),
                            "language": script.get(
                                "language", self._detect_language(script.get("name", ""))
                            ),
                        }
                    )

            metadata = {
                "author": data.get("author"),
                "description": data.get("description"),
                "version": data.get("version", "1.0.0"),
                "permissions": data.get("permissions", []),
                "triggers": data.get("triggers", []),
                "tags": data.get("tags", []),
                "source": "skillhub",
            }

            file_size = len(content.encode("utf-8"))
            for script in scripts:
                file_size += len(script.get("content", "").encode("utf-8"))

            return SkillSource(
                name=name,
                content=content,
                scripts=scripts,
                source_path=f"{config['base_url']}/skills/{skill_id}",
                platform="skillhub",
                channel=SourceChannel.NETWORK_CRAWL,
                file_size=file_size,
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error parsing SkillHub skill data: {e}")
            return None

    async def _fetch_skill_detail(
        self, platform: str, config: dict[str, Any], skill_id: str
    ) -> SkillSource | None:
        """获取技能详情"""
        try:
            client = await self._get_client()
            url = config["api_url"] + config["skill_detail_endpoint"].format(id=skill_id)

            response = await client.get(url)

            if response.status_code != 200:
                logger.warning(f"Failed to fetch skill {skill_id}: {response.status_code}")
                return None

            data = response.json()
            return self._parse_skill_data(platform, skill_id, data, config)

        except Exception as e:
            logger.error(f"Error fetching skill {skill_id} from {platform}: {e}")
            return None

    def _parse_skill_data(
        self,
        platform: str,
        skill_id: str,
        data: dict[str, Any],
        config: dict[str, Any] | None = None,
    ) -> SkillSource | None:
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

            base_url = config.get("base_url", "") if config else ""
            return SkillSource(
                name=data.get("name", skill_id),
                content=content,
                scripts=scripts,
                source_path=f"{base_url}/skills/{skill_id}",
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

    async def crawl_url(self, url: str) -> SkillSource | None:
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
