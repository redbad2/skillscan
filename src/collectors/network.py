"""
Network collector for crawling skill platforms.
"""

import asyncio
import aiohttp
import logging
from typing import List, Optional, AsyncIterator, Dict, Any
from datetime import datetime
import json
import os
from pathlib import Path

from .base import BaseCollector
from ..models import (
    SkillDocument, CollectionInfo, CollectionChannel, 
    Platform, Language
)
from ..config import settings

logger = logging.getLogger(__name__)


class NetworkCollector(BaseCollector):
    """Collect skills from network platforms via API or web scraping."""
    
    def __init__(self, platforms: Optional[List[str]] = None):
        super().__init__(name="network")
        self.platforms = platforms or ["clawhub", "smithery", "skillssh"]
        self.session: Optional[aiohttp.ClientSession] = None
        self.headers = {
            "User-Agent": settings.collector.crawl_user_agent,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=settings.collector.crawl_timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def test_connection(self) -> bool:
        """Test connection to all configured platforms."""
        results = []
        for platform in self.platforms:
            try:
                connected = await self._test_platform_connection(platform)
                results.append(connected)
                logger.info(f"Platform {platform}: {'connected' if connected else 'failed'}")
            except Exception as e:
                logger.error(f"Platform {platform} connection test failed: {e}")
                results.append(False)
        return any(results)
    
    async def _test_platform_connection(self, platform: str) -> bool:
        """Test connection to a specific platform."""
        if not self.session:
            return False
        
        urls = {
            "clawhub": f"{settings.collector.clawhub_api_url}/health",
            "smithery": f"{settings.collector.smithery_api_url}/health",
            "skillssh": f"{settings.collector.skillssh_api_url}/health",
        }
        
        url = urls.get(platform)
        if not url:
            return False
        
        try:
            async with self.session.get(url) as response:
                return response.status == 200
        except:
            return False
    
    async def collect(self, **kwargs) -> AsyncIterator[SkillDocument]:
        """Collect skills from configured platforms."""
        for platform in self.platforms:
            try:
                async for skill in self._collect_from_platform(platform, **kwargs):
                    yield skill
            except Exception as e:
                logger.error(f"Error collecting from {platform}: {e}")
    
    async def _collect_from_platform(
        self, 
        platform: str, 
        limit: Optional[int] = None,
        offset: int = 0
    ) -> AsyncIterator[SkillDocument]:
        """Collect skills from a specific platform."""
        
        if platform == "clawhub":
            async for skill in self._collect_from_clawhub(limit, offset):
                yield skill
        elif platform == "smithery":
            async for skill in self._collect_from_smithery(limit, offset):
                yield skill
        elif platform == "skillssh":
            async for skill in self._collect_from_skillssh(limit, offset):
                yield skill
        else:
            logger.warning(f"Unknown platform: {platform}")
    
    async def _collect_from_clawhub(
        self, 
        limit: Optional[int] = None, 
        offset: int = 0
    ) -> AsyncIterator[SkillDocument]:
        """Collect skills from ClawHub platform."""
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        url = f"{settings.collector.clawhub_api_url}/skills"
        params = {
            "offset": offset,
            "limit": min(limit or 100, 100),
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    skills = data.get("skills", [])
                    
                    for skill_data in skills:
                        skill = await self._parse_clawhub_skill(skill_data)
                        if skill:
                            yield skill
                            self.update_stats(True)
                            
                            if limit and self.stats["total_processed"] >= limit:
                                return
                else:
                    logger.error(f"ClawHub API error: {response.status}")
                    self.update_stats(False)
                    
        except Exception as e:
            logger.error(f"Error collecting from ClawHub: {e}")
            self.update_stats(False)
    
    async def _parse_clawhub_skill(self, data: Dict[str, Any]) -> Optional[SkillDocument]:
        """Parse a skill from ClawHub API response."""
        try:
            skill_id = data.get("id") or data.get("skill_id")
            name = data.get("name", "Unknown")
            version = data.get("version", "1.0.0")
            
            # Create basic skill document
            skill = SkillDocument(
                skill_id=skill_id,
                name=name,
                version=version,
                platform=Platform.CLAWHUB,
                source=CollectionChannel.NETWORK_CRAWL,
            )
            
            # Extract metadata
            skill.metadata.author = data.get("author")
            skill.metadata.description = data.get("description")
            skill.metadata.permissions = data.get("permissions", [])
            skill.metadata.triggers = data.get("triggers", [])
            
            # Fetch skill content
            content_url = data.get("content_url") or data.get("download_url")
            if content_url:
                content = await self._fetch_skill_content(content_url)
                if content:
                    skill.skill_md_content = content
                    skill.metadata = self.extract_metadata(content)
            
            # Detect language
            if skill.skill_md_content:
                lang, confidence = self.detect_language(skill.skill_md_content)
                skill.language = lang
            
            # Set collection info
            skill.collection_info = CollectionInfo(
                channel=CollectionChannel.NETWORK_CRAWL,
                source_platform=Platform.CLAWHUB,
                original_path=content_url,
            )
            
            return skill
            
        except Exception as e:
            logger.error(f"Error parsing ClawHub skill: {e}")
            return None
    
    async def _collect_from_smithery(
        self, 
        limit: Optional[int] = None, 
        offset: int = 0
    ) -> AsyncIterator[SkillDocument]:
        """Collect skills from Smithery platform."""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        url = f"{settings.collector.smithery_api_url}/skills"
        params = {
            "skip": offset,
            "take": min(limit or 100, 100),
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    skills = data.get("items", data.get("skills", []))
                    
                    for skill_data in skills:
                        skill = await self._parse_smithery_skill(skill_data)
                        if skill:
                            yield skill
                            self.update_stats(True)
                            
                            if limit and self.stats["total_processed"] >= limit:
                                return
                else:
                    logger.error(f"Smithery API error: {response.status}")
                    self.update_stats(False)
                    
        except Exception as e:
            logger.error(f"Error collecting from Smithery: {e}")
            self.update_stats(False)
    
    async def _parse_smithery_skill(self, data: Dict[str, Any]) -> Optional[SkillDocument]:
        """Parse a skill from Smithery API response."""
        try:
            skill_id = data.get("id") or data.get("slug")
            name = data.get("name", "Unknown")
            version = data.get("version", "1.0.0")
            
            skill = SkillDocument(
                skill_id=skill_id,
                name=name,
                version=version,
                platform=Platform.SMITHERY,
                source=CollectionChannel.NETWORK_CRAWL,
            )
            
            skill.metadata.author = data.get("author", {}).get("name")
            skill.metadata.description = data.get("description")
            skill.metadata.repository = data.get("repository_url")
            
            # Fetch content
            if data.get("skill_md"):
                skill.skill_md_content = data["skill_md"]
                skill.metadata = self.extract_metadata(skill.skill_md_content)
            
            if skill.skill_md_content:
                lang, _ = self.detect_language(skill.skill_md_content)
                skill.language = lang
            
            skill.collection_info = CollectionInfo(
                channel=CollectionChannel.NETWORK_CRAWL,
                source_platform=Platform.SMITHERY,
            )
            
            return skill
            
        except Exception as e:
            logger.error(f"Error parsing Smithery skill: {e}")
            return None
    
    async def _collect_from_skillssh(
        self, 
        limit: Optional[int] = None, 
        offset: int = 0
    ) -> AsyncIterator[SkillDocument]:
        """Collect skills from skills.sh platform."""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        url = f"{settings.collector.skillssh_api_url}/skills"
        params = {
            "offset": offset,
            "limit": min(limit or 100, 100),
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    skills = data.get("data", data.get("skills", []))
                    
                    for skill_data in skills:
                        skill = await self._parse_skillssh_skill(skill_data)
                        if skill:
                            yield skill
                            self.update_stats(True)
                            
                            if limit and self.stats["total_processed"] >= limit:
                                return
                else:
                    logger.error(f"skills.sh API error: {response.status}")
                    self.update_stats(False)
                    
        except Exception as e:
            logger.error(f"Error collecting from skills.sh: {e}")
            self.update_stats(False)
    
    async def _parse_skillssh_skill(self, data: Dict[str, Any]) -> Optional[SkillDocument]:
        """Parse a skill from skills.sh API response."""
        try:
            skill_id = data.get("id") or data.get("uuid")
            name = data.get("title", data.get("name", "Unknown"))
            version = data.get("version", "1.0.0")
            
            skill = SkillDocument(
                skill_id=skill_id,
                name=name,
                version=version,
                platform=Platform.SKILLSSH,
                source=CollectionChannel.NETWORK_CRAWL,
            )
            
            skill.metadata.author = data.get("author")
            skill.metadata.description = data.get("description")
            skill.metadata.tags = data.get("tags", [])
            
            if data.get("content"):
                skill.skill_md_content = data["content"]
                skill.metadata = self.extract_metadata(skill.skill_md_content)
            
            if skill.skill_md_content:
                lang, _ = self.detect_language(skill.skill_md_content)
                skill.language = lang
            
            skill.collection_info = CollectionInfo(
                channel=CollectionChannel.NETWORK_CRAWL,
                source_platform=Platform.SKILLSSH,
            )
            
            return skill
            
        except Exception as e:
            logger.error(f"Error parsing skills.sh skill: {e}")
            return None
    
    async def _fetch_skill_content(self, url: str) -> Optional[str]:
        """Fetch skill content from URL."""
        if not self.session:
            return None
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            logger.error(f"Error fetching content from {url}: {e}")
        
        return None