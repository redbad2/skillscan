"""
Factory for creating collector instances.
"""

from typing import List, Optional, Dict, Any
import logging

from .base import BaseCollector
from .network import NetworkCollector
from .local import LocalCollector

logger = logging.getLogger(__name__)


class CollectorFactory:
    """Factory for creating appropriate collectors based on configuration."""
    
    @staticmethod
    def create_collector(
        collector_type: str,
        **kwargs
    ) -> BaseCollector:
        """Create a collector instance based on type."""
        
        collectors = {
            "network": NetworkCollector,
            "local": LocalCollector,
        }
        
        collector_class = collectors.get(collector_type)
        if not collector_class:
            raise ValueError(f"Unknown collector type: {collector_type}")
        
        return collector_class(**kwargs)
    
    @staticmethod
    def create_dual_collector(
        local_config: Optional[Dict[str, Any]] = None,
        network_config: Optional[Dict[str, Any]] = None,
    ) -> "DualCollector":
        """Create a dual collector that runs both local and network collectors."""
        
        local = LocalCollector(**(local_config or {}))
        network = NetworkCollector(**(network_config or {}))
        
        return DualCollector(local=local, network=network)


class DualCollector:
    """Collector that combines local and network collection."""
    
    def __init__(
        self,
        local: Optional[LocalCollector] = None,
        network: Optional[NetworkCollector] = None,
    ):
        self.local = local
        self.network = network
        self.stats = {
            "local": {"total": 0, "success": 0, "failed": 0},
            "network": {"total": 0, "success": 0, "failed": 0},
            "combined": {"total": 0, "success": 0, "failed": 0, "duplicates": 0},
        }
        self._seen_hashes = set()
    
    async def test_connection(self) -> Dict[str, bool]:
        """Test connections for all configured collectors."""
        results = {}
        
        if self.local:
            results["local"] = await self.local.test_connection()
        
        if self.network:
            results["network"] = await self.network.test_connection()
        
        return results
    
    async def collect_all(self, **kwargs):
        """Collect from all configured channels."""
        from ..models import SkillDocument
        
        # Run local collection
        if self.local:
            async for skill in self.local.collect(**kwargs):
                content_hash = self._calculate_hash(skill)
                if content_hash not in self._seen_hashes:
                    self._seen_hashes.add(content_hash)
                    yield skill, "local"
                    self.stats["combined"]["success"] += 1
                else:
                    self.stats["combined"]["duplicates"] += 1
                self.stats["combined"]["total"] += 1
        
        # Run network collection
        if self.network:
            async with self.network:
                async for skill in self.network.collect(**kwargs):
                    content_hash = self._calculate_hash(skill)
                    if content_hash not in self._seen_hashes:
                        self._seen_hashes.add(content_hash)
                        yield skill, "network"
                        self.stats["combined"]["success"] += 1
                    else:
                        self.stats["combined"]["duplicates"] += 1
                    self.stats["combined"]["total"] += 1
    
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
        import hashlib
        combined = "\n".join(content_parts)
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        stats = self.stats.copy()
        
        if self.local:
            stats["local"].update(self.local.get_stats())
        
        if self.network:
            stats["network"].update(self.network.get_stats())
        
        return stats