"""
MongoDB storage implementation.
"""

import logging
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import IndexModel, ASCENDING, DESCENDING
import asyncio

from ..config import settings
from ..models import (
    SKILL_INDEXES, VULNERABILITY_INDEXES, CONFIG_INDEXES
)

logger = logging.getLogger(__name__)


class MongoDBStorage:
    """MongoDB storage manager."""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self._initialized = False
    
    async def connect(self) -> bool:
        """Connect to MongoDB."""
        try:
            # Build connection URI with authentication if provided
            uri = settings.mongodb.uri
            
            if settings.mongodb.username and settings.mongodb.password:
                # Insert credentials into URI
                if "://" in uri and "@" not in uri:
                    protocol, rest = uri.split("://", 1)
                    uri = f"{protocol}://{settings.mongodb.username}:{settings.mongodb.password}@{rest}"
            
            self.client = AsyncIOMotorClient(
                uri,
                maxPoolSize=settings.mongodb.max_pool_size,
                minPoolSize=settings.mongodb.min_pool_size,
            )
            
            # Test connection
            await self.client.admin.command('ping')
            
            self.database = self.client[settings.mongodb.database]
            logger.info(f"Connected to MongoDB: {settings.mongodb.database}")
            
            # Initialize indexes
            await self._create_indexes()
            
            self._initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from MongoDB."""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
            self._initialized = False
    
    async def _create_indexes(self):
        """Create database indexes."""
        if not self.database:
            return
        
        try:
            # Skills collection indexes
            skills_collection = self.database.skills
            await skills_collection.create_indexes([
                IndexModel([("skill_id", ASCENDING)], unique=True),
                IndexModel([("name", ASCENDING)]),
                IndexModel([("platform", ASCENDING)]),
                IndexModel([("language", ASCENDING)]),
                IndexModel([("scan_status", ASCENDING)]),
                IndexModel([("scan_result.risk_level", ASCENDING)]),
                IndexModel([("metadata.author", ASCENDING)]),
                IndexModel([("collection_info.channel", ASCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("updated_at", DESCENDING)]),
                IndexModel([("scan_result.vulnerability_count", DESCENDING)]),
                IndexModel([("scan_result.risk_score", DESCENDING)]),
            ])
            
            # Vulnerabilities collection indexes
            vuln_collection = self.database.vulnerabilities
            await vuln_collection.create_indexes([
                IndexModel([("vulnerability_id", ASCENDING)], unique=True),
                IndexModel([("skill_id", ASCENDING)]),
                IndexModel([("category", ASCENDING)]),
                IndexModel([("pattern", ASCENDING)]),
                IndexModel([("severity", ASCENDING)]),
                IndexModel([("confidence", DESCENDING)]),
                IndexModel([("detected_at", DESCENDING)]),
                IndexModel([("false_positive", ASCENDING)]),
                IndexModel([("verified", ASCENDING)]),
                IndexModel([("skill_language", ASCENDING)]),
                IndexModel([("skill_platform", ASCENDING)]),
                IndexModel([("category", ASCENDING), ("severity", ASCENDING)]),
                IndexModel([("skill_id", ASCENDING), ("category", ASCENDING)]),
                IndexModel([("detected_at", DESCENDING), ("severity", ASCENDING)]),
            ])
            
            # Configurations collection indexes
            config_collection = self.database.configurations
            await config_collection.create_indexes([
                IndexModel([("config_type", ASCENDING)]),
                IndexModel([("language", ASCENDING)]),
                IndexModel([("version", ASCENDING)]),
                IndexModel([("enabled", ASCENDING)]),
                IndexModel([("updated_at", DESCENDING)]),
            ])
            
            # Scan tasks collection indexes
            tasks_collection = self.database.scan_tasks
            await tasks_collection.create_indexes([
                IndexModel([("task_id", ASCENDING)], unique=True),
                IndexModel([("status", ASCENDING)]),
                IndexModel([("priority", DESCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
            ])
            
            logger.info("Database indexes created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
    
    def get_collection(self, name: str):
        """Get a MongoDB collection."""
        if not self.database:
            raise RuntimeError("Database not connected")
        return self.database[name]
    
    @property
    def skills(self):
        """Get skills collection."""
        return self.get_collection("skills")
    
    @property
    def vulnerabilities(self):
        """Get vulnerabilities collection."""
        return self.get_collection("vulnerabilities")
    
    @property
    def configurations(self):
        """Get configurations collection."""
        return self.get_collection("configurations")
    
    @property
    def scan_tasks(self):
        """Get scan tasks collection."""
        return self.get_collection("scan_tasks")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check MongoDB health status."""
        try:
            # Ping database
            await self.client.admin.command('ping')
            
            # Get server status
            status = await self.client.admin.command('serverStatus')
            
            # Get collection stats
            db_stats = await self.database.command('dbStats')
            
            return {
                "status": "healthy",
                "version": status.get("version", "unknown"),
                "connections": status.get("connections", {}),
                "collections": {
                    "skills": await self.skills.count_documents({}),
                    "vulnerabilities": await self.vulnerabilities.count_documents({}),
                    "configurations": await self.configurations.count_documents({}),
                    "scan_tasks": await self.scan_tasks.count_documents({}),
                },
                "storage": {
                    "data_size": db_stats.get("dataSize", 0),
                    "storage_size": db_stats.get("storageSize", 0),
                    "indexes": db_stats.get("totalIndexSize", 0),
                },
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
            }
    
    async def ensure_indexes(self):
        """Ensure all indexes exist (idempotent operation)."""
        await self._create_indexes()