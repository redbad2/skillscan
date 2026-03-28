"""
MongoDB数据库管理模块

管理MongoDB连接、索引和基础操作。
"""

from typing import Optional, Dict, Any, List
from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from loguru import logger

from src.config import get_settings


class DatabaseManager:
    """MongoDB数据库管理器"""

    def __init__(self, uri: Optional[str] = None, database: Optional[str] = None):
        settings = get_settings()
        self.uri = uri or settings.mongodb_uri
        self.database_name = database or settings.mongodb_database
        self.max_pool_size = settings.mongodb_max_pool_size
        self.min_pool_size = settings.mongodb_min_pool_size
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None

    async def connect(self) -> None:
        """连接到MongoDB"""
        try:
            self.client = AsyncIOMotorClient(
                self.uri,
                maxPoolSize=self.max_pool_size,
                minPoolSize=self.min_pool_size,
            )
            self.db = self.client[self.database_name]
            # 测试连接
            await self.client.admin.command("ping")
            logger.info(f"Connected to MongoDB: {self.database_name}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise

    async def disconnect(self) -> None:
        """断开MongoDB连接"""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")

    async def init_indexes(self) -> None:
        """初始化数据库索引"""
        # Skills集合索引
        skills_collection = self.db["skills"]
        await skills_collection.create_index("skill_id", unique=True)
        await skills_collection.create_index([("platform", 1), ("language", 1)])
        await skills_collection.create_index("scan_status")
        await skills_collection.create_index("scan_result.risk_level")
        await skills_collection.create_index("metadata.created_at")
        await skills_collection.create_index(
            [("files.skill_md", "text"), ("metadata.description", "text")]
        )

        # Vulnerabilities集合索引
        vuln_collection = self.db["vulnerabilities"]
        await vuln_collection.create_index("vulnerability_id", unique=True)
        await vuln_collection.create_index("skill_id")
        await vuln_collection.create_index([("category", 1), ("pattern", 1)])
        await vuln_collection.create_index("severity")
        await vuln_collection.create_index("detected_at")

        # Configurations集合索引
        config_collection = self.db["configurations"]
        await config_collection.create_index(
            [("config_type", 1), ("language", 1)], unique=True
        )

        # Scan tasks集合索引
        tasks_collection = self.db["scan_tasks"]
        await tasks_collection.create_index("task_id", unique=True)
        await tasks_collection.create_index("status")
        await tasks_collection.create_index("created_at")

        logger.info("Database indexes initialized")

    async def get_collection(self, name: str):
        """获取集合"""
        return self.db[name]

    async def insert_one(self, collection: str, document: Dict[str, Any]) -> str:
        """插入单个文档"""
        result = await self.db[collection].insert_one(document)
        return str(result.inserted_id)

    async def find_one(self, collection: str, filter_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """查找单个文档"""
        return await self.db[collection].find_one(filter_dict)

    async def find_many(
        self,
        collection: str,
        filter_dict: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort: Optional[List[tuple]] = None,
    ) -> List[Dict[str, Any]]:
        """查找多个文档"""
        cursor = self.db[collection].find(filter_dict).skip(skip).limit(limit)
        if sort:
            cursor = cursor.sort(sort)
        return await cursor.to_list(length=limit)

    async def update_one(
        self, collection: str, filter_dict: Dict[str, Any], update_dict: Dict[str, Any]
    ) -> bool:
        """更新单个文档"""
        result = await self.db[collection].update_one(filter_dict, {"$set": update_dict})
        return result.modified_count > 0

    async def count_documents(self, collection: str, filter_dict: Dict[str, Any] = None) -> int:
        """统计文档数量"""
        return await self.db[collection].count_documents(filter_dict or {})

    async def aggregate(self, collection: str, pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行聚合查询"""
        return await self.db[collection].aggregate(pipeline).to_list(length=None)


# 全局数据库管理器实例
_db_manager: Optional[DatabaseManager] = None


async def get_database() -> DatabaseManager:
    """获取数据库管理器实例"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        await _db_manager.connect()
        await _db_manager.init_indexes()
    return _db_manager
