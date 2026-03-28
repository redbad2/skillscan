"""
技能文件数据模型

定义技能文件的MongoDB文档结构。
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId


class PyObjectId(ObjectId):
    """自定义ObjectId类型，用于Pydantic"""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, *args, **kwargs):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, *args, **kwargs):
        return {"type": "string"}


class ScanStatus(str, Enum):
    """扫描状态枚举"""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, Enum):
    """风险等级枚举"""

    SAFE = "safe"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    MALICIOUS = "malicious"


class ScriptFile(BaseModel):
    """脚本文件模型"""

    filename: str
    content: str
    language: str  # Python, Shell, JavaScript, etc.
    file_hash: str  # MD5或SHA256
    size: Optional[int] = None


class SkillMetadata(BaseModel):
    """技能元数据模型"""

    author: Optional[str] = None
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    triggers: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)


class SkillFile(BaseModel):
    """技能文件内容"""

    skill_md: str  # SKILL.md文件内容
    scripts: List[ScriptFile] = Field(default_factory=list)


class ScanResult(BaseModel):
    """扫描结果模型"""

    scan_time: Optional[datetime] = None
    status: str = "pending"
    vulnerabilities: List[str] = Field(default_factory=list)  # 漏洞ID列表
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.SAFE
    scan_duration_ms: int = 0
    scanner_version: str = "1.0.0"
    vulnerability_count: Dict[str, int] = Field(default_factory=dict)  # 各类别漏洞数量


class CollectionInfo(BaseModel):
    """数据收集信息"""

    channel: str  # "network_crawl" 或 "local_scan"
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    original_path: str  # 本地文件路径或网络URL
    file_size: Optional[int] = None


class SkillModel(BaseModel):
    """技能文件完整模型"""

    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    skill_id: str  # 唯一标识符
    name: str
    version: str = "1.0.0"
    source: str  # "network" 或 "local"
    platform: str  # "clawhub", "smithery", "skillssh", "local"
    language: str  # "en", "zh", "ja", "ko", "mixed"
    metadata: SkillMetadata = Field(default_factory=SkillMetadata)
    files: SkillFile
    scan_status: ScanStatus = ScanStatus.PENDING
    scan_result: ScanResult = Field(default_factory=ScanResult)
    collection_info: CollectionInfo
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
    )


class SkillModelDB:
    """技能模型数据库操作"""

    COLLECTION_NAME = "skills"

    def __init__(self, db_manager):
        self.db_manager = db_manager

    async def create(self, skill: SkillModel) -> str:
        """创建技能记录"""
        skill_dict = skill.model_dump(by_alias=True, exclude={"id"})
        skill_dict["created_at"] = datetime.utcnow()
        skill_dict["updated_at"] = datetime.utcnow()
        return await self.db_manager.insert_one(self.COLLECTION_NAME, skill_dict)

    async def get_by_id(self, skill_id: str) -> Optional[Dict[str, Any]]:
        """根据skill_id获取技能"""
        return await self.db_manager.find_one(self.COLLECTION_NAME, {"skill_id": skill_id})

    async def get_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """根据文件哈希获取技能（用于去重）"""
        return await self.db_manager.find_one(
            self.COLLECTION_NAME, {"files.scripts.file_hash": file_hash}
        )

    async def update_scan_status(
        self, skill_id: str, status: ScanStatus, result: Optional[ScanResult] = None
    ) -> bool:
        """更新扫描状态"""
        update_data = {
            "scan_status": status.value,
            "updated_at": datetime.utcnow(),
        }
        if result:
            update_data["scan_result"] = result.model_dump()
        return await self.db_manager.update_one(
            self.COLLECTION_NAME, {"skill_id": skill_id}, update_data
        )

    async def find_by_platform(
        self, platform: str, skip: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """根据平台查询技能"""
        return await self.db_manager.find_many(
            self.COLLECTION_NAME,
            {"platform": platform},
            skip=skip,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_by_risk_level(
        self, risk_level: str, skip: int = 0, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """根据风险等级查询技能"""
        return await self.db_manager.find_many(
            self.COLLECTION_NAME,
            {"scan_result.risk_level": risk_level},
            skip=skip,
            limit=limit,
            sort=[("scan_result.risk_score", -1)],
        )

    async def find_pending_skills(self, limit: int = 100) -> List[Dict[str, Any]]:
        """查找待扫描的技能"""
        return await self.db_manager.find_many(
            self.COLLECTION_NAME,
            {"scan_status": ScanStatus.PENDING.value},
            limit=limit,
            sort=[("created_at", 1)],
        )

    async def count_by_platform(self) -> List[Dict[str, Any]]:
        """统计各平台技能数量"""
        pipeline = [
            {"$group": {"_id": "$platform", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return await self.db_manager.aggregate(self.COLLECTION_NAME, pipeline)

    async def count_by_risk_level(self) -> List[Dict[str, Any]]:
        """统计各风险等级技能数量"""
        pipeline = [
            {"$group": {"_id": "$scan_result.risk_level", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return await self.db_manager.aggregate(self.COLLECTION_NAME, pipeline)
