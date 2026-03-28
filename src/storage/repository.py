"""
Repository classes for data access.
"""

import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from bson import ObjectId

from ..models import (
    SkillDocument, VulnerabilityDocument, PlatformConfig,
    ScanStatus, RiskLevel, VulnerabilityCategory, Language
)
from .mongodb import MongoDBStorage

logger = logging.getLogger(__name__)


class SkillRepository:
    """Repository for skill document operations."""
    
    def __init__(self, storage: MongoDBStorage):
        self.storage = storage
        self.collection = storage.skills
    
    async def insert(self, skill: SkillDocument) -> str:
        """Insert a skill document."""
        doc = skill.dict(by_alias=True, exclude_none=True)
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)
    
    async def insert_many(self, skills: List[SkillDocument]) -> List[str]:
        """Insert multiple skill documents."""
        docs = [skill.dict(by_alias=True, exclude_none=True) for skill in skills]
        result = await self.collection.insert_many(docs)
        return [str(id) for id in result.inserted_ids]
    
    async def find_by_id(self, skill_id: str) -> Optional[SkillDocument]:
        """Find a skill by ID."""
        doc = await self.collection.find_one({"skill_id": skill_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            return SkillDocument(**doc)
        return None
    
    async def find_by_name(self, name: str, limit: int = 10) -> List[SkillDocument]:
        """Find skills by name."""
        cursor = self.collection.find(
            {"name": {"$regex": name, "$options": "i"}}
        ).limit(limit)
        
        skills = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            skills.append(SkillDocument(**doc))
        return skills
    
    async def find_by_platform(
        self, 
        platform: str, 
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[SkillDocument], int]:
        """Find skills by platform."""
        total = await self.collection.count_documents({"platform": platform})
        cursor = self.collection.find(
            {"platform": platform}
        ).skip(offset).limit(limit)
        
        skills = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            skills.append(SkillDocument(**doc))
        return skills, total
    
    async def find_by_language(
        self, 
        language: str, 
        limit: int = 100
    ) -> List[SkillDocument]:
        """Find skills by language."""
        cursor = self.collection.find({"language": language}).limit(limit)
        
        skills = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            skills.append(SkillDocument(**doc))
        return skills
    
    async def find_unscanned(self, limit: int = 100) -> List[SkillDocument]:
        """Find skills that haven't been scanned yet."""
        cursor = self.collection.find(
            {"scan_status": {"$in": ["pending", None]}}
        ).limit(limit)
        
        skills = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            skills.append(SkillDocument(**doc))
        return skills
    
    async def find_by_risk_level(
        self, 
        risk_level: RiskLevel, 
        limit: int = 100
    ) -> List[SkillDocument]:
        """Find skills by risk level."""
        cursor = self.collection.find(
            {"scan_result.risk_level": risk_level.value}
        ).limit(limit)
        
        skills = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            skills.append(SkillDocument(**doc))
        return skills
    
    async def update_scan_result(
        self, 
        skill_id: str, 
        scan_result: Dict[str, Any]
    ) -> bool:
        """Update scan result for a skill."""
        result = await self.collection.update_one(
            {"skill_id": skill_id},
            {
                "$set": {
                    "scan_result": scan_result,
                    "scan_status": "completed",
                    "updated_at": datetime.utcnow(),
                }
            }
        )
        return result.modified_count > 0
    
    async def update_scan_status(
        self, 
        skill_id: str, 
        status: str
    ) -> bool:
        """Update scan status for a skill."""
        result = await self.collection.update_one(
            {"skill_id": skill_id},
            {
                "$set": {
                    "scan_status": status,
                    "updated_at": datetime.utcnow(),
                }
            }
        )
        return result.modified_count > 0
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about skills."""
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "scanned": {
                        "$sum": {"$cond": [
                            {"$eq": ["$scan_status", "completed"]}, 1, 0
                        ]}
                    },
                    "pending": {
                        "$sum": {"$cond": [
                            {"$eq": ["$scan_status", "pending"]}, 1, 0
                            ]}
                    },
                }
            }
        ]
        
        async for result in self.collection.aggregate(pipeline):
            return result
        
        return {"total": 0, "scanned": 0, "pending": 0}
    
    async def get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of risk levels."""
        pipeline = [
            {"$match": {"scan_result.risk_level": {"$exists": True}}},
            {
                "$group": {
                    "_id": "$scan_result.risk_level",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        distribution = {}
        async for result in self.collection.aggregate(pipeline):
            distribution[result["_id"]] = result["count"]
        
        return distribution
    
    async def delete(self, skill_id: str) -> bool:
        """Delete a skill by ID."""
        result = await self.collection.delete_one({"skill_id": skill_id})
        return result.deleted_count > 0


class VulnerabilityRepository:
    """Repository for vulnerability document operations."""
    
    def __init__(self, storage: MongoDBStorage):
        self.storage = storage
        self.collection = storage.vulnerabilities
    
    async def insert(self, vulnerability: VulnerabilityDocument) -> str:
        """Insert a vulnerability document."""
        doc = vulnerability.dict(by_alias=True, exclude_none=True)
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)
    
    async def insert_many(self, vulnerabilities: List[VulnerabilityDocument]) -> List[str]:
        """Insert multiple vulnerability documents."""
        docs = [v.dict(by_alias=True, exclude_none=True) for v in vulnerabilities]
        result = await self.collection.insert_many(docs)
        return [str(id) for id in result.inserted_ids]
    
    async def find_by_skill_id(self, skill_id: str) -> List[VulnerabilityDocument]:
        """Find vulnerabilities by skill ID."""
        cursor = self.collection.find({"skill_id": skill_id})
        
        vulns = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            vulns.append(VulnerabilityDocument(**doc))
        return vulns
    
    async def find_by_category(
        self, 
        category: str, 
        limit: int = 100
    ) -> List[VulnerabilityDocument]:
        """Find vulnerabilities by category."""
        cursor = self.collection.find({"category": category}).limit(limit)
        
        vulns = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            vulns.append(VulnerabilityDocument(**doc))
        return vulns
    
    async def find_by_severity(
        self, 
        severity: str, 
        limit: int = 100
    ) -> List[VulnerabilityDocument]:
        """Find vulnerabilities by severity."""
        cursor = self.collection.find({"severity": severity}).limit(limit)
        
        vulns = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            vulns.append(VulnerabilityDocument(**doc))
        return vulns
    
    async def mark_false_positive(self, vulnerability_id: str) -> bool:
        """Mark a vulnerability as false positive."""
        result = await self.collection.update_one(
            {"vulnerability_id": vulnerability_id},
            {
                "$set": {
                    "false_positive": True,
                    "updated_at": datetime.utcnow(),
                }
            }
        )
        return result.modified_count > 0
    
    async def verify(self, vulnerability_id: str, notes: Optional[str] = None) -> bool:
        """Mark a vulnerability as verified."""
        update_data = {
            "verified": True,
            "updated_at": datetime.utcnow(),
        }
        if notes:
            update_data["notes"] = notes
        
        result = await self.collection.update_one(
            {"vulnerability_id": vulnerability_id},
            {"$set": update_data}
        )
        return result.modified_count > 0
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about vulnerabilities."""
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "false_positives": {
                        "$sum": {"$cond": ["$false_positive", 1, 0]}
                    },
                    "verified": {
                        "$sum": {"$cond": ["$verified", 1, 0]}
                    },
                    "avg_confidence": {"$avg": "$confidence"},
                }
            }
        ]
        
        async for result in self.collection.aggregate(pipeline):
            return result
        
        return {"total": 0, "false_positives": 0, "verified": 0, "avg_confidence": 0}
    
    async def get_category_distribution(self) -> Dict[str, int]:
        """Get distribution of vulnerability categories."""
        pipeline = [
            {
                "$group": {
                    "_id": "$category",
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"count": -1}}
        ]
        
        distribution = {}
        async for result in self.collection.aggregate(pipeline):
            distribution[result["_id"]] = result["count"]
        
        return distribution
    
    async def get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of vulnerability severities."""
        pipeline = [
            {
                "$group": {
                    "_id": "$severity",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        distribution = {}
        async for result in self.collection.aggregate(pipeline):
            distribution[result["_id"]] = result["count"]
        
        return distribution
    
    async def get_top_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most common vulnerability patterns."""
        pipeline = [
            {
                "$group": {
                    "_id": "$pattern",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence"},
                }
            },
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]
        
        patterns = []
        async for result in self.collection.aggregate(pipeline):
            patterns.append({
                "pattern": result["_id"],
                "count": result["count"],
                "avg_confidence": result["avg_confidence"],
            })
        
        return patterns


class ConfigRepository:
    """Repository for configuration operations."""
    
    def __init__(self, storage: MongoDBStorage):
        self.storage = storage
        self.collection = storage.configurations
    
    async def save_config(self, config: PlatformConfig) -> str:
        """Save a configuration."""
        doc = config.dict(by_alias=True, exclude_none=True)
        
        # Upsert based on config_type and language
        result = await self.collection.update_one(
            {
                "config_type": config.config_type,
                "language": config.language,
            },
            {"$set": doc},
            upsert=True
        )
        
        if result.upserted_id:
            return str(result.upserted_id)
        return config.config_type
    
    async def get_config(
        self, 
        config_type: str, 
        language: str = "all"
    ) -> Optional[PlatformConfig]:
        """Get a configuration."""
        doc = await self.collection.find_one({
            "config_type": config_type,
            "language": language,
        })
        
        if doc:
            doc["_id"] = str(doc["_id"])
            return PlatformConfig(**doc)
        return None
    
    async def list_configs(self, config_type: Optional[str] = None) -> List[PlatformConfig]:
        """List configurations."""
        query = {}
        if config_type:
            query["config_type"] = config_type
        
        cursor = self.collection.find(query)
        
        configs = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            configs.append(PlatformConfig(**doc))
        
        return configs