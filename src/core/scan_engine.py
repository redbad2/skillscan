"""
扫描引擎模块

整合数据收集，分析和存储的完整扫描流程。
"""

import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from loguru import logger

from src.collectors.local_collector import LocalCollector
from src.collectors.base import SkillSource
from src.analyzers.hybrid_analyzer import HybridAnalyzer
from src.storage.mongodb import MongoDBStorage
from src.storage.repository import SkillRepository, VulnerabilityRepository
from src.config import get_settings


class ScanEngine:
    """扫描引擎 - 整合完整的扫描流程"""

    def __init__(self, mongodb: Optional[MongoDBStorage] = None):
        self.settings = get_settings()
        self.mongodb = mongodb
        self.skill_repo: Optional[SkillRepository] = None
        self.vuln_repo: Optional[VulnerabilityRepository] = None
        self.analyzer = HybridAnalyzer()

        if mongodb:
            self.skill_repo = SkillRepository(mongodb)
            self.vuln_repo = VulnerabilityRepository(mongodb)

    async def initialize(self) -> bool:
        """初始化连接"""
        if self.mongodb:
            connected = await self.mongodb.connect()
            if connected:
                logger.info("MongoDB connected successfully")
                return True
            else:
                logger.warning("MongoDB connection failed, running without persistence")
                return False
        else:
            # 尝试使用配置中的 MongoDB 设置创建连接
            db_config = self.settings.get_database_config()
            mongodb_settings = db_config.get("mongodb", {})
            if mongodb_settings.get("enabled", True):
                try:
                    self.mongodb = MongoDBStorage(
                        connection_string=mongodb_settings.get("connection_string"),
                        database=mongodb_settings.get("database", "skillscan"),
                    )
                    connected = await self.mongodb.connect()
                    if connected:
                        logger.info("MongoDB connected via config successfully")
                        self.skill_repo = SkillRepository(self.mongodb)
                        self.vuln_repo = VulnerabilityRepository(self.mongodb)
                        return True
                except Exception as e:
                    logger.warning(f"MongoDB config connection failed: {e}")
        return False

    async def shutdown(self):
        """关闭连接"""
        if self.mongodb:
            await self.mongodb.disconnect()
            logger.info("MongoDB disconnected")

    async def scan_local_directory(
        self,
        path: str,
        limit: Optional[int] = None,
        skip_llm: bool = False,
        save_to_db: bool = True,
    ) -> Dict[str, Any]:
        """
        扫描本地目录

        Args:
            path: 本地目录路径
            limit: 最大扫描数量
            skip_llm: 跳过LLM分析
            save_to_db: 保存结果到MongoDB

        Returns:
            扫描结果统计
        """
        start_time = datetime.utcnow()
        collector = LocalCollector()

        # 收集技能文件
        logger.info(f"Collecting skills from {path}")
        skills = await collector.scan_path(path, limit=limit)
        logger.info(f"Found {len(skills)} skills")

        if not skills:
            return {
                "total_skills": 0,
                "vulnerabilities": [],
                "scan_duration_ms": 0,
            }

        # 分析技能文件
        results = []
        all_vulnerabilities = []

        for skill in skills:
            result = await self._analyze_and_store_skill(
                skill=skill,
                skip_llm=skip_llm,
                save_to_db=save_to_db,
            )
            results.append(result)
            all_vulnerabilities.extend(result.get("vulnerabilities", []))

        # 计算统计信息
        stats = self._calculate_statistics(results, all_vulnerabilities)

        end_time = datetime.utcnow()
        scan_duration = int((end_time - start_time).total_seconds() * 1000)

        return {
            "total_skills": len(skills),
            "scan_results": results,
            "statistics": stats,
            "vulnerabilities": all_vulnerabilities,
            "scan_duration_ms": scan_duration,
            "scan_time": end_time.isoformat(),
        }

    async def _analyze_and_store_skill(
        self,
        skill: SkillSource,
        skip_llm: bool = False,
        save_to_db: bool = True,
    ) -> Dict[str, Any]:
        """分析单个技能并存储结果"""
        skill_id = skill.content_hash[:16]

        # 转换脚本格式
        scripts = []
        for script in skill.scripts:
            scripts.append(
                {
                    "filename": script.get("filename", "unknown"),
                    "content": script.get("content", ""),
                    "language": script.get("language", "unknown"),
                }
            )

        # 执行分析
        try:
            result = await self.analyzer.analyze(
                skill_md=skill.content,
                scripts=scripts,
                skill_id=skill_id,
                language=None,
                skip_llm=skip_llm,
            )
        except Exception as e:
            logger.error(f"Error analyzing skill {skill.name}: {e}")
            result = {
                "skill_id": skill_id,
                "vulnerabilities": [],
                "vulnerability_count": {},
                "risk_score": 0.0,
                "risk_level": "safe",
            }

        # 构建完整结果
        analysis_result = {
            "skill_id": skill_id,
            "name": skill.name,
            "platform": skill.platform,
            "source": skill.channel.value
            if hasattr(skill.channel, "value")
            else str(skill.channel),
            "language": self._detect_language(skill.content),
            "vulnerabilities": result.get("vulnerabilities", []),
            "vulnerability_count": result.get("vulnerability_count", {}),
            "risk_score": result.get("risk_score", 0.0),
            "risk_level": result.get("risk_level", "safe"),
            "scan_duration_ms": result.get("scan_duration_ms", 0),
        }

        # 保存到MongoDB
        if save_to_db and self.skill_repo:
            try:
                await self._save_to_mongodb(skill, analysis_result)
            except Exception as e:
                logger.error(f"Error saving to MongoDB: {e}")

        return analysis_result

    async def _save_to_mongodb(
        self,
        skill: SkillSource,
        analysis_result: Dict[str, Any],
    ):
        """保存技能和分析结果到MongoDB"""
        if not self.skill_repo:
            return

        # 构建SkillDocument
        from src.models.skill import (
            SkillModel,
            SkillFile,
            ScriptFile,
            SkillMetadata,
            ScanResult,
            CollectionInfo,
            ScanStatus,
            RiskLevel,
        )

        skill_id = analysis_result["skill_id"]

        # 检查是否已存在
        existing = await self.skill_repo.find_by_id(skill_id)

        # 构建脚本文件列表
        scripts = []
        for script in skill.scripts:
            script_file = ScriptFile(
                filename=script.get("filename", "unknown"),
                content=script.get("content", ""),
                language=script.get("language", "unknown"),
                file_hash="",  # 可以计算
            )
            scripts.append(script_file)

        # 构建扫描结果
        scan_result = ScanResult(
            scan_time=datetime.utcnow(),
            status="completed",
            vulnerabilities=[],
            risk_score=analysis_result.get("risk_score", 0.0),
            risk_level=RiskLevel(analysis_result.get("risk_level", "safe")),
            scan_duration_ms=analysis_result.get("scan_duration_ms", 0),
            vulnerability_count=analysis_result.get("vulnerability_count", {}),
        )

        if existing:
            # 更新现有记录
            await self.skill_repo.update_scan_result(skill_id, scan_result.model_dump())
            logger.info(f"Updated skill {skill_id} in MongoDB")
        else:
            # 创建新记录
            skill_model = SkillModel(
                skill_id=skill_id,
                name=skill.name,
                version="1.0.0",
                source="network" if "crawl" in str(skill.channel).lower() else "local",
                platform=skill.platform,
                language=analysis_result.get("language", "unknown"),
                metadata=SkillMetadata(
                    author=skill.metadata.get("author")
                    if isinstance(skill.metadata, dict)
                    else None,
                    description=skill.metadata.get("description")
                    if isinstance(skill.metadata, dict)
                    else None,
                ),
                files=SkillFile(
                    skill_md=skill.content,
                    scripts=scripts,
                ),
                scan_status=ScanStatus.COMPLETED,
                scan_result=scan_result,
                collection_info=CollectionInfo(
                    channel=str(skill.channel),
                    original_path=skill.source_path or "",
                    file_size=skill.file_size or 0,
                ),
            )
            await self.skill_repo.insert(skill_model)
            logger.info(f"Saved new skill {skill_id} to MongoDB")

    def _detect_language(self, content: str) -> str:
        """检测内容的主要语言"""
        # 简单的语言检测
        import re

        # 中文字符计数
        chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", content))
        # 日文字符（平假名、片假名）
        japanese_chars = len(re.findall(r"[\u3040-\u309f\u30a0-\u30ff]", content))
        # 韩文字符
        korean_chars = len(re.findall(r"[\uac00-\ud7af\u1100-\u11ff]", content))

        total = len(content)

        if total == 0:
            return "unknown"

        # 计算比例
        chinese_ratio = chinese_chars / total
        japanese_ratio = japanese_chars / total
        korean_ratio = korean_chars / total

        # 判断主要语言
        if chinese_ratio > 0.3:
            return "zh"
        elif japanese_ratio > 0.1:
            return "ja"
        elif korean_chars > 0.1:
            return "ko"
        else:
            return "en"

    def _calculate_statistics(
        self,
        results: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """计算扫描统计信息"""
        total = len(results)

        if total == 0:
            return {
                "total_skills": 0,
                "risk_distribution": {},
                "category_distribution": {},
                "platform_distribution": {},
            }

        # 风险分布
        risk_counts = {"safe": 0, "warning": 0, "dangerous": 0, "malicious": 0}
        category_counts: Dict[str, int] = {}
        platform_counts: Dict[str, int] = {}

        for result in results:
            risk_level = result.get("risk_level", "safe")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

            platform = result.get("platform", "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

            vuln_count = result.get("vulnerability_count", {})
            for category, count in vuln_count.items():
                category_counts[category] = category_counts.get(category, 0) + count

        return {
            "total_skills": total,
            "risk_distribution": risk_counts,
            "category_distribution": category_counts,
            "platform_distribution": platform_counts,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerable_percentage": (
                (total - risk_counts.get("safe", 0)) / total * 100 if total > 0 else 0
            ),
        }

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """从MongoDB获取扫描统计信息"""
        if not self.skill_repo:
            return {"error": "MongoDB not connected"}

        try:
            # 技能统计
            skill_stats = await self.skill_repo.get_statistics()
            risk_distribution = await self.skill_repo.get_risk_distribution()

            return {
                "skills": skill_stats,
                "risk_distribution": risk_distribution,
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {"error": str(e)}

    async def list_skills(
        self,
        platform: Optional[str] = None,
        risk_level: Optional[str] = None,
        language: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """查询技能列表"""
        if not self.skill_repo:
            return {"skills": [], "total": 0}

        try:
            from src.models.skill import RiskLevel

            if risk_level:
                skills = await self.skill_repo.find_by_risk_level(RiskLevel(risk_level), limit)
            elif platform:
                skills, total = await self.skill_repo.find_by_platform(platform, skip, limit)
            else:
                skills = await self.skill_repo.find_unscanned(limit)
                total = len(skills)

            return {
                "skills": skills,
                "total": total,
                "skip": skip,
                "limit": limit,
            }
        except Exception as e:
            logger.error(f"Error listing skills: {e}")
            return {"skills": [], "total": 0, "error": str(e)}

    async def list_vulnerabilities(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        skill_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """查询漏洞列表"""
        if not self.vuln_repo:
            return {"vulnerabilities": [], "total": 0}

        try:
            if skill_id:
                vulns = await self.vuln_repo.find_by_skill_id(skill_id)
            elif category:
                vulns = await self.vuln_repo.find_by_category(category, limit)
            elif severity:
                vulns = await self.vuln_repo.find_by_severity(severity, limit)
            else:
                vulns = []

            return {
                "vulnerabilities": vulns[skip : skip + limit],
                "total": len(vulns),
                "skip": skip,
                "limit": limit,
            }
        except Exception as e:
            logger.error(f"Error listing vulnerabilities: {e}")
            return {"vulnerabilities": [], "total": 0, "error": str(e)}
