"""
混合分类引擎

结合静态分析和LLM分析结果，实现安全保守的聚合逻辑。
"""

import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime

from loguru import logger

from src.config import get_settings, RiskLevel
from src.analyzers.static_analyzer import StaticAnalyzer
from src.analyzers.llm_analyzer import LLMAnalyzer

try:
    from src.config.llm_config_manager import llm_config_manager
except ImportError:
    llm_config_manager = None


class HybridAnalyzer:
    """混合分类分析器"""

    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.settings = get_settings()
        self.static_analyzer = StaticAnalyzer(db_manager)
        self.llm_analyzer = LLMAnalyzer()

    async def analyze(
        self,
        skill_md: str,
        scripts: List[Dict[str, str]],
        skill_id: str,
        language: Optional[str] = None,
        skip_llm: bool = False,
    ) -> Dict[str, Any]:
        """
        执行混合分析

        Args:
            skill_md: SKILL.md内容
            scripts: 脚本文件列表
            skill_id: 技能ID
            language: 技能文件的主要语言
            skip_llm: 是否跳过LLM分析（用于性能优化）

        Returns:
            分析结果
        """
        start_time = datetime.utcnow()
        all_vulnerabilities: List[Dict[str, Any]] = []

        if llm_config_manager is not None:
            llm_config = llm_config_manager.get_config()
        else:
            llm_config = self.settings.get_llm_config()

        # 第一阶段：静态分析（高召回率）
        logger.debug(f"Running static analysis for {skill_id}")
        static_result = await self.static_analyzer.analyze(
            skill_md=skill_md,
            scripts=scripts,
            skill_id=skill_id,
            language=language,
        )
        static_vulns = static_result.get("vulnerabilities", [])
        all_vulnerabilities.extend(static_vulns)

        logger.debug(f"Static analysis found {len(static_vulns)} potential vulnerabilities")

        # 第二阶段：LLM分析（可选，精确度提升）
        llm_vulns = []
        if not skip_llm and llm_config.get("enabled", True) and llm_config.get("api_key"):
            try:
                logger.debug(f"Running LLM analysis for {skill_id}")
                llm_result = await self.llm_analyzer.analyze(
                    skill_md=skill_md,
                    scripts=scripts,
                    skill_id=skill_id,
                    language=language,
                )
                llm_vulns = llm_result.get("vulnerabilities", [])
                logger.debug(f"LLM analysis found {len(llm_vulns)} potential vulnerabilities")
            except Exception as e:
                logger.warning(f"LLM analysis failed: {e}")

        # 第三阶段：混合分类和聚合
        final_vulnerabilities = await self._merge_results(
            static_vulns=static_vulns,
            llm_vulns=llm_vulns,
            skill_id=skill_id,
        )

        # 计算风险评分
        risk_score, risk_level = self._calculate_final_risk(final_vulnerabilities)

        # 统计漏洞数量
        vuln_count = self._count_vulnerabilities(final_vulnerabilities)

        # 计算耗时
        end_time = datetime.utcnow()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        return {
            "skill_id": skill_id,
            "vulnerabilities": final_vulnerabilities,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "vulnerability_count": vuln_count,
            "scan_duration_ms": duration_ms,
            "scanner_version": "1.0.0",
            "static_findings": len(static_vulns),
            "llm_findings": len(llm_vulns),
            "final_findings": len(final_vulnerabilities),
        }

    async def _merge_results(
        self,
        static_vulns: List[Dict[str, Any]],
        llm_vulns: List[Dict[str, Any]],
        skill_id: str,
    ) -> List[Dict[str, Any]]:
        """
        合并静态分析和LLM分析结果

        策略：安全保守 - 宁可误报，不可漏报
        """
        merged: Dict[str, Dict[str, Any]] = {}

        # 首先添加所有静态分析结果
        for vuln in static_vulns:
            key = self._create_vuln_key(vuln)
            if key not in merged:
                merged[key] = vuln.copy()
                merged[key]["detection_method"] = "static"
                merged[key]["confirmed_by_llm"] = False

        # 处理LLM分析结果
        for llm_vuln in llm_vulns:
            key = self._create_vuln_key(llm_vuln)

            if key in merged:
                # 静态分析已发现，LLM确认
                merged[key]["confirmed_by_llm"] = True
                merged[key]["confidence"] = min(merged[key]["confidence"] + 0.1, 1.0)
            else:
                # LLM单独发现，使用较低置信度
                merged_vuln = llm_vuln.copy()
                merged_vuln["detection_method"] = "llm"
                merged_vuln["confirmed_by_llm"] = True
                # 使用 LLM 配置中的确认阈值
                llm_config = self.settings.get_llm_config()
                llm_threshold = llm_config.get("confirm_threshold", 0.7)
                # LLM发现的漏洞，使用配置中的阈值
                if merged_vuln.get("confidence", 0) >= llm_threshold:
                    merged[key] = merged_vuln

        # 如果LLM推翻了静态发现（高置信度LLM认为安全）
        # 这里简化处理，实际可以更复杂

        return list(merged.values())

    def _create_vuln_key(self, vuln: Dict[str, Any]) -> str:
        """创建漏洞唯一键"""
        pattern = vuln.get("pattern", "unknown")
        file = vuln.get("evidence", {}).get("file", "unknown")
        line = vuln.get("evidence", {}).get("line", 0)

        return f"{pattern}:{file}:{line}"

    def _calculate_final_risk(self, vulnerabilities: List[Dict[str, Any]]) -> tuple:
        """计算最终风险评分"""
        if not vulnerabilities:
            return 0.0, RiskLevel.SAFE

        # 严重程度权重
        severity_weights = {
            "high": 1.0,
            "medium": 0.5,
            "low": 0.2,
        }

        # 检测方法加权
        method_weights = {
            "static": 1.0,
            "llm": 0.8,
            "hybrid": 1.2,
        }

        total_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            confidence = vuln.get("confidence", 0.5)
            method = vuln.get("detection_method", "static")
            confirmed = vuln.get("confirmed_by_llm", False)

            base_score = severity_weights.get(severity, 0.2) * confidence
            method_weight = method_weights.get(method, 1.0)

            # LLM确认的加权
            if confirmed:
                method_weight *= 1.1

            total_score += base_score * method_weight

        # 归一化
        risk_score = min(total_score / 5.0, 1.0)

        # 确定风险等级
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        if risk_score >= 0.7 or high_count >= 3:
            risk_level = RiskLevel.MALICIOUS
        elif risk_score >= 0.5 or high_count >= 2:
            risk_level = RiskLevel.DANGEROUS
        elif risk_score >= 0.3 or high_count >= 1:
            risk_level = RiskLevel.WARNING
        else:
            risk_level = RiskLevel.SAFE

        return round(risk_score, 2), risk_level

    def _count_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """统计各类漏洞数量"""
        counts: Dict[str, int] = {}

        for vuln in vulnerabilities:
            category = vuln.get("category", "unknown")
            counts[category] = counts.get(category, 0) + 1

        return counts

    async def batch_analyze(
        self,
        skills: List[Dict[str, Any]],
        max_concurrent: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        批量分析技能

        Args:
            skills: 技能列表
            max_concurrent: 最大并发数

        Returns:
            分析结果列表
        """
        import asyncio
        from tqdm import tqdm

        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def analyze_with_semaphore(skill: Dict[str, Any]):
            async with semaphore:
                try:
                    result = await self.analyze(
                        skill_md=skill.get("files", {}).get("skill_md", ""),
                        scripts=skill.get("files", {}).get("scripts", []),
                        skill_id=skill.get("skill_id", "unknown"),
                        language=skill.get("language"),
                        skip_llm=True,  # 批量分析时跳过LLM以提升性能
                    )
                    return result
                except Exception as e:
                    logger.error(f"Error analyzing skill {skill.get('skill_id')}: {e}")
                    return None

        tasks = [analyze_with_semaphore(skill) for skill in skills]

        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                results.append(result)

        return results
