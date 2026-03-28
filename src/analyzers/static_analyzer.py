"""
静态分析引擎

实现基于规则的静态代码分析，检测论文中定义的14种漏洞模式。
支持多语言检测，包括中文、英文、日文、韩文等。
"""

import re
import uuid
import hashlib
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field

from loguru import logger

from src.config.settings import get_settings

# Import constants from models.common (proper enums)
from src.models.common import (
    VulnerabilityCategory,
    VulnerabilityPattern,
    Severity,
)
from src.models.vulnerability import (
    VulnerabilityModel,
    VulnerabilityEvidence,
    VULNERABILITY_DESCRIPTIONS,
    VULNERABILITY_RECOMMENDATIONS,
)
from src.models.configuration import ConfigurationModelDB
from src.models.configuration import DEFAULT_DETECTION_RULES


@dataclass
class DetectionMatch:
    """检测匹配结果"""

    rule_id: str
    pattern: str
    category: str
    pattern_code: str
    severity: str
    confidence: float
    file: str
    line: Optional[int]
    snippet: str
    context: Optional[str] = None
    language: str = "all"
    char_start: Optional[int] = None
    char_end: Optional[int] = None


class StaticAnalyzer:
    """静态分析引擎"""

    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.settings = get_settings()
        self._compiled_rules: Dict[str, re.Pattern] = {}
        self._rules_cache: Optional[List[Dict]] = None

    async def analyze(
        self,
        skill_md: str,
        scripts: List[Dict[str, str]],
        skill_id: str,
        language: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        执行静态分析

        Args:
            skill_md: SKILL.md内容
            scripts: 脚本文件列表 [{filename, content, language}, ...]
            skill_id: 技能ID
            language: 技能文件的主要语言

        Returns:
            分析结果
        """
        start_time = datetime.utcnow()
        all_matches: List[DetectionMatch] = []

        # 获取检测规则
        rules = await self._get_rules(language)

        # 分析SKILL.md
        if skill_md:
            skill_matches = await self._analyze_content(
                content=skill_md,
                filename="SKILL.md",
                rules=rules,
                skill_language=language,
            )
            all_matches.extend(skill_matches)

        # 分析脚本文件
        for script in scripts:
            if not script.get("content"):
                continue

            script_matches = await self._analyze_content(
                content=script["content"],
                filename=script.get("filename", "unknown"),
                rules=rules,
                script_language=script.get("language"),
                skill_language=language,
            )
            all_matches.extend(script_matches)

        # 生成漏洞记录
        vulnerabilities = await self._create_vulnerabilities(
            matches=all_matches,
            skill_id=skill_id,
            language=language,
        )

        # 计算风险评分
        risk_score, risk_level = self._calculate_risk_score(vulnerabilities)

        # 统计各类漏洞数量
        vuln_count = self._count_vulnerabilities(vulnerabilities)

        # 计算耗时
        end_time = datetime.utcnow()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        return {
            "vulnerabilities": vulnerabilities,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "vulnerability_count": vuln_count,
            "scan_duration_ms": duration_ms,
            "scanner_version": "1.0.0",
            "rules_used": len(rules),
        }

    async def _get_rules(self, language: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取检测规则"""
        # 优先从数据库获取
        if self.db_manager:
            try:
                config_db = ConfigurationModelDB(self.db_manager)
                rules = await config_db.get_detection_rules(language=language)
                if rules:
                    return rules
            except Exception as e:
                logger.warning(f"Failed to load rules from database: {e}")

        # 使用默认规则
        if language:
            return [
                r
                for r in DEFAULT_DETECTION_RULES
                if r.get("language") == "all" or r.get("language") == language
            ]
        return DEFAULT_DETECTION_RULES

    async def _analyze_content(
        self,
        content: str,
        filename: str,
        rules: List[Dict[str, Any]],
        script_language: Optional[str] = None,
        skill_language: Optional[str] = None,
    ) -> List[DetectionMatch]:
        """分析内容"""
        matches: List[DetectionMatch] = []

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            rule_id = rule["rule_id"]
            pattern = rule["pattern"]
            category = rule["category"]
            pattern_code = rule["pattern_code"]
            severity = rule["severity"]
            rule_language = rule.get("language", "all")

            # 语言过滤：如果规则指定语言，且与技能语言不匹配则跳过
            if rule_language != "all":
                target_lang = skill_language or script_language
                if target_lang and target_lang != rule_language:
                    continue

            # 编译正则表达式
            compiled = self._compile_pattern(rule_id, pattern)
            if not compiled:
                continue

            # 查找匹配
            for match in compiled.finditer(content):
                # 提取上下文
                start, end = match.span()
                context_start = max(0, start - 100)
                context_end = min(len(content), end + 100)
                context = content[context_start:context_end]

                # 提取代码片段
                snippet = self._extract_snippet(content, start, end)

                # 计算行号
                line_number = content[:start].count("\n") + 1

                detection_match = DetectionMatch(
                    rule_id=rule_id,
                    pattern=pattern,
                    category=category,
                    pattern_code=pattern_code,
                    severity=severity,
                    confidence=self._calculate_confidence(rule, match.group()),
                    file=filename,
                    line=line_number,
                    snippet=snippet,
                    context=context,
                    language=rule_language,
                    char_start=start,
                    char_end=end,
                )
                matches.append(detection_match)

        return matches

    def _compile_pattern(self, rule_id: str, pattern: str) -> Optional[re.Pattern]:
        """编译正则表达式模式"""
        if rule_id in self._compiled_rules:
            return self._compiled_rules[rule_id]

        try:
            compiled = re.compile(pattern, re.DOTALL | re.MULTILINE)
            self._compiled_rules[rule_id] = compiled
            return compiled
        except re.error as e:
            logger.warning(f"Failed to compile pattern for rule {rule_id}: {e}")
            return None

    def _extract_snippet(self, content: str, start: int, end: int, max_length: int = 200) -> str:
        """提取代码片段"""
        # 扩展到行边界
        line_start = content.rfind("\n", 0, start) + 1
        line_end = content.find("\n", end)
        if line_end == -1:
            line_end = min(len(content), line_start + max_length)

        snippet = content[line_start:line_end]

        # 限制长度
        if len(snippet) > max_length:
            snippet = snippet[:max_length] + "..."

        return snippet.strip()

    def _calculate_confidence(self, rule: Dict[str, Any], matched_text: str) -> float:
        """计算置信度"""
        base_confidence = 0.7  # 基础置信度

        # 根据匹配长度调整
        if len(matched_text) > 50:
            base_confidence += 0.1

        # 根据规则的置信度提升因子调整
        confidence_boost = rule.get("confidence_boost", 1.0)
        base_confidence *= confidence_boost

        return min(base_confidence, 1.0)

    async def _create_vulnerabilities(
        self,
        matches: List[DetectionMatch],
        skill_id: str,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """创建漏洞记录"""
        vulnerabilities = []

        for match in matches:
            pattern = VulnerabilityPattern(match.pattern_code)
            descriptions = VULNERABILITY_DESCRIPTIONS.get(pattern, {})
            recommendations = VULNERABILITY_RECOMMENDATIONS.get(pattern, {})

            vuln_id = f"VULN-{uuid.uuid4().hex[:16].upper()}"

            vuln = {
                "vulnerability_id": vuln_id,
                "skill_id": skill_id,
                "category": match.category,
                "pattern": match.pattern_code,
                "severity": match.severity,
                "confidence": match.confidence,
                "evidence": {
                    "file": match.file,
                    "line": match.line,
                    "snippet": match.snippet,
                    "context": match.context,
                    "char_start": match.char_start,
                    "char_end": match.char_end,
                },
                "description_zh": descriptions.get("zh", f"检测到{match.pattern_code}漏洞"),
                "description_en": descriptions.get(
                    "en", f"Detected {match.pattern_code} vulnerability"
                ),
                "recommendation_zh": recommendations.get("zh", "请审查相关代码"),
                "recommendation_en": recommendations.get("en", "Please review the related code"),
                "detection_method": "static",
                "detected_by": f"static_analyzer:{match.rule_id}",
                "detected_at": datetime.utcnow(),
                "language": language or "unknown",
            }

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Tuple[float, str]:
        """计算风险评分和等级"""
        if not vulnerabilities:
            return 0.0, "safe"

        # 严重程度权重
        severity_weights = {
            "high": 1.0,
            "medium": 0.5,
            "low": 0.2,
        }

        # 计算加权总分
        total_score = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            confidence = vuln.get("confidence", 0.5)
            total_score += severity_weights.get(severity, 0.2) * confidence

        # 归一化评分 (0-1)
        risk_score = min(total_score / 5.0, 1.0)

        # 确定风险等级
        if risk_score >= 0.7:
            risk_level = "malicious"
        elif risk_score >= 0.5:
            risk_level = "dangerous"
        elif risk_score >= 0.3:
            risk_level = "warning"
        else:
            risk_level = "safe"

        return round(risk_score, 2), risk_level

    def _count_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """统计各类漏洞数量"""
        counts: Dict[str, int] = {}

        for vuln in vulnerabilities:
            category = vuln.get("category", "unknown")
            counts[category] = counts.get(category, 0) + 1

        return counts

    async def analyze_skill_md(self, content: str, skill_id: str) -> List[Dict[str, Any]]:
        """仅分析SKILL.md文件"""
        result = await self.analyze(
            skill_md=content,
            scripts=[],
            skill_id=skill_id,
        )
        return result["vulnerabilities"]

    async def analyze_script(
        self,
        filename: str,
        content: str,
        skill_id: str,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """仅分析脚本文件"""
        result = await self.analyze(
            skill_md="",
            scripts=[{"filename": filename, "content": content, "language": language}],
            skill_id=skill_id,
        )
        return result["vulnerabilities"]

    def get_pattern_info(self, pattern_code: str) -> Dict[str, Any]:
        """获取漏洞模式信息"""
        pattern = VulnerabilityPattern(pattern_code)
        descriptions = VULNERABILITY_DESCRIPTIONS.get(pattern, {})
        recommendations = VULNERABILITY_RECOMMENDATIONS.get(pattern, {})

        return {
            "pattern_code": pattern_code,
            "description_zh": descriptions.get("zh", ""),
            "description_en": descriptions.get("en", ""),
            "recommendation_zh": recommendations.get("zh", ""),
            "recommendation_en": recommendations.get("en", ""),
        }
