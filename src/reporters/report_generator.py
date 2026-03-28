"""
报告生成器模块

生成详细的安全扫描报告，支持多种格式。
"""

import json
import base64
import io
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from loguru import logger


class ReportGenerator:
    """报告生成器"""

    def __init__(self):
        self._templates_dir = Path(__file__).parent / "templates"

    def generate_json_report(
        self,
        scan_result: Dict[str, Any],
        include_evidence: bool = True,
    ) -> str:
        """
        生成JSON格式报告

        Args:
            scan_result: 扫描结果
            include_evidence: 是否包含证据详情

        Returns:
            JSON字符串
        """
        report = self._build_report_data(scan_result, include_evidence)
        return json.dumps(report, ensure_ascii=False, indent=2, default=str)

    def generate_markdown_report(
        self,
        scan_result: Dict[str, Any],
        include_evidence: bool = True,
    ) -> str:
        """
        生成Markdown格式报告

        Args:
            scan_result: 扫描结果
            include_evidence: 是否包含证据详情

        Returns:
            Markdown字符串
        """
        report = self._build_report_data(scan_result, include_evidence)
        return self._format_markdown(report)

    def generate_html_report(
        self,
        scan_result: Dict[str, Any],
        include_evidence: bool = True,
    ) -> str:
        """
        生成HTML格式报告

        Args:
            scan_result: 扫描结果
            include_evidence: 是否包含证据详情

        Returns:
            HTML字符串
        """
        report = self._build_report_data(scan_result, include_evidence)
        return self._format_html(report)

    def generate_pdf_report(
        self,
        scan_result: Dict[str, Any],
        include_evidence: bool = True,
        output_path: Optional[str] = None,
    ) -> str:
        """
        生成PDF格式报告

        Args:
            scan_result: 扫描结果
            include_evidence: 是否包含证据详情
            output_path: 输出文件路径，如果为None则返回PDF的base64编码

        Returns:
            PDF文件路径或base64编码的PDF数据
        """
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor, black, white
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                PageBreak,
            )
            from reportlab.lib import colors
        except ImportError:
            logger.warning("reportlab not installed, using HTML fallback")
            return self.generate_html_report(scan_result, include_evidence)

        from reportlab.lib.pagesizes import letter

        report = self._build_report_data(scan_result, include_evidence)

        if output_path is None:
            import tempfile
            import base64
            import io

            output = io.BytesIO()
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                pdf_buffer,
                pagesize=letter,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch,
            )
            self._build_pdf_content(doc, report)
            pdf_buffer.seek(0)
            return base64.b64encode(pdf_buffer.read()).decode("utf-8")
        else:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=0.75 * inch,
                bottomMargin=0.75 * inch,
            )
            self._build_pdf_content(doc, report)
            return output_path

    def _build_pdf_content(self, doc, report: Dict[str, Any]):
        """构建PDF内容"""
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor("#24292e"),
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor("#24292e"),
        )

        risk_colors = {
            "safe": HexColor("#28a745"),
            "warning": HexColor("#ffc107"),
            "dangerous": HexColor("#dc3545"),
            "malicious": HexColor("#6c1a1a"),
        }

        severity_colors = {
            "high": HexColor("#dc3545"),
            "medium": HexColor("#ffc107"),
            "low": HexColor("#28a745"),
        }

        story = []

        story.append(Paragraph("SkillScan Security Report", title_style))
        story.append(Spacer(1, 12))

        story.append(
            Paragraph(
                f"<b>Generated:</b> {report.get('report_metadata', {}).get('generated_at', 'unknown')}",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Scanner Version:</b> {report.get('report_metadata', {}).get('scanner_version', 'unknown')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 20))

        story.append(Paragraph("Skill Information", heading_style))

        skill_info = report.get("skill_info", {})
        skill_data = [
            ["Property", "Value"],
            ["Skill ID", skill_info.get("skill_id", "unknown")],
            ["Name", skill_info.get("name", "unknown")],
            ["Platform", skill_info.get("platform", "unknown")],
            ["Language", skill_info.get("language", "unknown")],
        ]
        skill_table = Table(skill_data, colWidths=[2 * inch, 4 * inch])
        skill_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f6f8fa")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#24292e")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 1, HexColor("#ddd")),
                ]
            )
        )
        story.append(skill_table)
        story.append(Spacer(1, 20))

        story.append(Paragraph("Risk Assessment", heading_style))

        risk = report.get("risk_assessment", {})
        risk_level = risk.get("risk_level", "safe")
        risk_color = risk_colors.get(risk_level, HexColor("#6c757d"))

        risk_data = [
            ["Risk Level", risk.get("risk_level", "unknown").upper()],
            ["Risk Score", f"{risk.get('risk_score', 0.0):.2f}"],
            ["Total Vulnerabilities", str(risk.get("total_vulnerabilities", 0))],
        ]
        risk_table = Table(risk_data, colWidths=[2 * inch, 4 * inch])
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), risk_color),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("BACKGROUND", (0, 1), (-1, 1), HexColor("#f8f9fa")),
                    ("BACKGROUND", (0, 2), (-1, 2), HexColor("#f8f9fa")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 1, HexColor("#ddd")),
                ]
            )
        )
        story.append(risk_table)
        story.append(Spacer(1, 20))

        vulns = report.get("vulnerabilities", [])
        if vulns:
            story.append(Paragraph("Vulnerabilities Detected", heading_style))

            for i, vuln in enumerate(vulns, 1):
                severity = vuln.get("severity", "low")
                sev_color = severity_colors.get(severity, HexColor("#6c757d"))

                vuln_text = f"<b>{i}. {vuln.get('pattern', 'unknown')}</b> - {vuln.get('category', 'unknown')}"
                story.append(Paragraph(vuln_text, styles["Normal"]))

                details = f"""
                <b>Severity:</b> {vuln.get('severity', 'unknown')} | 
                <b>Confidence:</b> {vuln.get('confidence', 0.0):.2f} | 
                <b>Detection:</b> {vuln.get('detection_method', 'unknown')}
                """
                story.append(Paragraph(details, styles["Normal"]))

                if vuln.get("description_en"):
                    story.append(
                        Paragraph(
                            f"<i>{vuln.get('description_en', '')}</i>",
                            styles["Normal"],
                        )
                    )

                if vuln.get("evidence"):
                    evidence = vuln["evidence"]
                    evidence_text = f"""
                    <b>Evidence:</b> {evidence.get('file', 'unknown')} 
                    (Line: {evidence.get('line', 'N/A')})
                    """
                    story.append(Paragraph(evidence_text, styles["Normal"]))

                story.append(Spacer(1, 10))

        doc.build(story)

    def _build_report_data(
        self,
        scan_result: Dict[str, Any],
        include_evidence: bool = True,
    ) -> Dict[str, Any]:
        """构建报告数据"""
        vulnerabilities = scan_result.get("vulnerabilities", [])

        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "scanner_version": scan_result.get("scanner_version", "1.0.0"),
                "scan_duration_ms": scan_result.get("scan_duration_ms", 0),
            },
            "skill_info": {
                "skill_id": scan_result.get("skill_id", "unknown"),
                "name": scan_result.get("name", "Unknown Skill"),
                "platform": scan_result.get("platform", "unknown"),
                "language": scan_result.get("language", "unknown"),
            },
            "risk_assessment": {
                "risk_score": scan_result.get("risk_score", 0.0),
                "risk_level": scan_result.get("risk_level", "safe"),
                "vulnerability_count": scan_result.get("vulnerability_count", {}),
                "total_vulnerabilities": len(vulnerabilities),
            },
            "vulnerabilities": [
                self._format_vulnerability(v, include_evidence) for v in vulnerabilities
            ],
            "summary": self._generate_summary(scan_result),
        }

    def _format_vulnerability(
        self,
        vuln: Dict[str, Any],
        include_evidence: bool = True,
    ) -> Dict[str, Any]:
        """格式化漏洞信息"""
        result = {
            "vulnerability_id": vuln.get("vulnerability_id", "unknown"),
            "pattern": vuln.get("pattern", "unknown"),
            "category": vuln.get("category", "unknown"),
            "severity": vuln.get("severity", "unknown"),
            "confidence": vuln.get("confidence", 0.0),
            "description_zh": vuln.get("description_zh", ""),
            "description_en": vuln.get("description_en", ""),
            "recommendation_zh": vuln.get("recommendation_zh", ""),
            "recommendation_en": vuln.get("recommendation_en", ""),
            "detection_method": vuln.get("detection_method", "unknown"),
        }

        if include_evidence:
            evidence = vuln.get("evidence", {})
            result["evidence"] = {
                "file": evidence.get("file", "unknown"),
                "line": evidence.get("line"),
                "snippet": evidence.get("snippet", ""),
            }

        return result

    def _generate_summary(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """生成摘要"""
        vuln_count = scan_result.get("vulnerability_count", {})
        risk_level = scan_result.get("risk_level", "safe")

        # 根据风险等级生成状态描述
        risk_descriptions = {
            "safe": "No significant vulnerabilities detected.",
            "warning": "Some vulnerabilities detected. Review recommended.",
            "dangerous": "Multiple serious vulnerabilities detected. Immediate attention required.",
            "malicious": "High confidence malicious patterns detected. Skill may be compromised.",
        }

        return {
            "risk_status": risk_descriptions.get(risk_level, "Unknown"),
            "by_category": vuln_count,
            "has_critical": vuln_count.get("prompt_injection", 0) > 0,
            "has_data_exfiltration": vuln_count.get("data_exfiltration", 0) > 0,
            "has_privilege_escalation": vuln_count.get("privilege_escalation", 0) > 0,
            "has_supply_chain_risk": vuln_count.get("supply_chain", 0) > 0,
        }

    def _format_markdown(self, report: Dict[str, Any]) -> str:
        """格式化为Markdown"""
        skill_info = report.get("skill_info", {})
        risk = report.get("risk_assessment", {})
        vulns = report.get("vulnerabilities", [])
        summary = report.get("summary", {})

        # 风险等级emoji
        risk_emoji = {
            "safe": "✅",
            "warning": "⚠️",
            "dangerous": "🔴",
            "malicious": "🚨",
        }

        lines = [
            "# SkillScan Security Report",
            "",
            f"**Generated:** {report.get('report_metadata', {}).get('generated_at', 'unknown')}",
            f"**Scanner Version:** {report.get('report_metadata', {}).get('scanner_version', 'unknown')}",
            "",
            "## Skill Information",
            "",
            f"| Property | Value |",
            f"|----------|-------|",
            f"| Skill ID | {skill_info.get('skill_id', 'unknown')} |",
            f"| Name | {skill_info.get('name', 'unknown')} |",
            f"| Platform | {skill_info.get('platform', 'unknown')} |",
            f"| Language | {skill_info.get('language', 'unknown')} |",
            "",
            "## Risk Assessment",
            "",
            f"**Risk Level:** {risk_emoji.get(risk.get('risk_level', 'safe'), '')} {risk.get('risk_level', 'safe').upper()}",
            f"**Risk Score:** {risk.get('risk_score', 0.0):.2f}",
            f"**Total Vulnerabilities:** {risk.get('total_vulnerabilities', 0)}",
            "",
            "### Vulnerability Distribution",
            "",
        ]

        # 漏洞分布
        for category, count in risk.get("vulnerability_count", {}).items():
            lines.append(f"- **{category}**: {count}")

        # 详细漏洞列表
        if vulns:
            lines.extend(
                [
                    "",
                    "## Vulnerabilities Detected",
                    "",
                ]
            )

            for i, vuln in enumerate(vulns, 1):
                severity_emoji = {
                    "high": "🔴",
                    "medium": "🟡",
                    "low": "🟢",
                }

                lines.extend(
                    [
                        f"### {i}. {vuln.get('pattern', 'unknown')} - {vuln.get('category', 'unknown')}",
                        "",
                        f"**Severity:** {severity_emoji.get(vuln.get('severity', 'low'), '')} {vuln.get('severity', 'unknown')}",
                        f"**Confidence:** {vuln.get('confidence', 0.0):.2f}",
                        f"**Detection Method:** {vuln.get('detection_method', 'unknown')}",
                        "",
                        f"**Description (ZH):** {vuln.get('description_zh', '')}",
                        f"**Description (EN):** {vuln.get('description_en', '')}",
                        "",
                    ]
                )

                if vuln.get("evidence"):
                    evidence = vuln["evidence"]
                    lines.extend(
                        [
                            "**Evidence:**",
                            f"- File: `{evidence.get('file', 'unknown')}`",
                            f"- Line: {evidence.get('line', 'N/A')}",
                            f"- Snippet: `{evidence.get('snippet', '')[:100]}`",
                            "",
                        ]
                    )

                if vuln.get("recommendation_zh"):
                    lines.extend(
                        [
                            f"**Recommendation:** {vuln.get('recommendation_zh', '')}",
                            "",
                        ]
                    )

        # 摘要
        lines.extend(
            [
                "",
                "## Summary",
                "",
                f"**Status:** {summary.get('risk_status', 'Unknown')}",
                "",
                "- "
                + (
                    "Has critical vulnerabilities (Prompt Injection)"
                    if summary.get("has_critical")
                    else "No critical vulnerabilities"
                ),
                "- "
                + (
                    "Has data exfiltration risks"
                    if summary.get("has_data_exfiltration")
                    else "No data exfiltration risks"
                ),
                "- "
                + (
                    "Has privilege escalation risks"
                    if summary.get("has_privilege_escalation")
                    else "No privilege escalation risks"
                ),
                "- "
                + (
                    "Has supply chain risks"
                    if summary.get("has_supply_chain_risk")
                    else "No supply chain risks"
                ),
                "",
                "---",
                "",
                "*Report generated by SkillScan - Agent Skills Threat Analysis Engine*",
            ]
        )

        return "\n".join(lines)

    def _format_html(self, report: Dict[str, Any]) -> str:
        """格式化为HTML"""
        skill_info = report.get("skill_info", {})
        risk = report.get("risk_assessment", {})
        vulns = report.get("vulnerabilities", [])

        risk_colors = {
            "safe": "#28a745",
            "warning": "#ffc107",
            "dangerous": "#dc3545",
            "malicious": "#6c1a1a",
        }

        severity_colors = {
            "high": "#dc3545",
            "medium": "#ffc107",
            "low": "#28a745",
        }

        vulns_html = ""
        for vuln in vulns:
            color = severity_colors.get(vuln.get("severity", "low"), "#6c757d")
            vulns_html += f"""
            <div class="vulnerability" style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0; background: #f8f9fa;">
                <h4>{vuln.get('pattern', 'unknown')} - {vuln.get('category', 'unknown')}</h4>
                <p><strong>Severity:</strong> <span style="color: {color};">{vuln.get('severity', 'unknown').upper()}</span></p>
                <p><strong>Confidence:</strong> {vuln.get('confidence', 0.0):.2f}</p>
                <p><strong>Description:</strong> {vuln.get('description_en', '')}</p>
                <p><strong>Recommendation:</strong> {vuln.get('recommendation_en', '')}</p>
            </div>
            """

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SkillScan Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #24292e; }}
        .risk-badge {{ padding: 10px 20px; border-radius: 5px; color: white; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f6f8fa; }}
        .summary {{ background: #f6f8fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🔒 SkillScan Security Report</h1>
    <p>Generated: {report.get('report_metadata', {}).get('generated_at', 'unknown')}</p>

    <h2>Skill Information</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Skill ID</td><td>{skill_info.get('skill_id', 'unknown')}</td></tr>
        <tr><td>Name</td><td>{skill_info.get('name', 'unknown')}</td></tr>
        <tr><td>Platform</td><td>{skill_info.get('platform', 'unknown')}</td></tr>
        <tr><td>Language</td><td>{skill_info.get('language', 'unknown')}</td></tr>
    </table>

    <h2>Risk Assessment</h2>
    <p class="risk-badge" style="background: {risk_colors.get(risk.get('risk_level', 'safe'), '#6c757d')};">
        Risk Level: {risk.get('risk_level', 'safe').upper()}
    </p>
    <p><strong>Risk Score:</strong> {risk.get('risk_score', 0.0):.2f}</p>
    <p><strong>Total Vulnerabilities:</strong> {risk.get('total_vulnerabilities', 0)}</p>

    <h2>Vulnerabilities</h2>
    {vulns_html if vulns_html else '<p>No vulnerabilities detected.</p>'}

    <hr>
    <p><em>Report generated by SkillScan - Agent Skills Threat Analysis Engine</em></p>
</body>
</html>
        """

        return html

    def generate_summary_report(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        生成批量扫描汇总报告

        Args:
            scan_results: 扫描结果列表

        Returns:
            汇总报告
        """
        total = len(scan_results)
        if total == 0:
            return {"total_skills": 0}

        # 统计
        risk_counts = {"safe": 0, "warning": 0, "dangerous": 0, "malicious": 0}
        category_counts: Dict[str, int] = {}
        platform_counts: Dict[str, int] = {}
        total_vulnerabilities = 0
        high_severity_count = 0

        for result in scan_results:
            risk_level = result.get("risk_level", "safe")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

            platform = result.get("platform", "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

            vuln_count = result.get("vulnerability_count", {})
            for category, count in vuln_count.items():
                category_counts[category] = category_counts.get(category, 0) + count
                total_vulnerabilities += count

            high_severity_count += vuln_count.get("prompt_injection", 0)
            high_severity_count += vuln_count.get("data_exfiltration", 0)

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_skills": total,
            "risk_distribution": risk_counts,
            "category_distribution": category_counts,
            "platform_distribution": platform_counts,
            "total_vulnerabilities": total_vulnerabilities,
            "high_severity_count": high_severity_count,
            "vulnerable_percentage": (
                (total - risk_counts.get("safe", 0)) / total * 100 if total > 0 else 0
            ),
            "malicious_percentage": (
                risk_counts.get("malicious", 0) / total * 100 if total > 0 else 0
            ),
        }
