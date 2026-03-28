"""
Dashboard可视化模块

提供Web界面用于展示扫描结果和统计信息。
"""

from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
import json

from loguru import logger

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])

templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(templates_dir))


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request):
    """Dashboard首页"""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "SkillScan Dashboard",
        },
    )


@dashboard_router.get("/stats")
async def dashboard_stats():
    """获取统计数据用于仪表盘"""
    from src.api.app import scan_engine, scan_tasks

    stats = {
        "total_tasks": len(scan_tasks),
        "completed_tasks": sum(1 for t in scan_tasks.values() if t.get("status") == "completed"),
        "pending_tasks": sum(1 for t in scan_tasks.values() if t.get("status") == "pending"),
        "failed_tasks": sum(1 for t in scan_tasks.values() if t.get("status") == "failed"),
    }

    if scan_engine and scan_engine.skill_repo:
        try:
            db_stats = await scan_engine.get_scan_statistics()
            stats["database"] = db_stats
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            stats["database"] = {"error": str(e)}

    return stats


@dashboard_router.get("/vulnerabilities")
async def dashboard_vulnerabilities():
    """获取漏洞统计"""
    from src.api.app import scan_tasks

    vulns = []
    for task in scan_tasks.values():
        if task.get("status") == "completed" and task.get("result"):
            result = task["result"]
            for vuln in result.get("vulnerabilities", []):
                vulns.append(
                    {
                        "skill_id": result.get("skill_id"),
                        "category": vuln.get("category"),
                        "severity": vuln.get("severity"),
                        "confidence": vuln.get("confidence"),
                        "pattern": vuln.get("pattern"),
                    }
                )

    return {"vulnerabilities": vulns, "total": len(vulns)}


@dashboard_router.get("/tasks")
async def dashboard_tasks(
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
):
    """获取任务列表"""
    from src.api.app import scan_tasks

    tasks = list(scan_tasks.values())

    if status:
        tasks = [t for t in tasks if t.get("status") == status]

    tasks = tasks[skip : skip + limit]

    return {
        "tasks": tasks,
        "total": len(scan_tasks),
        "skip": skip,
        "limit": limit,
    }


@dashboard_router.get("/report/{task_id}")
async def dashboard_task_report(task_id: str):
    """获取任务报告"""
    from src.api.app import scan_tasks, report_generator

    if task_id not in scan_tasks:
        return {"error": "Task not found"}

    task = scan_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Task not completed"}

    result = task.get("result", {})

    report = report_generator.generate_json_report(result)

    return json.loads(report)


@dashboard_router.get("/health")
async def dashboard_health():
    """健康检查"""
    from src.api.app import scan_engine, mongodb_storage

    health = {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "components": {},
    }

    if scan_engine:
        health["components"]["scan_engine"] = "healthy"
    else:
        health["components"]["scan_engine"] = "unavailable"
        health["status"] = "degraded"

    if mongodb_storage:
        try:
            if mongodb_storage.client:
                health["components"]["mongodb"] = "healthy"
            else:
                health["components"]["mongodb"] = "disconnected"
                health["status"] = "degraded"
        except Exception:
            health["components"]["mongodb"] = "error"
            health["status"] = "degraded"
    else:
        health["components"]["mongodb"] = "unavailable"

    return health
