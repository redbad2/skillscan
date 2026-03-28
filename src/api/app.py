"""
FastAPI应用模块

提供REST API接口：
- POST /api/v1/scan - 提交扫描任务
- GET /api/v1/scan/{id} - 获取扫描状态和结果
- GET /api/v1/skills - 查询技能列表
- GET /api/v1/skills/{id} - 获取技能详情
- GET /api/v1/vulnerabilities - 查询漏洞列表
- GET /api/v1/reports - 获取报告列表
- GET /api/v1/stats - 获取统计信息
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from loguru import logger

from src.config import get_settings
from src.core.scan_engine import ScanEngine
from src.storage.mongodb import MongoDBStorage


# Pydantic模型
class ScanRequest(BaseModel):
    """扫描请求模型"""

    skill_id: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    platform: str = "custom"
    language: Optional[str] = None
    skip_llm: bool = False


class ScanResponse(BaseModel):
    """扫描响应模型"""

    task_id: str
    status: str
    message: str


class SkillResponse(BaseModel):
    """技能响应模型"""

    skill_id: str
    name: str
    platform: str
    language: str
    scan_status: str
    risk_level: str
    risk_score: float
    vulnerability_count: Dict[str, int]


class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""

    vulnerability_id: str
    skill_id: str
    category: str
    pattern: str
    severity: str
    confidence: float
    description_zh: str
    description_en: str


class StatsResponse(BaseModel):
    """统计响应模型"""

    total_skills: int
    scanned_skills: int
    pending_skills: int
    vulnerabilities_by_category: Dict[str, int]
    risk_distribution: Dict[str, int]


# 创建FastAPI应用
app = FastAPI(
    title="SkillScan API",
    description="Skills 威胁分析引擎 - 自动化安全扫描API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# 配置CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 存储扫描任务状态
scan_tasks: Dict[str, Dict[str, Any]] = {}

# MongoDB存储和扫描引擎
mongodb_storage: Optional[MongoDBStorage] = None
scan_engine: Optional[ScanEngine] = None


@app.on_event("startup")
async def startup_event():
    """应用启动时初始化MongoDB连接"""
    global mongodb_storage, scan_engine

    try:
        mongodb_storage = MongoDBStorage()
        scan_engine = ScanEngine(mongodb=mongodb_storage)
        await scan_engine.initialize()
        logger.info("Scan engine initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize scan engine: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时清理资源"""
    global scan_engine

    if scan_engine:
        await scan_engine.shutdown()
        logger.info("Scan engine shut down")


@app.get("/")
async def root():
    """根端点"""
    return {
        "name": "SkillScan API",
        "version": "1.0.0",
        "description": "Skills 威胁分析引擎",
        "docs": "/api/docs",
    }


@app.get("/api/v1/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    提交扫描任务

    支持：
    - 直接提交内容
    - URL爬取
    - 按技能ID扫描
    """
    import uuid

    task_id = f"TASK-{uuid.uuid4().hex[:12].upper()}"

    # 初始化任务状态
    scan_tasks[task_id] = {
        "task_id": task_id,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "request": request.model_dump(),
    }

    # 后台执行扫描
    background_tasks.add_task(
        execute_scan,
        task_id=task_id,
        request=request,
    )

    return ScanResponse(
        task_id=task_id,
        status="pending",
        message="Scan task created successfully",
    )


@app.get("/api/v1/scan/{task_id}")
async def get_scan_result(task_id: str):
    """获取扫描状态和结果"""
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = scan_tasks[task_id]
    return task


@app.get("/api/v1/skills")
async def list_skills(
    platform: Optional[str] = None,
    risk_level: Optional[str] = None,
    language: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """查询技能列表"""
    if not scan_engine:
        return {
            "skills": [],
            "total": 0,
            "skip": skip,
            "limit": limit,
            "message": "Database not connected",
        }

    try:
        result = await scan_engine.list_skills(
            platform=platform,
            risk_level=risk_level,
            language=language,
            skip=skip,
            limit=limit,
        )
        return result
    except Exception as e:
        logger.error(f"Error listing skills: {e}")
        return {
            "skills": [],
            "total": 0,
            "skip": skip,
            "limit": limit,
            "error": str(e),
        }


@app.get("/api/v1/skills/{skill_id}")
async def get_skill(skill_id: str):
    """获取技能详情"""
    # 这里应该从数据库查询
    raise HTTPException(status_code=404, detail="Skill not found")


@app.get("/api/v1/vulnerabilities")
async def list_vulnerabilities(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    skill_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """查询漏洞列表"""
    if not scan_engine:
        return {
            "vulnerabilities": [],
            "total": 0,
            "skip": skip,
            "limit": limit,
            "message": "Database not connected",
        }

    try:
        result = await scan_engine.list_vulnerabilities(
            category=category,
            severity=severity,
            skill_id=skill_id,
            skip=skip,
            limit=limit,
        )
        return result
    except Exception as e:
        logger.error(f"Error listing vulnerabilities: {e}")
        return {
            "vulnerabilities": [],
            "total": 0,
            "skip": skip,
            "limit": limit,
            "error": str(e),
        }


@app.get("/api/v1/stats")
async def get_stats():
    """获取统计信息"""
    # 先获取任务统计
    total_tasks = len(scan_tasks)
    completed = sum(1 for t in scan_tasks.values() if t.get("status") == "completed")
    pending = sum(1 for t in scan_tasks.values() if t.get("status") == "pending")

    result = {
        "tasks": {
            "total": total_tasks,
            "completed": completed,
            "pending": pending,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }

    # 获取数据库统计
    if scan_engine:
        try:
            db_stats = await scan_engine.get_scan_statistics()
            result["database"] = db_stats
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            result["database"] = {"error": str(e)}

    return result


@app.get("/api/v1/reports")
async def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """获取报告列表"""
    return {
        "reports": [],
        "total": 0,
        "skip": skip,
        "limit": limit,
        "message": "This endpoint requires database connection",
    }


@app.post("/api/v1/webhooks")
async def register_webhook(url: str, events: List[str]):
    """注册Webhook回调"""
    return {
        "webhook_id": "WEBHOOK-001",
        "url": url,
        "events": events,
        "status": "registered",
    }


async def execute_scan(task_id: str, request: ScanRequest):
    """执行扫描任务"""
    try:
        # 更新状态为扫描中
        scan_tasks[task_id]["status"] = "scanning"

        # 根据请求类型执行扫描
        if request.content:
            # 直接内容扫描
            from src.analyzers.static_analyzer import StaticAnalyzer

            analyzer = StaticAnalyzer()

            vulnerabilities = await analyzer.analyze_skill_md(
                content=request.content,
                skill_id=request.skill_id or f"CUSTOM-{task_id}",
            )

            scan_tasks[task_id].update(
                {
                    "status": "completed",
                    "result": {
                        "skill_id": request.skill_id or f"CUSTOM-{task_id}",
                        "vulnerabilities": vulnerabilities,
                        "risk_score": len(vulnerabilities) * 0.2,
                        "risk_level": "warning" if vulnerabilities else "safe",
                    },
                    "completed_at": datetime.utcnow().isoformat(),
                }
            )

        elif request.url:
            # URL扫描
            scan_tasks[task_id].update(
                {
                    "status": "completed",
                    "result": {
                        "message": "URL scanning not yet implemented",
                        "url": request.url,
                    },
                    "completed_at": datetime.utcnow().isoformat(),
                }
            )

        else:
            scan_tasks[task_id].update(
                {
                    "status": "failed",
                    "error": "No content or URL provided",
                    "completed_at": datetime.utcnow().isoformat(),
                }
            )

    except Exception as e:
        logger.error(f"Scan task {task_id} failed: {e}")
        scan_tasks[task_id].update(
            {
                "status": "failed",
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat(),
            }
        )


def create_app() -> FastAPI:
    """创建FastAPI应用"""
    return app
