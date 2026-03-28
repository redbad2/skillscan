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
- GET/POST /api/v1/config - LLM配置管理
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from loguru import logger

from src.config import get_settings
from src.core.scan_engine import ScanEngine
from src.storage.mongodb import MongoDBStorage
from src.api.webhooks import webhook_manager, WebhookEvent
from src.reporters.report_generator import ReportGenerator

try:
    from src.config.llm_config_manager import llm_config_manager
except ImportError:
    llm_config_manager = None

try:
    from src.dashboard.routes import dashboard_router

    HAS_DASHBOARD = True
except ImportError:
    HAS_DASHBOARD = False


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


class LLMThresholdUpdate(BaseModel):
    """LLM阈值更新模型"""

    static_confidence_threshold: Optional[float] = Field(None, ge=0, le=1)
    llm_confirm_threshold: Optional[float] = Field(None, ge=0, le=1)
    llm_override_threshold: Optional[float] = Field(None, ge=0, le=1)
    timeout: Optional[int] = Field(None, ge=1, le=300)
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    enabled: Optional[bool] = None


class LLMCostControlUpdate(BaseModel):
    """LLM成本控制更新模型"""

    monthly_budget: Optional[float] = Field(None, ge=0)
    max_tokens_per_analysis: Optional[int] = Field(None, ge=100, le=100000)
    on_budget_exceeded: Optional[str] = None
    enable_cost_tracking: Optional[bool] = None

    @field_validator("on_budget_exceeded")
    @classmethod
    def validate_budget_action(cls, v):
        if v and v not in ("block", "warn", "ignore"):
            raise ValueError("on_budget_exceeded must be 'block', 'warn', or 'ignore'")
        return v


class LLMProviderUpdate(BaseModel):
    """LLM提供商更新模型"""

    enabled: Optional[bool] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0, le=2)
    max_tokens: Optional[int] = Field(None, ge=100, le=100000)
    timeout: Optional[int] = Field(None, ge=1, le=300)
    retry_count: Optional[int] = Field(None, ge=0, le=10)


class LLMConfigResponse(BaseModel):
    """LLM配置响应模型"""

    providers: Dict[str, Any]
    default_provider: str
    analysis: Dict[str, Any]
    cost_control: Dict[str, Any]
    prompts: Optional[Dict[str, Any]] = None


class LLMConfigUpdateResponse(BaseModel):
    """LLM配置更新响应模型"""

    success: bool
    message: str
    new_version: Optional[str] = None


class ConfigVersionResponse(BaseModel):
    """配置版本响应模型"""

    version_id: str
    created_at: str
    created_by: str
    config_hash: str


class ConfigDiffResponse(BaseModel):
    """配置差异响应模型"""

    version1: str
    version2: str
    changes: List[Dict[str, Any]]


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

# 注册Dashboard路由
if HAS_DASHBOARD:
    app.include_router(dashboard_router)

# 存储扫描任务状态
scan_tasks: Dict[str, Dict[str, Any]] = {}

# MongoDB存储和扫描引擎
mongodb_storage: Optional[MongoDBStorage] = None
scan_engine: Optional[ScanEngine] = None
report_generator = ReportGenerator()


@app.on_event("startup")
async def startup_event():
    """应用启动时初始化MongoDB连接和LLM配置"""
    global mongodb_storage, scan_engine

    try:
        mongodb_storage = MongoDBStorage()
        scan_engine = ScanEngine(mongodb=mongodb_storage)
        await scan_engine.initialize()
        logger.info("Scan engine initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize scan engine: {e}")

    if llm_config_manager is not None:
        try:
            llm_config = settings.get_llm_config()
            llm_config_manager.initialize(llm_config)
            logger.info("LLM Config Manager initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM Config Manager: {e}")


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
    if not scan_engine or not scan_engine.skill_repo:
        raise HTTPException(
            status_code=503,
            detail="Database not connected",
        )

    try:
        skill = await scan_engine.skill_repo.find_by_id(skill_id)
        if not skill:
            raise HTTPException(
                status_code=404,
                detail="Skill not found",
            )

        return skill
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting skill {skill_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving skill: {str(e)}",
        )


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
async def register_webhook(
    url: str,
    events: List[str],
    secret: Optional[str] = None,
):
    """注册Webhook回调"""
    webhook_id = webhook_manager.register_webhook(url, events, secret)
    return {
        "webhook_id": webhook_id,
        "url": url,
        "events": events,
        "status": "registered",
    }


@app.delete("/api/v1/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """删除Webhook"""
    success = webhook_manager.unregister_webhook(webhook_id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted", "webhook_id": webhook_id}


@app.get("/api/v1/webhooks")
async def list_webhooks():
    """列出所有Webhook"""
    return {"webhooks": webhook_manager.list_webhooks()}


@app.get("/api/v1/config/llm")
async def get_llm_config():
    """获取LLM配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    return llm_config_manager.get_config()


@app.get("/api/v1/config/llm/provider/{provider}")
async def get_provider_config(provider: str):
    """获取指定LLM提供商配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    config = llm_config_manager.get_provider_config(provider)
    if config is None:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' not found")

    return {"provider": provider, "config": config}


@app.put("/api/v1/config/llm/provider/{provider}")
async def update_provider_config(
    provider: str,
    config: LLMProviderUpdate,
):
    """更新LLM提供商配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    valid_providers = ["openai", "anthropic", "azure_openai", "local"]
    if provider not in valid_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider. Must be one of: {valid_providers}",
        )

    config_dict = config.model_dump(exclude_none=True)
    success = llm_config_manager.update_provider(provider, config_dict)

    return LLMConfigUpdateResponse(
        success=success,
        message=f"Provider '{provider}' updated" if success else "Update failed",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.put("/api/v1/config/llm/provider/default")
async def set_default_provider(provider: str):
    """切换默认LLM提供商"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    success = llm_config_manager.set_default_provider(provider)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to set default provider: {provider}")

    return LLMConfigUpdateResponse(
        success=True,
        message=f"Default provider set to '{provider}'",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.patch("/api/v1/config/llm/thresholds")
async def update_thresholds(
    thresholds: LLMThresholdUpdate,
):
    """动态更新LLM分析阈值"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    thresholds_dict = thresholds.model_dump(exclude_none=True)
    success = llm_config_manager.update_analysis_thresholds(thresholds_dict)

    return LLMConfigUpdateResponse(
        success=success,
        message="Thresholds updated" if success else "Update failed",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.patch("/api/v1/config/llm/cost-control")
async def update_cost_control(
    cost_config: LLMCostControlUpdate,
):
    """更新成本控制配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    cost_dict = cost_config.model_dump(exclude_none=True)
    success = llm_config_manager.update_cost_control(cost_dict)

    return LLMConfigUpdateResponse(
        success=success,
        message="Cost control updated" if success else "Update failed",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.get("/api/v1/config/llm/versions")
async def list_config_versions(limit: int = Query(10, ge=1, le=100)):
    """列出配置版本历史"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    return {"versions": llm_config_manager.list_versions(limit)}


@app.get("/api/v1/config/llm/versions/{version_id}")
async def get_config_version(version_id: str):
    """获取指定配置版本"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    version = llm_config_manager.get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail=f"Version '{version_id}' not found")

    return version.to_dict()


@app.post("/api/v1/config/llm/versions/{version_id}/rollback")
async def rollback_config_version(version_id: str):
    """回滚到指定版本"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    success = llm_config_manager.rollback_version(version_id)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to rollback to version: {version_id}")

    return LLMConfigUpdateResponse(
        success=True,
        message=f"Rolled back to version '{version_id}'",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.get("/api/v1/config/llm/versions/diff")
async def diff_config_versions(
    version_id1: str = Query(..., description="First version ID"),
    version_id2: str = Query(..., description="Second version ID"),
):
    """比较两个配置版本的差异"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    diff = llm_config_manager.diff_versions(version_id1, version_id2)
    if diff is None:
        raise HTTPException(status_code=404, detail="One or both versions not found")

    return diff


@app.post("/api/v1/config/llm/reset")
async def reset_llm_config():
    """重置LLM配置为默认值"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    success = llm_config_manager.reset_to_default()

    return LLMConfigUpdateResponse(
        success=success,
        message="Configuration reset to default" if success else "Reset failed",
        new_version=f"v{len(llm_config_manager.list_versions())}",
    )


@app.get("/api/v1/config/llm/rate-limit")
async def get_rate_limit_status():
    """获取速率限制状态"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    return llm_config_manager.get_rate_limit_status()


@app.post("/api/v1/scans/{task_id}/report")
async def get_scan_report(
    task_id: str,
    format: str = Query("json", regex="^(json|html|markdown|pdf)$"),
):
    """获取扫描报告"""
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = scan_tasks[task_id]
    if task.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Task not completed, current status: {task.get('status')}",
        )

    result = task.get("result", {})

    if format == "json":
        return report_generator.generate_json_report(result)
    elif format == "html":
        return report_generator.generate_html_report(result)
    elif format == "markdown":
        return report_generator.generate_markdown_report(result)
    elif format == "pdf":
        import tempfile
        import base64

        pdf_base64 = report_generator.generate_pdf_report(result)
        if len(pdf_base64) > 100:
            return {"format": "pdf", "data": pdf_base64}
        return {"error": "PDF generation failed"}


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

            risk_level = (
                "malicious"
                if any(
                    v.get("severity") == "high" and v.get("confidence", 0) > 0.8
                    for v in vulnerabilities
                )
                else "dangerous"
                if len(vulnerabilities) > 3
                else "warning"
                if vulnerabilities
                else "safe"
            )

            result = {
                "skill_id": request.skill_id or f"CUSTOM-{task_id}",
                "vulnerabilities": vulnerabilities,
                "risk_score": min(len(vulnerabilities) * 0.2, 1.0),
                "risk_level": risk_level,
                "vulnerability_count": {
                    v.get("category", "unknown"): vulnerabilities.count(v) for v in vulnerabilities
                },
            }

            scan_tasks[task_id].update(
                {
                    "status": "completed",
                    "result": result,
                    "completed_at": datetime.utcnow().isoformat(),
                }
            )

            # 触发webhook回调
            await webhook_manager.trigger_event(
                WebhookEvent.SCAN_COMPLETED.value,
                {
                    "task_id": task_id,
                    "skill_id": result["skill_id"],
                    "risk_level": risk_level,
                    "vulnerability_count": len(vulnerabilities),
                },
            )

            # 如果发现高危漏洞，触发高危通知
            if risk_level in ("dangerous", "malicious"):
                await webhook_manager.trigger_event(
                    WebhookEvent.HIGH_RISK_DETECTED.value,
                    {
                        "task_id": task_id,
                        "skill_id": result["skill_id"],
                        "risk_level": risk_level,
                        "vulnerabilities": vulnerabilities,
                    },
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

            await webhook_manager.trigger_event(
                WebhookEvent.SCAN_FAILED.value,
                {
                    "task_id": task_id,
                    "error": "No content or URL provided",
                },
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

        await webhook_manager.trigger_event(
            WebhookEvent.SCAN_FAILED.value,
            {
                "task_id": task_id,
                "error": str(e),
            },
        )


def create_app() -> FastAPI:
    """创建FastAPI应用"""
    return app
