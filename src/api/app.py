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

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.config import get_settings
from src.core.scan_engine import ScanEngine
from src.storage.mongodb import MongoDBStorage
from src.api.webhooks import webhook_manager, WebhookEvent
from src.api.auth import require_api_key
from src.reporters.report_generator import ReportGenerator

limiter = Limiter(key_func=get_remote_address)

try:
    from src.config.llm_config_manager import llm_config_manager
except ImportError:
    llm_config_manager = None

try:
    from src.rules.rule_config_manager import rule_config_manager
except ImportError:
    rule_config_manager = None

try:
    from src.dashboard.routes import dashboard_router

    HAS_DASHBOARD = True
except ImportError:
    HAS_DASHBOARD = False


# Pydantic模型
class ScanRequest(BaseModel):
    """scan请求模型"""

    skill_id: Optional[str] = Field(None, max_length=100)
    content: Optional[str] = Field(None, max_length=100000)
    url: Optional[str] = Field(None, max_length=2048)
    platform: str = Field("custom", max_length=50)
    language: Optional[str] = Field(None, max_length=50)
    skip_llm: bool = False

    @field_validator("skill_id", "platform", "language")
    @classmethod
    def validate_alphanumeric(cls, v):
        if v is not None:
            if not v.replace("-", "").replace("_", "").isalnum():
                raise ValueError(
                    "Field must contain only alphanumeric characters, hyphens, and underscores"
                )
        return v

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v):
        if v is not None and v.strip():
            import re

            url_pattern = re.compile(
                r"^https?://"
                r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
                r"localhost|"
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                r"(?::\d+)?"
                r"(?:/?|[/?]\S+)$",
                re.IGNORECASE,
            )
            if not url_pattern.match(v):
                raise ValueError("Invalid URL format")
        return v


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
    """配置 diff响应模型"""

    version1: str
    version2: str
    changes: List[Dict[str, Any]]


class RuleCreate(BaseModel):
    """规则创建模型"""

    rule_id: str = Field(..., max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    pattern_code: str = Field(..., max_length=5000)
    language: str = Field(..., max_length=50)
    name: str = Field(..., max_length=200)
    description: str = Field(..., max_length=1000)
    patterns: List[str] = Field(..., min_length=1, max_length=100)
    severity: str = Field("medium", max_length=20)
    category: str = Field("", max_length=100)
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        valid_severities = ["low", "medium", "high", "critical"]
        if v.lower() not in valid_severities:
            raise ValueError(f"severity must be one of: {valid_severities}")
        return v.lower()

    @field_validator("patterns")
    @classmethod
    def validate_patterns_content(cls, v):
        for i, pattern in enumerate(v):
            if len(pattern) > 1000:
                raise ValueError(f"Pattern at index {i} exceeds maximum length of 1000 characters")
        return v


class RuleUpdate(BaseModel):
    """规则更新模型"""

    name: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    patterns: Optional[List[str]] = Field(None, max_length=100)
    severity: Optional[str] = Field(None, max_length=20)
    category: Optional[str] = Field(None, max_length=100)
    enabled: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v is not None:
            valid_severities = ["low", "medium", "high", "critical"]
            if v.lower() not in valid_severities:
                raise ValueError(f"severity must be one of: {valid_severities}")
            return v.lower()
        return v

    @field_validator("patterns")
    @classmethod
    def validate_patterns_content(cls, v):
        if v is not None:
            for i, pattern in enumerate(v):
                if len(pattern) > 1000:
                    raise ValueError(
                        f"Pattern at index {i} exceeds maximum length of 1000 characters"
                    )
        return v


class RuleTestRequest(BaseModel):
    """规则测试请求模型"""

    rule_id: Optional[str] = Field(None, max_length=100)
    rule: Optional[Dict[str, Any]] = None
    test_content: str = Field(..., max_length=50000)

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id_format(cls, v):
        if v is not None and not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "rule_id must contain only alphanumeric characters, hyphens, and underscores"
            )
        return v


class RuleFeedbackRequest(BaseModel):
    """规则反馈模型"""

    rule_id: str = Field(..., max_length=100)
    true_positive: bool

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id_format(cls, v):
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "rule_id must contain only alphanumeric characters, hyphens, and underscores"
            )
        return v


class ThresholdUpdate(BaseModel):
    """阈值更新模型"""

    thresholds: Dict[str, float]


# 创建FastAPI应用
app = FastAPI(
    title="SkillScan API",
    description="Skills 威胁分析引擎 - 自动化安全扫描API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 配置CORS
settings = get_settings()
api_settings = settings.api
app.add_middleware(
    CORSMiddleware,
    allow_origins=api_settings.cors_origins
    if api_settings.cors_origins != ["*"]
    else ["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
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
@limiter.limit(f"{api_settings.rate_limit}/minute")
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_api_key),
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
        "request": scan_request.model_dump(),
    }

    # 后台执行扫描
    background_tasks.add_task(
        execute_scan,
        task_id=task_id,
        request=scan_request,
    )

    return ScanResponse(
        task_id=task_id,
        status="pending",
        message="Scan task created successfully",
    )


@app.get("/api/v1/scan/{task_id}")
async def get_scan_result(task_id: str = Field(..., pattern=r"^[A-Z0-9_-]+$", max_length=100)):
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
async def get_skill(skill_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]+$", max_length=100)):
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
@limiter.limit("10/minute")
async def register_webhook(
    request: Request,
    url: str = Field(..., max_length=2048),
    events: List[str] = Field(..., min_length=1, max_length=20),
    secret: Optional[str] = Field(None, max_length=256),
    auth: dict = Depends(require_api_key),
):
    """注册Webhook回调"""
    from src.api.webhooks import WebhookSecurityError

    valid_events = ["scan.completed", "scan.failed", "high_risk.detected", "config.changed"]
    for event in events:
        if event not in valid_events:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type '{event}'. Must be one of: {valid_events}",
            )

    try:
        webhook_id = webhook_manager.register_webhook(url, events, secret)
        return {
            "webhook_id": webhook_id,
            "url": url,
            "events": events,
            "status": "registered",
        }
    except WebhookSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]+$", max_length=100),
    auth: dict = Depends(require_api_key),
):
    """删除Webhook"""
    success = webhook_manager.unregister_webhook(webhook_id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted", "webhook_id": webhook_id}


@app.get("/api/v1/webhooks")
async def list_webhooks(auth: dict = Depends(require_api_key)):
    """列出所有Webhook"""
    return {"webhooks": webhook_manager.list_webhooks()}


@app.get("/api/v1/config/llm")
async def get_llm_config():
    """获取LLM配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    return llm_config_manager.get_config()


@app.get("/api/v1/config/llm/provider/{provider}")
async def get_provider_config(provider: str = Field(..., pattern=r"^[a-z_]+$", max_length=50)):
    """获取指定LLM提供商配置"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    config = llm_config_manager.get_provider_config(provider)
    if config is None:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' not found")

    return {"provider": provider, "config": config}


@app.put("/api/v1/config/llm/provider/{provider}")
async def update_provider_config(
    provider: str = Field(..., pattern=r'^[a-z_]+$', max_length=50),
    config: LLMProviderUpdate,
    auth: dict = Depends(require_api_key),
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
async def set_default_provider(
    provider: str = Field(..., pattern=r'^[a-z_]+$', max_length=50),
    auth: dict = Depends(require_api_key),
):
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
    auth: dict = Depends(require_api_key),
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
    auth: dict = Depends(require_api_key),
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
async def get_config_version(version_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100)):
    """获取指定配置版本"""
    if llm_config_manager is None:
        raise HTTPException(status_code=503, detail="LLM Config Manager not available")

    version = llm_config_manager.get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail=f"Version '{version_id}' not found")

    return version.to_dict()


@app.post("/api/v1/config/llm/versions/{version_id}/rollback")
async def rollback_config_version(
    version_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100),
    auth: dict = Depends(require_api_key),
):
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
async def reset_llm_config(auth: dict = Depends(require_api_key)):
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


@app.get("/api/v1/config/rules")
async def list_rules(
    enabled_only: bool = Query(False, description="Only return enabled rules"),
    language: Optional[str] = Query(None, description="Filter by language"),
    category: Optional[str] = Query(None, description="Filter by category"),
):
    """获取规则列表"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    rules = rule_config_manager.get_all_rules(enabled_only=enabled_only)

    if language:
        rules = [r for r in rules if r.get("language") == language]
    if category:
        rules = [r for r in rules if r.get("category") == category]

    return {"rules": rules, "total": len(rules)}


@app.post("/api/v1/config/rules")
async def create_rule(rule: RuleCreate, auth: dict = Depends(require_api_key)):
    """创建新规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    from src.rules.rule_config_manager import RuleConfigManager

    manager = rule_config_manager

    result = manager.create_rule(
        rule_id=rule.rule_id,
        pattern_code=rule.pattern_code,
        language=rule.language,
        name=rule.name,
        description=rule.description,
        patterns=rule.patterns,
        severity=rule.severity,
        category=rule.category,
        enabled=rule.enabled,
    )

    if not result:
        raise HTTPException(
            status_code=400, detail="Failed to create rule (rule_id may already exist)"
        )

    return {"success": True, "rule_id": rule.rule_id, "message": "Rule created successfully"}


@app.put("/api/v1/config/rules/{rule_id}")
async def update_rule(
    rule_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100),
    update: RuleUpdate = None,
    auth: dict = Depends(require_api_key),
):
    """更新规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    result = rule_config_manager.update_rule(rule_id, update.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    return {"success": True, "rule_id": rule_id, "message": "Rule updated successfully"}


@app.delete("/api/v1/config/rules/{rule_id}")
async def delete_rule(
    rule_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100),
    auth: dict = Depends(require_api_key),
):
    """删除规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    success = rule_config_manager.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    return {"success": True, "rule_id": rule_id, "message": "Rule deleted successfully"}


@app.get("/api/v1/config/rules/language/{language}")
async def get_rules_by_language(language: str = Field(..., pattern=r'^[A-Za-z0-9_+-]+$', max_length=50)):
    """按语言获取规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    rules = rule_config_manager.get_rules_by_language(language)
    return {"language": language, "rules": rules, "total": len(rules)}


@app.patch("/api/v1/config/rules/{rule_id}/enable")
async def toggle_rule(
    rule_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100),
    enabled: bool = Query(..., description="Enable or disable rule"),
    auth: dict = Depends(require_api_key),
):
    """启用/禁用规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    success = rule_config_manager.enable_rule(rule_id, enabled)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    return {"success": True, "rule_id": rule_id, "enabled": enabled}


@app.get("/api/v1/config/rules/thresholds")
async def get_thresholds():
    """获取语言阈值配置"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return {"thresholds": rule_config_manager.get_all_thresholds()}


@app.patch("/api/v1/config/rules/thresholds")
async def update_thresholds(thresholds: ThresholdUpdate):
    """更新语言阈值"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    for lang, threshold in thresholds.thresholds.items():
        rule_config_manager.set_language_threshold(lang, threshold)

    return {"success": True, "thresholds": rule_config_manager.get_all_thresholds()}


@app.get("/api/v1/config/rules/versions")
async def list_rule_versions(limit: int = Query(10, ge=1, le=100)):
    """获取规则版本历史"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return {"versions": rule_config_manager.get_versions(limit)}


@app.get("/api/v1/config/rules/versions/{version_id}")
async def get_rule_version(version_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100)):
    """获取指定规则版本"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    version = rule_config_manager.get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail=f"Version '{version_id}' not found")

    return version


@app.post("/api/v1/config/rules/versions/{version_id}/rollback")
async def rollback_rule_version(
    version_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100),
    auth: dict = Depends(require_api_key),
):
    """回滚到指定规则版本"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    success = rule_config_manager.rollback_version(version_id)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to rollback to version: {version_id}")

    return {
        "success": True,
        "version_id": version_id,
        "message": f"Rolled back to version '{version_id}'",
    }


@app.get("/api/v1/config/rules/versions/diff")
async def diff_rule_versions(
    version_id1: str = Query(..., description="First version ID"),
    version_id2: str = Query(..., description="Second version ID"),
):
    """比较两个规则版本的差异"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    version1 = rule_config_manager.get_version(version_id1)
    version2 = rule_config_manager.get_version(version_id2)

    if version1 is None or version2 is None:
        raise HTTPException(status_code=404, detail="One or both versions not found")

    changes = []
    rules1 = {r["rule_id"]: r for r in version1.get("rules", [])}
    rules2 = {r["rule_id"]: r for r in version2.get("rules", [])}

    all_ids = set(rules1.keys()) | set(rules2.keys())
    for rule_id in all_ids:
        if rule_id in rules1 and rule_id not in rules2:
            changes.append({"rule_id": rule_id, "change": "removed"})
        elif rule_id not in rules1 and rule_id in rules2:
            changes.append({"rule_id": rule_id, "change": "added"})
        elif rules1[rule_id] != rules2[rule_id]:
            changes.append(
                {
                    "rule_id": rule_id,
                    "change": "modified",
                    "before": rules1[rule_id],
                    "after": rules2[rule_id],
                }
            )

    return {"version1": version_id1, "version2": version_id2, "changes": changes}


@app.post("/api/v1/config/rules/versions")
async def create_rule_version(
    comment: str = Query("", description="Version comment"),
    auth: dict = Depends(require_api_key),
):
    """创建规则版本快照"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    version = rule_config_manager.create_version(comment=comment)
    return {
        "success": True,
        "version_id": version.version_id,
        "created_at": version.created_at.isoformat(),
    }


@app.get("/api/v1/config/rules/templates")
async def list_templates():
    """获取规则模板列表"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return {"templates": rule_config_manager.get_templates()}


@app.post("/api/v1/config/rules/templates/{template_id}/apply")
async def apply_template(template_id: str = Field(..., pattern=r'^[A-Za-z0-9_-]+$', max_length=100)):
    """应用规则模板"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    success = rule_config_manager.apply_template(template_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    return {
        "success": True,
        "template_id": template_id,
        "message": f"Template '{template_id}' applied",
    }


@app.get("/api/v1/config/rules/statistics")
async def get_rule_statistics():
    """获取规则统计信息"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return rule_config_manager.get_statistics()


@app.get("/api/v1/config/rules/effectiveness")
async def get_effectiveness():
    """获取规则效果统计"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return rule_config_manager.get_effectiveness_stats()


@app.get("/api/v1/config/rules/effectiveness/by-category")
async def get_effectiveness_by_category():
    """按分类获取规则效果"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    return rule_config_manager.get_effectiveness_by_category()


@app.post("/api/v1/config/rules/effectiveness/feedback")
async def record_feedback(feedback: RuleFeedbackRequest):
    """记录规则反馈"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    if feedback.true_positive:
        rule_config_manager.record_true_positive(feedback.rule_id)
    else:
        rule_config_manager.record_false_positive(feedback.rule_id)

    return {"success": True, "rule_id": feedback.rule_id, "true_positive": feedback.true_positive}


@app.post("/api/v1/config/rules/validate")
async def validate_rule(rule: Dict[str, Any]):
    """验证规则配置"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    result = rule_config_manager.validate_rule(rule)
    return result


@app.post("/api/v1/config/rules/test")
async def test_rule(request: RuleTestRequest):
    """测试规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    result = rule_config_manager.test_rule(
        rule_id=request.rule_id, rule=request.rule, test_content=request.test_content
    )
    return result


@app.post("/api/v1/config/rules/export")
async def export_rules(format: str = Query("json", regex="^(json|yaml)$")):
    """导出规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    rules = rule_config_manager.export_rules(format=format)
    return {"format": format, "data": rules}


@app.post("/api/v1/config/rules/import")
async def import_rules(
    data: Dict[str, Any],
    format: str = Query("json", regex="^(json|yaml)$"),
    replace: bool = Query(False),
    auth: dict = Depends(require_api_key),
):
    """导入规则"""
    if rule_config_manager is None:
        raise HTTPException(status_code=503, detail="Rule Config Manager not available")

    success = rule_config_manager.import_rules(
        data.get("rules", []), format=format, replace=replace
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to import rules")

    return {"success": True, "message": f"Imported {len(data.get('rules', []))} rules"}


@app.post("/api/v1/scans/{task_id}/report")
async def get_scan_report(
    task_id: str = Field(..., pattern=r'^[A-Z0-9_-]+$', max_length=100),
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
