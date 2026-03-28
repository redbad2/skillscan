"""
Collection and scan task models.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import Field, BaseModel

from .common import (
    BaseDocument, TimestampMixin, Language, 
    Platform, CollectionChannel, ScanStatus, ScanPriority
)


class CollectionInfo(BaseModel):
    """Collection information for skill documents."""
    channel: CollectionChannel
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    original_path: Optional[str] = None
    source_platform: Platform = Platform.UNKNOWN
    file_size: int = 0
    collection_attempt: int = 1
    collection_error: Optional[str] = None


class ScanTask(BaseDocument, TimestampMixin):
    """Scan task model for tracking scan jobs."""
    
    task_id: str = Field(..., description="Unique task identifier")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    priority: ScanPriority = Field(default=ScanPriority.NORMAL)
    
    # Task configuration
    skill_ids: List[str] = Field(default_factory=list, description="Skills to scan")
    scan_type: str = Field(default="full", description="full, static_only, llm_only")
    
    # Progress tracking
    total_skills: int = 0
    completed_skills: int = 0
    failed_skills: int = 0
    progress_percentage: float = 0.0
    
    # Results
    results: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_duration_ms: Optional[int] = None
    
    # Metadata
    created_by: Optional[str] = None
    description: Optional[str] = None
    
    class Config:
        populate_by_name = True


class CrawlTask(BaseDocument, TimestampMixin):
    """Crawl task model for network collection."""
    
    task_id: str = Field(..., description="Unique task identifier")
    platform: Platform = Field(..., description="Platform to crawl")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    
    # Crawl configuration
    crawl_type: str = Field(default="incremental", description="full or incremental")
    since: Optional[datetime] = None
    limit: Optional[int] = None
    
    # Progress tracking
    total_found: int = 0
    collected: int = 0
    failed: int = 0
    duplicates: int = 0
    
    # Results
    collected_skill_ids: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    
    class Config:
        populate_by_name = True


class LocalScanTask(BaseDocument, TimestampMixin):
    """Local scan task model for local directory collection."""
    
    task_id: str = Field(..., description="Unique task identifier")
    root_path: str = Field(..., description="Root directory path")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    
    # Scan configuration
    recursive: bool = True
    watch_for_changes: bool = False
    patterns: List[str] = Field(default=["**/SKILL.md", "**/skill.md"])
    ignore_patterns: List[str] = Field(default=["node_modules", ".git", "__pycache__"])
    
    # Progress tracking
    files_scanned: int = 0
    skills_found: int = 0
    errors: int = 0
    
    # Results
    discovered_skill_ids: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    
    class Config:
        populate_by_name = True