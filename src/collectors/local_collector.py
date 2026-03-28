"""
本地收集器模块

支持递归扫描本地目录、批量导入压缩包、Git仓库克隆。
"""

import os
import re
import hashlib
import zipfile
import tarfile
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncGenerator
from datetime import datetime

import yaml
from loguru import logger

from src.collectors.base import BaseCollector, SkillSource, SourceChannel


class LocalCollector(BaseCollector):
    """本地文件收集器"""

    def __init__(self, db_manager=None, base_path: str = "."):
        super().__init__(db_manager)
        self.base_path = Path(base_path)
        self._skill_pattern = re.compile(r"^SKILL\.md$", re.IGNORECASE)
        self._script_extensions = {
            ".py": "python",
            ".sh": "shell",
            ".bash": "shell",
            ".js": "javascript",
            ".ts": "typescript",
            ".rb": "ruby",
            ".pl": "perl",
        }

    @property
    def name(self) -> str:
        return "local_collector"

    @property
    def channel(self) -> SourceChannel:
        return SourceChannel.LOCAL_SCAN

    async def collect(self, limit: Optional[int] = None) -> List[SkillSource]:
        """
        递归扫描目录收集技能文件

        Args:
            limit: 最大收集数量

        Returns:
            技能文件列表
        """
        skills: List[SkillSource] = []

        logger.info(f"Starting local scan: {self.base_path}")

        try:
            async for skill in self._scan_directory(self.base_path, limit):
                if limit and len(skills) >= limit:
                    break
                skills.append(skill)
                self._stats["collected"] += 1

                if len(skills) % 100 == 0:
                    logger.info(f"Collected {len(skills)} skills so far...")

        except Exception as e:
            logger.error(f"Error during local scan: {e}")
            self._stats["errors"] += 1

        logger.info(f"Local scan completed: {len(skills)} skills collected")
        return skills

    async def _scan_directory(
        self, directory: Path, limit: Optional[int] = None
    ) -> AsyncGenerator[SkillSource, None]:
        """递归扫描目录"""
        if not directory.exists() or not directory.is_dir():
            logger.warning(f"Directory does not exist: {directory}")
            return

        for item in directory.iterdir():
            if limit and self._stats["collected"] >= limit:
                return

            try:
                # 跳过隐藏文件和目录
                if item.name.startswith("."):
                    continue

                # 检查是否为压缩包
                if item.is_file() and self._is_archive(item):
                    async for skill in self._extract_archive(item):
                        yield skill
                    continue

                # 检查是否包含SKILL.md
                if item.is_dir():
                    skill_md_path = self._find_skill_md(item)
                    if skill_md_path:
                        skill = await self._load_skill(item, skill_md_path)
                        if skill:
                            yield skill
                    else:
                        # 递归扫描子目录
                        async for skill in self._scan_directory(item, limit):
                            yield skill

            except Exception as e:
                logger.error(f"Error scanning {item}: {e}")
                self._stats["errors"] += 1

    def _find_skill_md(self, directory: Path) -> Optional[Path]:
        """查找SKILL.md文件"""
        # 首先检查当前目录
        for file in directory.iterdir():
            if self._skill_pattern.match(file.name):
                return file

        # 检查常见的子目录
        for subdir in ["docs", "instructions"]:
            subdir_path = directory / subdir
            if subdir_path.is_dir():
                for file in subdir_path.iterdir():
                    if self._skill_pattern.match(file.name):
                        return file

        return None

    async def _load_skill(self, skill_dir: Path, skill_md_path: Path) -> Optional[SkillSource]:
        """加载技能文件"""
        try:
            # 读取SKILL.md内容
            content = skill_md_path.read_text(encoding="utf-8")

            # 提取元数据
            metadata = self._extract_metadata(content)

            # 查找脚本文件
            scripts = self._find_scripts(skill_dir)

            # 创建技能源
            skill = SkillSource(
                name=metadata.get("name", skill_dir.name),
                content=content,
                scripts=scripts,
                source_path=str(skill_dir),
                platform="local",
                channel=SourceChannel.LOCAL_SCAN,
                file_size=len(content.encode("utf-8")),
                metadata=metadata,
                collected_at=datetime.utcnow(),
            )

            # 验证
            if await self.validate_source(skill):
                return skill
            else:
                logger.debug(f"Invalid skill source: {skill_dir}")
                return None

        except Exception as e:
            logger.error(f"Error loading skill from {skill_dir}: {e}")
            self._stats["errors"] += 1
            return None

    def _extract_metadata(self, content: str) -> Dict[str, Any]:
        """从SKILL.md提取YAML元数据"""
        metadata = {}

        # 查找YAML frontmatter
        yaml_pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
        match = yaml_pattern.match(content)

        if match:
            try:
                metadata = yaml.safe_load(match.group(1)) or {}
            except yaml.YAMLError as e:
                logger.warning(f"Error parsing YAML frontmatter: {e}")

        # 如果没有frontmatter，尝试从标题提取
        if not metadata.get("name"):
            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            if title_match:
                metadata["name"] = title_match.group(1).strip()

        return metadata

    def _find_scripts(self, skill_dir: Path) -> List[Dict[str, str]]:
        """查找脚本文件"""
        scripts = []

        # 检查scripts目录
        scripts_dir = skill_dir / "scripts"
        if scripts_dir.is_dir():
            for file in scripts_dir.iterdir():
                if file.is_file():
                    script_info = self._read_script(file)
                    if script_info:
                        scripts.append(script_info)

        # 检查根目录下的脚本文件
        for file in skill_dir.iterdir():
            if file.is_file() and file.suffix.lower() in self._script_extensions:
                script_info = self._read_script(file)
                if script_info:
                    scripts.append(script_info)

        return scripts

    def _read_script(self, file_path: Path) -> Optional[Dict[str, str]]:
        """读取脚本文件"""
        try:
            content = file_path.read_text(encoding="utf-8")
            return {
                "filename": file_path.name,
                "content": content,
                "language": self._script_extensions.get(file_path.suffix.lower(), "unknown"),
            }
        except Exception as e:
            logger.warning(f"Error reading script {file_path}: {e}")
            return None

    def _is_archive(self, file_path: Path) -> bool:
        """检查是否为压缩包"""
        archive_extensions = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".7z"}
        return file_path.suffix.lower() in archive_extensions

    async def _extract_archive(self, archive_path: Path) -> AsyncGenerator[SkillSource, None]:
        """从压缩包提取技能文件"""
        temp_dir = archive_path.parent / f".tmp_{archive_path.stem}"
        temp_dir.mkdir(exist_ok=True)

        try:
            if archive_path.suffix.lower() == ".zip":
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(temp_dir)
            elif archive_path.suffix.lower() in {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2"}:
                with tarfile.open(archive_path, "r:*") as tf:
                    tf.extractall(temp_dir)

            # 扫描提取的目录
            async for skill in self._scan_directory(temp_dir):
                # 更新source_path为原始压缩包路径
                skill.source_path = str(archive_path)
                yield skill

        except Exception as e:
            logger.error(f"Error extracting archive {archive_path}: {e}")
            self._stats["errors"] += 1

        finally:
            # 清理临时目录
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    async def validate_source(self, source: SkillSource) -> bool:
        """验证技能源有效性"""
        if not source.content:
            return False

        # 检查内容长度（至少100字符）
        if len(source.content) < 100:
            return False

        # 检查是否有基本结构（标题或说明）
        if not re.search(r"^#\s+", source.content, re.MULTILINE):
            return False

        return True

    async def scan_path(self, path: str, limit: Optional[int] = None) -> List[SkillSource]:
        """扫描指定路径"""
        scan_path = Path(path)

        if scan_path.is_file():
            if self._is_archive(scan_path):
                skills = []
                async for skill in self._extract_archive(scan_path):
                    if limit and len(skills) >= limit:
                        break
                    skills.append(skill)
                return skills
            else:
                # 单文件处理
                try:
                    content = scan_path.read_text(encoding="utf-8")
                    metadata = self._extract_metadata(content)
                    skill = SkillSource(
                        name=metadata.get("name", scan_path.stem),
                        content=content,
                        scripts=[],
                        source_path=str(scan_path),
                        platform="local",
                        channel=SourceChannel.LOCAL_SCAN,
                        file_size=len(content.encode("utf-8")),
                        metadata=metadata,
                    )
                    if await self.validate_source(skill):
                        return [skill]
                except Exception as e:
                    logger.error(f"Error reading file {scan_path}: {e}")
                return []
        elif scan_path.is_dir():
            skills = []
            async for skill in self._scan_directory(scan_path, limit):
                skills.append(skill)
            return skills
        else:
            logger.error(f"Path does not exist: {path}")
            return []
