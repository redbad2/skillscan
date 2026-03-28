"""
Git collector module

支持从 Git 仓库克隆并扫描技能文件。
"""

import asyncio
import subprocess
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path

from loguru import logger

from src.collectors.base import BaseCollector, SkillSource, SourceChannel


class GitCollector(BaseCollector):
    """Git 仓库收集器"""

    def __init__(
        self,
        db_manager=None,
        clone_dir: str | None = None,
        shallow_clone: bool = True,
        branch: str | None = None,
    ):
        super().__init__(db_manager)
        self.clone_dir = (
            Path(clone_dir) if clone_dir else Path(tempfile.gettempdir()) / "skillscan_git"
        )
        self.shallow_clone = shallow_clone
        self.branch = branch
        self._ensure_clone_dir()

    def _ensure_clone_dir(self) -> None:
        """确保克隆目录存在"""
        self.clone_dir.mkdir(parents=True, exist_ok=True)

    @property
    def name(self) -> str:
        return "git_collector"

    @property
    def channel(self) -> SourceChannel:
        return SourceChannel.LOCAL_SCAN

    async def collect(self, repo_url: str, **kwargs) -> list[SkillSource]:
        """
        从 Git 仓库克隆并收集技能文件

        Args:
            repo_url: Git 仓库 URL
            **kwargs: 其他参数

        Returns:
            技能列表
        """
        skills = []
        try:
            cloned_path = await self._clone_repository(repo_url)
            if cloned_path:
                async for skill in self._scan_cloned_repo(cloned_path, repo_url):
                    skills.append(skill)
        except Exception as e:
            logger.error(f"Error collecting from {repo_url}: {e}")
            self._stats["errors"] += 1

        return skills

    async def _clone_repository(self, repo_url: str) -> Path | None:
        """
        克隆 Git 仓库

        Args:
            repo_url: 仓库 URL

        Returns:
            克隆后的本地路径
        """
        repo_name = self._get_repo_name(repo_url)
        dest_path = self.clone_dir / repo_name

        if dest_path.exists():
            logger.info(f"Repository already cloned, pulling latest: {repo_url}")
            await self._pull_repository(dest_path)
            return dest_path

        logger.info(f"Cloning repository: {repo_url}")

        cmd = ["git", "clone"]
        if self.shallow_clone:
            cmd.append("--depth=1")
        if self.branch:
            cmd.extend(["--branch", self.branch])
        cmd.extend([repo_url, str(dest_path)])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            if proc.returncode != 0:
                logger.error(f"Git clone failed: {stderr.decode()}")
                return None

            logger.info(f"Successfully cloned: {repo_url}")
            return dest_path

        except asyncio.TimeoutError:
            logger.error(f"Git clone timeout: {repo_url}")
            return None
        except Exception as e:
            logger.error(f"Git clone error: {e}")
            return None

    async def _pull_repository(self, repo_path: Path) -> bool:
        """
        拉取最新代码

        Args:
            repo_path: 仓库本地路径

        Returns:
            是否成功
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "pull",
                "--ff-only",
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Git pull error: {e}")
            return False

    async def _scan_cloned_repo(
        self, repo_path: Path, repo_url: str
    ) -> AsyncGenerator[SkillSource, None]:
        """
        扫描克隆的仓库

        Args:
            repo_path: 仓库路径
            repo_url: 原始 URL
        """
        from src.collectors.local_collector import LocalCollector

        local_collector = LocalCollector(db_manager=self.db_manager, base_path=str(repo_path))

        try:
            async for skill in local_collector.collect():
                skill.source_path = repo_url
                skill.platform = "git"
                yield skill
                self._stats["collected"] += 1
        except Exception as e:
            logger.error(f"Error scanning cloned repo: {e}")
            self._stats["errors"] += 1

    def _get_repo_name(self, repo_url: str) -> str:
        """
        从 URL 提取仓库名称

        Args:
            repo_url: 仓库 URL

        Returns:
            仓库名称
        """
        path = repo_url.rstrip("/").rsplit("/", 1)[-1]
        if path.endswith(".git"):
            path = path[:-4]
        return path

    async def validate_source(self, source: SkillSource) -> bool:
        """验证技能源有效性"""
        if not source.content or len(source.content) < 100:
            return False
        return True

    def get_repo_commit_hash(self, repo_path: Path) -> str | None:
        """
        获取当前 commit hash

        Args:
            repo_path: 仓库路径

        Returns:
            commit hash
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None


class GitWatcher:
    """Git 仓库监控器，支持定期更新多个仓库"""

    def __init__(
        self,
        repos: list[str],
        git_collector: GitCollector,
        update_interval: int = 3600,
    ):
        self.repos = repos
        self.git_collector = git_collector
        self.update_interval = update_interval
        self._running = False

    async def start(self) -> None:
        """启动监控"""
        self._running = True
        while self._running:
            await self._update_all()
            await asyncio.sleep(self.update_interval)

    async def stop(self) -> None:
        """停止监控"""
        self._running = False

    async def _update_all(self) -> None:
        """更新所有仓库"""
        for repo_url in self.repos:
            try:
                await self.git_collector.collect(repo_url)
            except Exception as e:
                logger.error(f"Error updating repo {repo_url}: {e}")
