"""
文件系统监控模块

支持跨平台的文件系统监控（inotify/FSEvents/ReadDirectoryChangesW）。
"""

import asyncio
import fnmatch
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger


class EventType(str, Enum):
    """文件系统事件类型"""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"


@dataclass
class FileEvent:
    """文件系统事件"""

    event_type: EventType
    path: Path
    is_directory: bool
    timestamp: float


class FileWatcher:
    """跨平台文件系统监控器"""

    def __init__(
        self,
        watch_paths: list[str | Path],
        patterns: list[str] | None = None,
        ignore_patterns: list[str] | None = None,
        recursive: bool = True,
    ):
        self.watch_paths = [Path(p) for p in watch_paths]
        self.patterns = patterns or ["**/SKILL.md", "**/skill.md"]
        self.ignore_patterns = ignore_patterns or [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            ".tox",
            "dist",
            "build",
            ".eggs",
            "*.pyc",
            ".DS_Store",
            ".skillignore",
        ]
        self.recursive = recursive
        self._callbacks: list[Callable[[FileEvent], None]] = []
        self._running = False
        self._watched_paths: set[Path] = set()

    def add_callback(self, callback: Callable[[FileEvent], None]) -> None:
        """添加事件回调"""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[FileEvent], None]) -> None:
        """移除事件回调"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _should_process(self, path: Path) -> bool:
        """检查路径是否应该处理"""
        path_str = str(path)

        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return False
            if "/" in path_str:
                parts = path_str.split("/")
                for part in parts:
                    if fnmatch.fnmatch(part, pattern):
                        return False

        if self.patterns:
            for pattern in self.patterns:
                if pattern.startswith("**/"):
                    suffix = pattern[3:]
                    if path.name == suffix or path.name.lower() == suffix.lower():
                        return True
                elif fnmatch.fnmatch(path.name, pattern):
                    return True
            return False

        return True

    async def start(self) -> None:
        """启动监控"""
        self._running = True
        for watch_path in self.watch_paths:
            if watch_path.exists() and watch_path.is_dir():
                self._watched_paths.add(watch_path)

        if not self._watched_paths:
            logger.warning("No valid directories to watch")
            return

        platform = self._get_platform()
        logger.info(f"Starting file watcher on {len(self._watched_paths)} paths ({platform})")

        if platform == "linux":
            await self._watch_linux()
        elif platform == "darwin":
            await self._watch_macos()
        elif platform == "windows":
            await self._watch_windows()
        else:
            await self._watch_poll()

    async def stop(self) -> None:
        """停止监控"""
        self._running = False
        logger.info("File watcher stopped")

    def _get_platform(self) -> str:
        """获取平台类型"""
        import platform

        return platform.system().lower()

    async def _watch_linux(self) -> None:
        """Linux: 使用 inotify"""
        try:
            import inotify.adapters

            i = inotify.adapters.Inotify()
            for path in self._watched_paths:
                i.add_watch(str(path))
                logger.info(f"Watching (inotify): {path}")

            for event in i.event_gen(yield_nones=False, timeout_s=1):
                if not self._running:
                    break

                _, event_types, path, filename = event
                full_path = Path(path) / filename

                if not self._should_process(full_path):
                    continue

                for callback in self._callbacks:
                    try:
                        if "IN_CREATE" in event_types or "IN_MOVED_TO" in event_types:
                            if full_path.is_dir():
                                i.add_watch(str(full_path))
                            await asyncio.sleep(0.1)
                            if full_path.exists():
                                callback(
                                    FileEvent(
                                        event_type=EventType.CREATED,
                                        path=full_path,
                                        is_directory=full_path.is_dir(),
                                        timestamp=asyncio.get_event_loop().time(),
                                    )
                                )
                        elif "IN_MODIFY" in event_types:
                            callback(
                                FileEvent(
                                    event_type=EventType.MODIFIED,
                                    path=full_path,
                                    is_directory=full_path.is_dir(),
                                    timestamp=asyncio.get_event_loop().time(),
                                )
                            )
                        elif "IN_DELETE" in event_types or "IN_MOVED_FROM" in event_types:
                            callback(
                                FileEvent(
                                    event_type=EventType.DELETED,
                                    path=full_path,
                                    is_directory=False,
                                    timestamp=asyncio.get_event_loop().time(),
                                )
                            )
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

        except ImportError:
            logger.warning("inotify not available, falling back to polling")
            await self._watch_poll()
        except Exception as e:
            logger.error(f"inotify error: {e}")
            await self._watch_poll()

    async def _watch_macos(self) -> None:
        """macOS: 使用 FSEvents"""
        try:
            import fsevents

            def fsevents_callback(event):
                if not self._running:
                    return

                for callback in self._callbacks:
                    try:
                        flags = event.flags
                        path = Path(event.path)

                        if not self._should_process(path):
                            return

                        if "ItemCreated" in flags or "ItemRenamed" in flags:
                            callback(
                                FileEvent(
                                    event_type=EventType.CREATED,
                                    path=path,
                                    is_directory=path.is_dir() if path.exists() else False,
                                    timestamp=event.time,
                                )
                            )
                        elif "ItemModified" in flags:
                            callback(
                                FileEvent(
                                    event_type=EventType.MODIFIED,
                                    path=path,
                                    is_directory=False,
                                    timestamp=event.time,
                                )
                            )
                        elif "ItemRemoved" in flags:
                            callback(
                                FileEvent(
                                    event_type=EventType.DELETED,
                                    path=path,
                                    is_directory=False,
                                    timestamp=event.time,
                                )
                            )
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

            observer = fsevents.Observer()
            stream = fsevents.Stream(
                fsevents_callback, *[str(p) for p in self._watched_paths], recursive=self.recursive
            )
            observer.schedule(stream)
            observer.start()

            while self._running:
                await asyncio.sleep(1)

            observer.stop()
            observer.join()

        except ImportError:
            logger.warning("fsevents not available, falling back to polling")
            await self._watch_poll()
        except Exception as e:
            logger.error(f"FSEvents error: {e}")
            await self._watch_poll()

    async def _watch_windows(self) -> None:
        """Windows: 使用 ReadDirectoryChangesW"""
        try:
            import win32con
            import win32file

            FILE_LIST_DIRECTORY = 0x0001  # noqa: N806 - Windows API constant naming

            async def watch_dir(dir_path: Path):
                hDir = win32file.CreateFile(  # noqa: N806 - Windows API variable naming
                    str(dir_path),
                    FILE_LIST_DIRECTORY,
                    win32con.FILE_SHARE_READ
                    | win32con.FILE_SHARE_WRITE
                    | win32con.FILE_SHARE_DELETE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                    None,
                )

                while self._running:
                    try:
                        results = win32file.ReadDirectoryChangesW(
                            hDir,
                            4096,
                            self.recursive,
                            win32con.FILE_NOTIFY_CHANGE_FILE_NAME
                            | win32con.FILE_NOTIFY_CHANGE_DIR_NAME
                            | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                            None,
                            None,
                        )

                        for action, filename in results:
                            full_path = dir_path / filename
                            if not self._should_process(full_path):
                                continue

                            for callback in self._callbacks:
                                try:
                                    if action == win32con.FILE_ACTION_CREATED:
                                        callback(
                                            FileEvent(
                                                event_type=EventType.CREATED,
                                                path=full_path,
                                                is_directory=filename.endswith("\\"),
                                                timestamp=asyncio.get_event_loop().time(),
                                            )
                                        )
                                    elif action == win32con.FILE_ACTION_MODIFIED:
                                        callback(
                                            FileEvent(
                                                event_type=EventType.MODIFIED,
                                                path=full_path,
                                                is_directory=False,
                                                timestamp=asyncio.get_event_loop().time(),
                                            )
                                        )
                                    elif action == win32con.FILE_ACTION_DELETED:
                                        callback(
                                            FileEvent(
                                                event_type=EventType.DELETED,
                                                path=full_path,
                                                is_directory=False,
                                                timestamp=asyncio.get_event_loop().time(),
                                            )
                                        )
                                except Exception as e:
                                    logger.error(f"Callback error: {e}")

                    except Exception as e:
                        logger.error(f"Watch error: {e}")
                        await asyncio.sleep(1)

                win32file.CloseHandle(hDir)

            tasks = [asyncio.create_task(watch_dir(p)) for p in self._watched_paths]
            await asyncio.gather(*tasks, return_exceptions=True)

        except ImportError:
            logger.warning("pywin32 not available, falling back to polling")
            await self._watch_poll()
        except Exception as e:
            logger.error(f"Windows watcher error: {e}")
            await self._watch_poll()

    async def _watch_poll(self) -> None:
        """轮询方式（跨平台备选）"""
        import hashlib
        import time

        file_hashes: dict[Path, str] = {}

        def compute_hash(path: Path) -> str | None:
            try:
                content = path.read_bytes()
                return hashlib.md5(content).hexdigest()
            except Exception:
                return None

        while self._running:
            for watch_path in self._watched_paths:
                try:
                    for item in watch_path.rglob("*") if self.recursive else watch_path.iterdir():
                        if not item.is_file():
                            continue
                        if not self._should_process(item):
                            continue

                        current_hash = compute_hash(item)
                        if current_hash is None:
                            continue

                        if item not in file_hashes:
                            file_hashes[item] = current_hash
                            for callback in self._callbacks:
                                try:
                                    callback(
                                        FileEvent(
                                            event_type=EventType.CREATED,
                                            path=item,
                                            is_directory=False,
                                            timestamp=time.time(),
                                        )
                                    )
                                except Exception as e:
                                    logger.error(f"Callback error: {e}")
                        elif file_hashes[item] != current_hash:
                            file_hashes[item] = current_hash
                            for callback in self._callbacks:
                                try:
                                    callback(
                                        FileEvent(
                                            event_type=EventType.MODIFIED,
                                            path=item,
                                            is_directory=False,
                                            timestamp=time.time(),
                                        )
                                    )
                                except Exception as e:
                                    logger.error(f"Callback error: {e}")

                    for old_path in list(file_hashes.keys()):
                        if not old_path.exists():
                            del file_hashes[old_path]
                            for callback in self._callbacks:
                                try:
                                    callback(
                                        FileEvent(
                                            event_type=EventType.DELETED,
                                            path=old_path,
                                            is_directory=False,
                                            timestamp=time.time(),
                                        )
                                    )
                                except Exception as e:
                                    logger.error(f"Callback error: {e}")

                except Exception as e:
                    logger.error(f"Poll error: {e}")

            await asyncio.sleep(2)


class SkillWatcher:
    """技能文件专用监控器"""

    def __init__(
        self,
        watch_paths: list[str | Path],
        local_collector,
        on_skill_added: Callable | None = None,
        on_skill_modified: Callable | None = None,
        on_skill_deleted: Callable | None = None,
    ):
        self.watcher = FileWatcher(
            watch_paths=watch_paths,
            patterns=["**/SKILL.md", "**/skill.md"],
            recursive=True,
        )
        self.local_collector = local_collector
        self.on_skill_added = on_skill_added
        self.on_skill_modified = on_skill_modified
        self.on_skill_deleted = on_skill_deleted
        self._processed_skills: dict[Path, str] = {}

    async def start(self) -> None:
        """启动监控"""
        self.watcher.add_callback(self._handle_event)
        await self.watcher.start()

    async def stop(self) -> None:
        """停止监控"""
        await self.watcher.stop()

    async def _handle_event(self, event: FileEvent) -> None:
        """处理文件事件"""
        if event.event_type == EventType.CREATED:
            if event.path.name.lower() == "skill.md":
                skill = await self._load_skill(event.path.parent)
                if skill:
                    self._processed_skills[event.path.parent] = skill.content_hash
                    if self.on_skill_added:
                        await self.on_skill_added(skill)

        elif event.event_type == EventType.MODIFIED:
            if event.path.name.lower() == "skill.md":
                skill_dir = event.path.parent
                skill = await self._load_skill(skill_dir)
                if skill:
                    self._processed_skills[skill_dir] = skill.content_hash
                    if self.on_skill_modified:
                        await self.on_skill_modified(skill)

        elif event.event_type == EventType.DELETED:
            if event.path.name.lower() == "skill.md":
                skill_dir = event.path.parent
                if skill_dir in self._processed_skills:
                    del self._processed_skills[skill_dir]
                    if self.on_skill_deleted:
                        await self.on_skill_deleted(str(skill_dir))

    async def _load_skill(self, skill_dir: Path):
        """加载技能"""

        skill_md_path = skill_dir / "SKILL.md"
        if skill_md_path.exists():
            return await self.local_collector._load_skill(skill_dir, skill_md_path)
        return None
