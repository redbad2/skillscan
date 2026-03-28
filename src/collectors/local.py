"""
Local collector for scanning local directories.
"""

import asyncio
import logging
from typing import List, Optional, AsyncIterator, Dict, Any, Set
from pathlib import Path
import aiofiles
import fnmatch
import json
import zipfile
import tarfile

from .base import BaseCollector
from ..models import (
    SkillDocument, ScriptFile, CollectionInfo, 
    CollectionChannel, Platform, Language
)
from ..config import settings

logger = logging.getLogger(__name__)


class LocalCollector(BaseCollector):
    """Collect skills from local filesystem."""
    
    def __init__(
        self,
        root_path: str = ".",
        recursive: bool = True,
        patterns: Optional[List[str]] = None,
        ignore_patterns: Optional[List[str]] = None,
    ):
        super().__init__(name="local")
        self.root_path = Path(root_path).resolve()
        self.recursive = recursive
        self.patterns = patterns or ["**/SKILL.md", "**/skill.md"]
        self.ignore_patterns = ignore_patterns or [
            "node_modules", ".git", "__pycache__", ".venv", 
            "venv", ".tox", "dist", "build", ".eggs",
            "*.pyc", ".DS_Store"
        ]
        self._seen_hashes: Set[str] = set()
    
    async def test_connection(self) -> bool:
        """Test if root path exists and is accessible."""
        try:
            return self.root_path.exists() and self.root_path.is_dir()
        except Exception as e:
            logger.error(f"Path test failed: {e}")
            return False
    
    async def collect(self, **kwargs) -> AsyncIterator[SkillDocument]:
        """Collect skills from local filesystem."""
        if not await self.test_connection():
            raise ValueError(f"Root path not accessible: {self.root_path}")
        
        logger.info(f"Starting local collection from: {self.root_path}")
        
        # Find all SKILL.md files
        skill_files = await self._find_skill_files()
        logger.info(f"Found {len(skill_files)} SKILL.md files")
        
        for skill_file_path in skill_files:
            try:
                skill = await self._process_skill_directory(skill_file_path)
                if skill:
                    # Check for duplicates using content hash
                    content_hash = self.calculate_content_hash(skill)
                    if content_hash in self._seen_hashes:
                        self.update_stats(True, duplicate=True)
                        continue
                    
                    self._seen_hashes.add(content_hash)
                    yield skill
                    self.update_stats(True)
                    
            except Exception as e:
                logger.error(f"Error processing {skill_file_path}: {e}")
                self.update_stats(False)
    
    async def _find_skill_files(self) -> List[Path]:
        """Find all SKILL.md files in the directory tree."""
        skill_files = []
        
        for pattern in self.patterns:
            if self.recursive:
                # Use async glob-like iteration
                async for path in self._walk_directory(self.root_path):
                    if self._matches_pattern(path, pattern):
                        if not self._should_ignore(path):
                            skill_files.append(path)
            else:
                # Non-recursive: only check immediate directory
                for path in self.root_path.iterdir():
                    if path.is_file() and self._matches_pattern(path.name, pattern):
                        skill_files.append(path)
        
        return sorted(set(skill_files))
    
    async def _walk_directory(self, directory: Path):
        """Async directory walker."""
        try:
            for path in directory.iterdir():
                if path.is_dir():
                    if not self._should_ignore(path):
                        async for child in self._walk_directory(path):
                            yield child
                elif path.is_file():
                    yield path
        except PermissionError:
            logger.warning(f"Permission denied: {directory}")
        except Exception as e:
            logger.error(f"Error walking {directory}: {e}")
    
    def _matches_pattern(self, path: Path, pattern: str) -> bool:
        """Check if path matches the given pattern."""
        path_str = str(path)
        
        # Simple pattern matching
        if pattern.startswith("**/"):
            # Recursive pattern
            suffix = pattern[3:]
            return path.name == suffix or path.name.lower() == suffix.lower()
        else:
            # Direct pattern
            return fnmatch.fnmatch(path.name, pattern)
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        parts = path.relative_to(self.root_path).parts
        
        for part in parts:
            for pattern in self.ignore_patterns:
                if fnmatch.fnmatch(part, pattern):
                    return True
                if pattern.startswith("*") and part.endswith(pattern[1:]):
                    return True
        
        return False
    
    async def _process_skill_directory(self, skill_md_path: Path) -> Optional[SkillDocument]:
        """Process a directory containing a SKILL.md file."""
        try:
            # Read SKILL.md content
            async with aiofiles.open(skill_md_path, 'r', encoding='utf-8') as f:
                skill_md_content = await f.read()
            
            # Get directory and skill name
            skill_dir = skill_md_path.parent
            skill_name = skill_dir.name
            
            # Create skill document
            skill = SkillDocument(
                skill_id=f"local_{skill_dir.relative_to(self.root_path).as_posix().replace('/', '_')}",
                name=skill_name,
                platform=Platform.LOCAL,
                source=CollectionChannel.LOCAL_SCAN,
                skill_md_content=skill_md_content,
            )
            
            # Extract metadata
            skill.metadata = self.extract_metadata(skill_md_content)
            if not skill.metadata.author:
                skill.metadata.author = "local"
            if not skill.metadata.description:
                skill.metadata.description = f"Local skill from {skill_dir}"
            
            # Detect language
            lang, confidence = self.detect_language(skill_md_content)
            skill.language = lang
            
            # Find and read script files
            scripts = await self._find_script_files(skill_dir)
            skill.scripts = scripts
            
            # Set collection info
            skill.collection_info = CollectionInfo(
                channel=CollectionChannel.LOCAL_SCAN,
                source_platform=Platform.LOCAL,
                original_path=str(skill_dir),
                file_size=skill_md_path.stat().st_size,
            )
            
            return skill
            
        except Exception as e:
            logger.error(f"Error processing skill directory {skill_md_path}: {e}")
            return None
    
    async def _find_script_files(self, skill_dir: Path) -> List[ScriptFile]:
        """Find and read script files in the skill directory."""
        scripts = []
        
        # Common script directories and files
        script_dirs = ["scripts", "src", "lib", "."]
        script_extensions = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".go"}
        
        for script_dir_name in script_dirs:
            script_dir = skill_dir / script_dir_name
            
            if script_dir.exists() and script_dir.is_dir():
                for file_path in script_dir.rglob("*"):
                    if file_path.is_file() and file_path.suffix in script_extensions:
                        try:
                            script = await self._read_script_file(file_path, skill_dir)
                            if script:
                                scripts.append(script)
                        except Exception as e:
                            logger.warning(f"Error reading {file_path}: {e}")
        
        return scripts
    
    async def _read_script_file(self, file_path: Path, base_dir: Path) -> Optional[ScriptFile]:
        """Read and create a ScriptFile object."""
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > settings.analyzer.max_file_size_mb * 1024 * 1024:
                logger.warning(f"File too large, skipping: {file_path}")
                return None
            
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            # Get relative path for filename
            relative_path = file_path.relative_to(base_dir)
            
            return self.create_script_file(str(relative_path), content)
            
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                async with aiofiles.open(file_path, 'r', encoding='latin-1') as f:
                    content = await f.read()
                relative_path = file_path.relative_to(base_dir)
                return self.create_script_file(str(relative_path), content)
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
                return None
        except Exception as e:
            logger.error(f"Error reading script file {file_path}: {e}")
            return None
    
    async def collect_archive(self, archive_path: str) -> AsyncIterator[SkillDocument]:
        """Collect skills from an archive file (ZIP or TAR)."""
        archive = Path(archive_path)
        
        if not archive.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if archive.suffix.lower() == '.zip':
            async for skill in self._collect_from_zip(archive):
                yield skill
        elif archive.suffix.lower() in ['.tar', '.gz', '.bz2', '.xz']:
            async for skill in self._collect_from_tar(archive):
                yield skill
        else:
            raise ValueError(f"Unsupported archive format: {archive.suffix}")
    
    async def _collect_from_zip(self, zip_path: Path) -> AsyncIterator[SkillDocument]:
        """Collect skills from a ZIP archive."""
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(tmp_path)
                
                # Create a temporary local collector for extracted contents
                temp_collector = LocalCollector(
                    root_path=str(tmp_path),
                    recursive=True,
                    patterns=self.patterns,
                    ignore_patterns=self.ignore_patterns,
                )
                
                async for skill in temp_collector.collect():
                    # Update skill ID to include archive reference
                    skill.skill_id = f"archive_{zip_path.stem}_{skill.skill_id}"
                    yield skill
                    
            except Exception as e:
                logger.error(f"Error processing ZIP archive {zip_path}: {e}")
    
    async def _collect_from_tar(self, tar_path: Path) -> AsyncIterator[SkillDocument]:
        """Collect skills from a TAR archive."""
        import tempfile
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            try:
                with tarfile.open(tar_path, 'r:*') as tar:
                    tar.extractall(tmp_path)
                
                temp_collector = LocalCollector(
                    root_path=str(tmp_path),
                    recursive=True,
                    patterns=self.patterns,
                    ignore_patterns=self.ignore_patterns,
                )
                
                async for skill in temp_collector.collect():
                    skill.skill_id = f"archive_{tar_path.stem}_{skill.skill_id}"
                    yield skill
                    
            except Exception as e:
                logger.error(f"Error processing TAR archive {tar_path}: {e}")