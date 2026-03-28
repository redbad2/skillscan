"""
Storage module for SkillScan.

Provides MongoDB storage for skills, vulnerabilities, and configurations.
"""

from .mongodb import MongoDBStorage
from .repository import SkillRepository, VulnerabilityRepository, ConfigRepository

__all__ = [
    "MongoDBStorage",
    "SkillRepository",
    "VulnerabilityRepository",
    "ConfigRepository",
]