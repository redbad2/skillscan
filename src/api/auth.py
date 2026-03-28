"""
API Authentication Module

Provides API key authentication for the SkillScan API.
"""

import hashlib
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from src.config import get_settings

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


class APIKeyManager:
    """Manages API keys for authentication"""

    def __init__(self):
        self._keys: dict[str, dict] = {}

    def generate_key(self, name: str, permissions: Optional[list[str]] = None) -> str:
        """Generate a new API key"""
        api_key = f"sk_{secrets.token_urlsafe(32)}"
        key_hash = self._hash_key(api_key)

        self._keys[key_hash] = {
            "name": name,
            "permissions": permissions or [],
            "created_at": None,
        }
        return api_key

    def verify_key(self, api_key: str) -> Optional[dict]:
        """Verify an API key and return its metadata if valid"""
        if not api_key:
            return None

        key_hash = self._hash_key(api_key)
        return self._keys.get(key_hash)

    def revoke_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        key_hash = self._hash_key(api_key)
        if key_hash in self._keys:
            del self._keys[key_hash]
            return True
        return False

    def list_keys(self) -> list[dict]:
        """List all API keys (metadata only)"""
        return [{"name": v["name"], "permissions": v["permissions"]} for v in self._keys.values()]

    @staticmethod
    def _hash_key(api_key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def hash_key(api_key: str) -> str:
        """Public method to hash a key"""
        return APIKeyManager._hash_key(api_key)


api_key_manager = APIKeyManager()


async def verify_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER),
) -> Optional[dict]:
    """
    Dependency to verify API key from request header.

    Returns key metadata if valid, None if no key provided.
    Raises HTTPException if key is invalid.
    """
    settings = get_settings()

    if not settings.api.api_key:
        return None

    if not api_key:
        return None

    key_hash = APIKeyManager.hash_key(api_key)
    expected_hash = APIKeyManager.hash_key(settings.api.api_key)

    if secrets.compare_digest(key_hash, expected_hash):
        return {"authenticated": True, "method": "api_key"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


async def require_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER),
) -> dict:
    """
    Dependency that requires API key authentication.

    Raises HTTPException if no valid key is provided.
    """
    settings = get_settings()

    if not settings.api.api_key:
        return {"authenticated": False, "method": "none", "reason": "auth_disabled"}

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    key_hash = APIKeyManager.hash_key(api_key)
    expected_hash = APIKeyManager.hash_key(settings.api.api_key)

    if secrets.compare_digest(key_hash, expected_hash):
        return {"authenticated": True, "method": "api_key"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )
