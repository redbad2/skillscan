"""
LLM配置管理器

提供LLM配置的动态调整能力，支持：
- 配置热更新（无需重启）
- 提供商切换
- 阈值动态调整
- 配置版本管理
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from threading import RLock
from copy import deepcopy

from loguru import logger


class ConfigVersion:
    """配置版本记录"""

    def __init__(
        self,
        version_id: str,
        config: Dict[str, Any],
        created_at: datetime,
        created_by: str = "system",
    ):
        self.version_id = version_id
        self.config = deepcopy(config)
        self.created_at = created_at
        self.created_by = created_by
        self.config_hash = self._compute_hash(config)

    @staticmethod
    def _compute_hash(config: Dict[str, Any]) -> str:
        """计算配置哈希"""
        config_str = json.dumps(config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "config_hash": self.config_hash,
        }


class LLMConfigManager:
    """
    LLM配置管理器

    支持动态调整LLM配置，提供配置版本管理功能。
    """

    _instance: Optional["LLMConfigManager"] = None
    _lock = RLock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._config: Dict[str, Any] = {}
        self._original_config: Dict[str, Any] = {}
        self._versions: List[ConfigVersion] = []
        self._version_counter = 0
        self._config_lock = RLock()
        self._change_callbacks: List[callable] = []

        logger.info("LLMConfigManager initialized")

    def initialize(self, config: Dict[str, Any]) -> None:
        """初始化配置"""
        with self._config_lock:
            self._config = deepcopy(config)
            self._original_config = deepcopy(config)

            version = ConfigVersion(
                version_id="v0",
                config=config,
                created_at=datetime.utcnow(),
                created_by="system",
            )
            self._versions.append(version)
            self._version_counter = 1

            logger.info("LLMConfigManager configuration loaded")

    def get_config(self) -> Dict[str, Any]:
        """获取当前配置"""
        with self._config_lock:
            return deepcopy(self._config)

    def get_provider_config(self, provider: str) -> Optional[Dict[str, Any]]:
        """获取指定提供商配置"""
        with self._config_lock:
            providers = self._config.get("providers", {})
            return deepcopy(providers.get(provider))

    def get_default_provider(self) -> str:
        """获取默认提供商"""
        with self._config_lock:
            return self._config.get("default_provider", "openai")

    def get_analysis_config(self) -> Dict[str, Any]:
        """获取分析配置"""
        with self._config_lock:
            return deepcopy(self._config.get("analysis", {}))

    def get_cost_control_config(self) -> Dict[str, Any]:
        """获取成本控制配置"""
        with self._config_lock:
            return deepcopy(self._config.get("cost_control", {}))

    def set_default_provider(self, provider: str, created_by: str = "api") -> bool:
        """
        切换默认LLM提供商

        Args:
            provider: 提供商名称 (openai, anthropic, azure_openai, local, volcengine, custom_openai, custom_anthropic)
            created_by: 操作者

        Returns:
            是否成功
        """
        valid_providers = [
            "openai",
            "anthropic",
            "azure_openai",
            "local",
            "volcengine",
            "custom_openai",
            "custom_anthropic",
        ]
        if provider not in valid_providers:
            logger.error(f"Invalid provider: {provider}")
            return False

        with self._config_lock:
            providers = self._config.get("providers", {})
            if provider not in providers:
                logger.error(f"Provider not configured: {provider}")
                return False

            old_provider = self._config.get("default_provider")
            self._config["default_provider"] = provider

            self._save_version(
                old_config={"default_provider": old_provider},
                new_config={"default_provider": provider},
                created_by=created_by,
            )

            logger.info(f"Default provider changed: {old_provider} -> {provider}")
            return True

    def update_provider(
        self, provider: str, config: Dict[str, Any], created_by: str = "api"
    ) -> bool:
        """
        更新提供商配置

        Args:
            provider: 提供商名称
            config: 新的配置
            created_by: 操作者

        Returns:
            是否成功
        """
        with self._config_lock:
            if "providers" not in self._config:
                self._config["providers"] = {}

            old_config = self._config["providers"].get(provider, {})
            self._config["providers"][provider] = {
                **old_config,
                **config,
            }

            self._save_version(
                old_config={provider: old_config},
                new_config={provider: config},
                created_by=created_by,
            )

            logger.info(f"Provider '{provider}' updated")
            return True

    def update_analysis_thresholds(
        self,
        thresholds: Dict[str, Any],
        created_by: str = "api",
    ) -> bool:
        """
        动态更新分析阈值

        Args:
            thresholds: 阈值配置
                - static_confidence_threshold: 静态分析置信度阈值
                - llm_confirm_threshold: LLM确认阈值
                - llm_override_threshold: LLM推翻阈值
                - timeout: 分析超时
            created_by: 操作者

        Returns:
            是否成功
        """
        valid_keys = {
            "static_confidence_threshold",
            "llm_confirm_threshold",
            "llm_override_threshold",
            "timeout",
            "max_retries",
            "enabled",
        }

        invalid_keys = set(thresholds.keys()) - valid_keys
        if invalid_keys:
            logger.warning(f"Invalid threshold keys: {invalid_keys}")

        with self._config_lock:
            if "analysis" not in self._config:
                self._config["analysis"] = {}

            old_thresholds = {
                k: self._config["analysis"].get(k)
                for k in valid_keys
                if k in self._config["analysis"]
            }

            for key, value in thresholds.items():
                if key in valid_keys:
                    if key == "enabled":
                        self._config["analysis"]["enabled"] = bool(value)
                    elif key in (
                        "static_confidence_threshold",
                        "llm_confirm_threshold",
                        "llm_override_threshold",
                    ):
                        self._config["analysis"][key] = float(value)
                        if not 0 <= self._config["analysis"][key] <= 1:
                            logger.warning(f"Threshold {key} should be between 0 and 1")
                            self._config["analysis"][key] = max(
                                0, min(1, self._config["analysis"][key])
                            )
                    elif key in ("timeout", "max_retries"):
                        self._config["analysis"][key] = int(value)

            new_thresholds = {
                k: self._config["analysis"].get(k) for k in valid_keys if k in thresholds
            }

            self._save_version(
                old_config={"analysis": old_thresholds},
                new_config={"analysis": new_thresholds},
                created_by=created_by,
            )

            logger.info(f"Analysis thresholds updated: {new_thresholds}")
            return True

    def update_cost_control(
        self,
        cost_config: Dict[str, Any],
        created_by: str = "api",
    ) -> bool:
        """
        更新成本控制配置

        Args:
            cost_config: 成本控制配置
                - monthly_budget: 月度预算
                - max_tokens_per_analysis: 每次分析最大token数
                - on_budget_exceeded: 预算超限行为 (block, warn, ignore)
            created_by: 操作者

        Returns:
            是否成功
        """
        valid_keys = {
            "monthly_budget",
            "max_tokens_per_analysis",
            "on_budget_exceeded",
            "enable_cost_tracking",
        }

        with self._config_lock:
            if "cost_control" not in self._config:
                self._config["cost_control"] = {}

            old_cost = {
                k: self._config["cost_control"].get(k)
                for k in valid_keys
                if k in self._config["cost_control"]
            }

            for key, value in cost_config.items():
                if key in valid_keys:
                    if key == "on_budget_exceeded":
                        if value not in ("block", "warn", "ignore"):
                            logger.warning(f"Invalid on_budget_exceeded value: {value}")
                            continue
                        self._config["cost_control"][key] = value
                    elif key in ("monthly_budget", "max_tokens_per_analysis"):
                        self._config["cost_control"][key] = float(value)
                    elif key == "enable_cost_tracking":
                        self._config["cost_control"][key] = bool(value)

            new_cost = {
                k: self._config["cost_control"].get(k) for k in valid_keys if k in cost_config
            }

            self._save_version(
                old_config={"cost_control": old_cost},
                new_config={"cost_control": new_cost},
                created_by=created_by,
            )

            logger.info(f"Cost control updated: {new_cost}")
            return True

    def update_prompts(
        self,
        prompts: Dict[str, Any],
        created_by: str = "api",
    ) -> bool:
        """
        更新提示词模板

        Args:
            prompts: 提示词配置
            created_by: 操作者

        Returns:
            是否成功
        """
        with self._config_lock:
            old_prompts = self._config.get("prompts", {})

            if "prompts" not in self._config:
                self._config["prompts"] = {}

            self._config["prompts"].update(prompts)

            self._save_version(
                old_config={"prompts": old_prompts},
                new_config={"prompts": prompts},
                created_by=created_by,
            )

            logger.info(f"Prompts updated")
            return True

    def reload_config(self, new_config: Dict[str, Any], created_by: str = "api") -> bool:
        """
        重新加载完整配置

        Args:
            new_config: 新配置
            created_by: 操作者

        Returns:
            是否成功
        """
        with self._config_lock:
            old_config = deepcopy(self._config)
            self._config = deepcopy(new_config)

            self._save_version(
                old_config=old_config,
                new_config=new_config,
                created_by=created_by,
            )

            self._notify_change()
            logger.info("Full configuration reloaded")
            return True

    def rollback_version(self, version_id: str) -> bool:
        """
        回滚到指定版本

        Args:
            version_id: 版本ID

        Returns:
            是否成功
        """
        version = self.get_version(version_id)
        if not version:
            logger.error(f"Version not found: {version_id}")
            return False

        with self._config_lock:
            old_config = deepcopy(self._config)
            self._config = deepcopy(version.config)

            self._save_version(
                old_config=old_config,
                new_config=version.config,
                created_by="rollback",
            )

            self._notify_change()
            logger.info(f"Rolled back to version: {version_id}")
            return True

    def get_version(self, version_id: str) -> Optional[ConfigVersion]:
        """获取指定版本"""
        for v in self._versions:
            if v.version_id == version_id:
                return v
        return None

    def list_versions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """列出配置版本历史"""
        versions = sorted(self._versions, key=lambda v: v.created_at, reverse=True)
        return [v.to_dict() for v in versions[:limit]]

    def diff_versions(self, version_id1: str, version_id2: str) -> Optional[Dict[str, Any]]:
        """
        比较两个版本的差异

        Args:
            version_id1: 第一个版本ID
            version_id2: 第二个版本ID

        Returns:
            差异信息
        """
        v1 = self.get_version(version_id1)
        v2 = self.get_version(version_id2)

        if not v1 or not v2:
            return None

        diff = self._compute_diff(v1.config, v2.config)
        return {
            "version1": version_id1,
            "version2": version_id2,
            "changes": diff,
        }

    def _compute_diff(
        self,
        old: Dict[str, Any],
        new: Dict[str, Any],
        path: str = "",
    ) -> List[Dict[str, Any]]:
        """递归计算配置差异"""
        changes = []

        all_keys = set(old.keys()) | set(new.keys())

        for key in all_keys:
            current_path = f"{path}.{key}" if path else key
            old_val = old.get(key)
            new_val = new.get(key)

            if key not in old:
                changes.append(
                    {
                        "path": current_path,
                        "type": "added",
                        "old_value": None,
                        "new_value": new_val,
                    }
                )
            elif key not in new:
                changes.append(
                    {
                        "path": current_path,
                        "type": "removed",
                        "old_value": old_val,
                        "new_value": None,
                    }
                )
            elif old_val != new_val:
                if isinstance(old_val, dict) and isinstance(new_val, dict):
                    changes.extend(self._compute_diff(old_val, new_val, current_path))
                else:
                    changes.append(
                        {
                            "path": current_path,
                            "type": "modified",
                            "old_value": old_val,
                            "new_value": new_val,
                        }
                    )

        return changes

    def _save_version(
        self,
        old_config: Dict[str, Any],
        new_config: Dict[str, Any],
        created_by: str,
    ) -> None:
        """保存配置版本"""
        self._version_counter += 1
        version_id = f"v{self._version_counter}"

        version = ConfigVersion(
            version_id=version_id,
            config=deepcopy(self._config),
            created_at=datetime.utcnow(),
            created_by=created_by,
        )
        self._versions.append(version)

        if len(self._versions) > 50:
            self._versions = self._versions[-50:]

        self._notify_change()

    def register_change_callback(self, callback: callable) -> None:
        """注册配置变更回调"""
        if callback not in self._change_callbacks:
            self._change_callbacks.append(callback)

    def unregister_change_callback(self, callback: callable) -> None:
        """注销配置变更回调"""
        if callback in self._change_callbacks:
            self._change_callbacks.remove(callback)

    def _notify_change(self) -> None:
        """通知配置变更"""
        for callback in self._change_callbacks:
            try:
                callback(self._config)
            except Exception as e:
                logger.error(f"Error in config change callback: {e}")

    def export_config(self) -> Dict[str, Any]:
        """导出当前配置"""
        with self._config_lock:
            return {
                "config": deepcopy(self._config),
                "version_history": self.list_versions(),
                "current_version": self._versions[-1].version_id if self._versions else None,
            }

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """获取速率限制状态"""
        with self._config_lock:
            provider = self._config.get("default_provider", "openai")
            provider_config = self._config.get("providers", {}).get(provider, {})

            return {
                "provider": provider,
                "timeout": provider_config.get("timeout", 60),
                "retry_count": provider_config.get("retry_count", 3),
                "retry_delay": provider_config.get("retry_delay", 2),
            }

    def reset_to_default(self, created_by: str = "api") -> bool:
        """重置为默认配置"""
        with self._config_lock:
            old_config = deepcopy(self._config)
            self._config = deepcopy(self._original_config)

            self._save_version(
                old_config=old_config,
                new_config=self._original_config,
                created_by=created_by,
            )

            self._notify_change()
            logger.info("Configuration reset to default")
            return True


llm_config_manager = LLMConfigManager()
