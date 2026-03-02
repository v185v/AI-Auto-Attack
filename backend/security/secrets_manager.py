from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os

from backend.core.config import get_settings


@dataclass(frozen=True)
class SecretManagerSettings:
    provider: str
    env_prefix: str
    env_mapping: dict[str, str]


class SecretManager:
    def __init__(self, settings: SecretManagerSettings) -> None:
        self.settings = settings

    def get(self, logical_key: str, default: str = "") -> str:
        provider = self.settings.provider.strip().lower()
        if provider != "env":
            return default
        mapping_key = logical_key.strip().lower()
        env_name = self.settings.env_mapping.get(mapping_key, mapping_key.upper())
        full_key = f"{self.settings.env_prefix}{env_name}" if self.settings.env_prefix else env_name
        return str(os.getenv(full_key, default))


@lru_cache(maxsize=1)
def get_secret_manager_settings() -> SecretManagerSettings:
    settings = get_settings()
    section = settings.get("secrets", {})
    mapping = section.get("env_mapping", {})
    env_mapping: dict[str, str] = {}
    if isinstance(mapping, dict):
        for key, value in mapping.items():
            key_str = str(key).strip().lower()
            value_str = str(value).strip()
            if key_str and value_str:
                env_mapping[key_str] = value_str
    return SecretManagerSettings(
        provider=str(section.get("provider", "env")),
        env_prefix=str(section.get("env_prefix", "")),
        env_mapping=env_mapping,
    )


@lru_cache(maxsize=1)
def get_secret_manager() -> SecretManager:
    return SecretManager(get_secret_manager_settings())


def clear_secret_manager_cache() -> None:
    get_secret_manager_settings.cache_clear()
    get_secret_manager.cache_clear()
