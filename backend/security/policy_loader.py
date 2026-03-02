from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@lru_cache(maxsize=16)
def load_policy(path: str) -> dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.exists():
        return {}

    with policy_path.open("r", encoding="utf-8") as file_obj:
        data = yaml.safe_load(file_obj) or {}
        if isinstance(data, dict):
            return data
    return {}


def clear_policy_cache() -> None:
    load_policy.cache_clear()

