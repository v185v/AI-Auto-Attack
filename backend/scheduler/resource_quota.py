from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from backend.core.config import get_settings


@dataclass(frozen=True)
class ResourceQuotaSettings:
    enabled: bool
    max_parallel_tasks: int
    max_targets_per_run: int


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    reason: str
    requested_parallelism: int
    applied_parallelism: int
    target_count: int
    max_parallel_tasks: int
    max_targets_per_run: int
    clamped: bool

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "requested_parallelism": self.requested_parallelism,
            "applied_parallelism": self.applied_parallelism,
            "target_count": self.target_count,
            "max_parallel_tasks": self.max_parallel_tasks,
            "max_targets_per_run": self.max_targets_per_run,
            "clamped": self.clamped,
        }


class ResourceQuotaManager:
    def __init__(self, settings: ResourceQuotaSettings) -> None:
        self.settings = settings

    def check_run(self, *, target_count: int, requested_parallelism: int) -> QuotaDecision:
        target_count = max(int(target_count), 0)
        requested = max(int(requested_parallelism), 1)
        max_parallel = max(int(self.settings.max_parallel_tasks), 1)
        max_targets = max(int(self.settings.max_targets_per_run), 1)

        if target_count < 1:
            return QuotaDecision(
                allowed=False,
                reason="empty_plan",
                requested_parallelism=requested,
                applied_parallelism=0,
                target_count=target_count,
                max_parallel_tasks=max_parallel,
                max_targets_per_run=max_targets,
                clamped=False,
            )

        if not self.settings.enabled:
            return QuotaDecision(
                allowed=True,
                reason="quota_disabled",
                requested_parallelism=requested,
                applied_parallelism=requested,
                target_count=target_count,
                max_parallel_tasks=max_parallel,
                max_targets_per_run=max_targets,
                clamped=False,
            )

        if target_count > max_targets:
            return QuotaDecision(
                allowed=False,
                reason="targets_over_quota",
                requested_parallelism=requested,
                applied_parallelism=0,
                target_count=target_count,
                max_parallel_tasks=max_parallel,
                max_targets_per_run=max_targets,
                clamped=False,
            )

        applied_parallelism = min(requested, max_parallel)
        clamped = requested > applied_parallelism
        return QuotaDecision(
            allowed=True,
            reason="parallelism_clamped" if clamped else "quota_ok",
            requested_parallelism=requested,
            applied_parallelism=applied_parallelism,
            target_count=target_count,
            max_parallel_tasks=max_parallel,
            max_targets_per_run=max_targets,
            clamped=clamped,
        )


@lru_cache(maxsize=1)
def get_resource_quota_settings() -> ResourceQuotaSettings:
    settings = get_settings()
    workflow = settings.get("workflow", {})
    quota = workflow.get("resource_quota", {})
    return ResourceQuotaSettings(
        enabled=bool(quota.get("enabled", True)),
        max_parallel_tasks=int(quota.get("max_parallel_tasks", 2)),
        max_targets_per_run=int(quota.get("max_targets_per_run", 20)),
    )


@lru_cache(maxsize=1)
def get_resource_quota_manager() -> ResourceQuotaManager:
    return ResourceQuotaManager(get_resource_quota_settings())


def clear_resource_quota_cache() -> None:
    get_resource_quota_settings.cache_clear()
    get_resource_quota_manager.cache_clear()
