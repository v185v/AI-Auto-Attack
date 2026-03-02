from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
import shutil
from typing import Any

from backend.core.config import get_settings


@dataclass(frozen=True)
class RetentionSettings:
    enabled: bool
    evidence_days: int
    reports_days: int
    evidence_root: str
    report_output_dir: str
    report_diff_output_dir: str


class RetentionService:
    def __init__(self, settings: RetentionSettings) -> None:
        self.settings = settings

    def prune(self, *, dry_run: bool = True) -> dict[str, Any]:
        if not self.settings.enabled:
            return {
                "enabled": False,
                "dry_run": dry_run,
                "status": "skipped",
                "reason": "retention_disabled",
            }
        now = datetime.now(UTC)
        evidence = _prune_date_dirs(
            root=Path(self.settings.evidence_root),
            retention_days=self.settings.evidence_days,
            now=now,
            dry_run=dry_run,
        )
        reports = _prune_date_dirs(
            root=Path(self.settings.report_output_dir),
            retention_days=self.settings.reports_days,
            now=now,
            dry_run=dry_run,
        )
        diff_reports = _prune_date_dirs(
            root=Path(self.settings.report_diff_output_dir),
            retention_days=self.settings.reports_days,
            now=now,
            dry_run=dry_run,
        )
        return {
            "enabled": True,
            "dry_run": dry_run,
            "status": "completed",
            "evidence": evidence,
            "reports": reports,
            "diff_reports": diff_reports,
        }


def _prune_date_dirs(
    *,
    root: Path,
    retention_days: int,
    now: datetime,
    dry_run: bool,
) -> dict[str, Any]:
    cutoff = now.date() - timedelta(days=max(retention_days, 1))
    result = {
        "root": root.as_posix(),
        "retention_days": retention_days,
        "cutoff_date": cutoff.isoformat(),
        "pruned_count": 0,
        "candidates": [],
    }
    if not root.exists():
        result["status"] = "root_not_found"
        return result

    for child in root.iterdir():
        if not child.is_dir():
            continue
        date_value = _parse_date_dir(child.name)
        if date_value is None or date_value >= cutoff:
            continue
        result["candidates"].append(child.as_posix())
        if not dry_run:
            shutil.rmtree(child, ignore_errors=True)
        result["pruned_count"] += 1
    result["status"] = "ok"
    return result


def _parse_date_dir(name: str) -> datetime.date | None:
    try:
        return datetime.strptime(name, "%Y-%m-%d").date()
    except ValueError:
        return None


@lru_cache(maxsize=1)
def get_retention_settings() -> RetentionSettings:
    settings = get_settings()
    audit = settings.get("audit", {})
    retention = audit.get("retention", {})
    reporting = settings.get("reporting", {})
    return RetentionSettings(
        enabled=bool(retention.get("enabled", False)),
        evidence_days=int(retention.get("evidence_days", 90)),
        reports_days=int(retention.get("reports_days", 180)),
        evidence_root=str(audit.get("evidence_root", "evidence")),
        report_output_dir=str(reporting.get("output_dir", "reports/generated")),
        report_diff_output_dir=str(reporting.get("diff_output_dir", "reports/diff")),
    )


@lru_cache(maxsize=1)
def get_retention_service() -> RetentionService:
    return RetentionService(get_retention_settings())


def clear_retention_caches() -> None:
    get_retention_settings.cache_clear()
    get_retention_service.cache_clear()
