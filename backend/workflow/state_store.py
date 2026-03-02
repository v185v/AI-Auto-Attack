from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
import json
from pathlib import Path
from threading import Lock
from typing import Any

from backend.core.config import get_settings


@dataclass(frozen=True)
class StateStoreSettings:
    directory: str


class WorkflowStateStore:
    def __init__(self, settings: StateStoreSettings) -> None:
        self.settings = settings
        self.base_dir = Path(settings.directory)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def save_snapshot(
        self,
        *,
        task_id: str,
        trace_id: str,
        step: str,
        status: str,
        state: dict[str, Any],
        node_input: dict[str, Any] | None = None,
        node_output: dict[str, Any] | None = None,
        reason: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        task_dir = self.base_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        snapshots_path = task_dir / "snapshots.jsonl"
        meta_path = task_dir / "meta.json"

        with self._lock:
            version = self._next_version(snapshots_path)
            state_for_snapshot = dict(state)
            state_for_snapshot["state_version"] = version
            snapshot = {
                "version": version,
                "timestamp": timestamp or _utc_now(),
                "task_id": task_id,
                "trace_id": trace_id,
                "step": step,
                "status": status,
                "reason": reason or "",
                "node_input": node_input or {},
                "node_output": node_output or {},
                "state": state_for_snapshot,
            }
            with snapshots_path.open("a", encoding="utf-8") as file_obj:
                file_obj.write(json.dumps(snapshot, ensure_ascii=True) + "\n")

            meta = {
                "task_id": task_id,
                "trace_id": trace_id,
                "latest_version": version,
                "latest_step": step,
                "latest_status": status,
                "updated_at": snapshot["timestamp"],
            }
            meta_path.write_text(json.dumps(meta, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return snapshot

    def list_snapshots(self, task_id: str) -> list[dict[str, Any]]:
        path = self.base_dir / task_id / "snapshots.jsonl"
        return self._read_jsonl(path)

    def get_latest_snapshot(self, task_id: str) -> dict[str, Any] | None:
        snapshots = self.list_snapshots(task_id)
        if not snapshots:
            return None
        return snapshots[-1]

    def get_snapshot(self, task_id: str, version: int) -> dict[str, Any] | None:
        for item in self.list_snapshots(task_id):
            if int(item.get("version", -1)) == version:
                return item
        return None

    @staticmethod
    def _next_version(path: Path) -> int:
        if not path.exists():
            return 1
        latest = 0
        with path.open("r", encoding="utf-8") as file_obj:
            for line in file_obj:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    latest = max(latest, int(item.get("version", 0)))
        return latest + 1

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        items: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as file_obj:
            for line in file_obj:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    items.append(item)
        items.sort(key=lambda x: int(x.get("version", 0)))
        return items


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def get_state_store_settings() -> StateStoreSettings:
    settings = get_settings()
    workflow = settings.get("workflow", {})
    state_store = workflow.get("state_store", {})
    directory = str(state_store.get("directory", "workflow/state"))
    return StateStoreSettings(directory=directory)


@lru_cache(maxsize=1)
def get_workflow_state_store() -> WorkflowStateStore:
    return WorkflowStateStore(get_state_store_settings())


def clear_state_store_caches() -> None:
    get_state_store_settings.cache_clear()
    get_workflow_state_store.cache_clear()
