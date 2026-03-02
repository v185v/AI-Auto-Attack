"""Workflow package with lazy exports.

Keep package import side-effect free to avoid circular imports between:
workflow graph <-> temporal worker <-> state store.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "StateStoreSettings",
    "WorkflowStateStore",
    "TemporalSettings",
    "TemporalWorkflowClient",
    "TemporalWorkerRunner",
    "get_state_store_settings",
    "get_temporal_settings",
    "get_temporal_workflow_client",
    "get_workflow_state_store",
]

_STATE_EXPORTS = {
    "StateStoreSettings",
    "WorkflowStateStore",
    "get_state_store_settings",
    "get_workflow_state_store",
}

_TEMPORAL_EXPORTS = {
    "TemporalSettings",
    "TemporalWorkflowClient",
    "TemporalWorkerRunner",
    "get_temporal_settings",
    "get_temporal_workflow_client",
}


def __getattr__(name: str) -> Any:
    if name in _STATE_EXPORTS:
        module = import_module("backend.workflow.state_store")
        return getattr(module, name)
    if name in _TEMPORAL_EXPORTS:
        module = import_module("backend.workflow.temporal_worker")
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
