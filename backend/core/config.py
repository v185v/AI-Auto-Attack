from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


DEFAULTS: dict[str, Any] = {
    "app": {"name": "ai-attack", "env": "dev", "log_level": "INFO"},
    "api": {"host": "0.0.0.0", "port": 8000},
    "auth": {
        "enabled": True,
        "header_user": "X-Actor-Id",
        "header_role": "X-Role",
        "default_user": "system",
        "default_role": "executor",
        "enforce_headers": False,
        "approval_signing_key": "dev-approval-signing-key",
    },
    "security": {
        "scope_policy_path": "policies/scope_policy.yaml",
        "action_policy_path": "policies/action_policy.yaml",
        "approval_store_path": "workflow/approvals/approvals.jsonl",
        "approval_store": {
            "backend": "file",
            "file_path": "workflow/approvals/approvals.jsonl",
            "sqlite_path": "workflow/approvals/approvals.db",
            "postgres_dsn": "",
            "table": "approval_records",
        },
        "require_human_approval_for_high_risk": True,
        "redaction": {
            "enabled": True,
            "mask": "***REDACTED***",
            "sensitive_keys": [],
        },
    },
    "secrets": {
        "provider": "env",
        "env_prefix": "",
        "env_mapping": {
            "defectdojo_api_token": "DEFECTDOJO_API_TOKEN",
            "approval_signing_key": "APPROVAL_SIGNING_KEY",
        },
    },
    "audit": {
        "evidence_root": "evidence",
        "write_index": True,
        "retention": {
            "enabled": False,
            "evidence_days": 90,
            "reports_days": 180,
        },
    },
    "tools": {
        "command_timeout_seconds": 180,
        "nmap_bin": "nmap",
        "nuclei_bin": "nuclei",
        "zap_bin": "zap.sh",
    },
    "llm": {
        "enabled": False,
        "gateway": "litellm",
        "default_model": "openai/gpt-4.1-mini",
        "fallback_model": "deepseek/deepseek-chat",
        "temperature": 0.1,
        "max_tokens": 1200,
        "request_timeout_seconds": 45,
        "routing": {
            "enabled": True,
            "high_capability_model": "openai/gpt-4.1-mini",
            "low_cost_model": "deepseek/deepseek-chat",
            "fallback_model": "deepseek/deepseek-chat",
            "high_risk_severities": ["critical", "high"],
            "high_risk_finding_threshold": 3,
            "cache_enabled": True,
            "cache_ttl_seconds": 600,
            "cache_max_entries": 256,
        },
        "cost": {
            "max_per_task_usd": 1.0,
            "max_llm_latency_ms": 15000,
            "model_prices": {
                "openai/gpt-4.1-mini": {
                    "input_per_1k_tokens_usd": 0.0004,
                    "output_per_1k_tokens_usd": 0.0016,
                },
                "deepseek/deepseek-chat": {
                    "input_per_1k_tokens_usd": 0.00014,
                    "output_per_1k_tokens_usd": 0.00028,
                },
            },
        },
    },
    "reporting": {
        "output_dir": "reports/generated",
        "diff_output_dir": "reports/diff",
        "path_output_dir": "reports/path",
        "enable_pdf": False,
    },
    "observability": {
        "default_window_hours": 168,
        "error_budget": {
            "max_failure_rate": 0.2,
            "min_retry_success_rate": 0.6,
            "max_mttr_seconds": 1800,
        },
        "kpi": {
            "output_dir": "observability/kpi",
            "weekly_window_hours": 168,
            "monthly_window_hours": 720,
        },
    },
    "integrations": {
        "defectdojo": {
            "enabled": False,
            "base_url": "",
            "api_token": "",
            "engagement_id": 0,
            "scan_type": "Generic Findings Import",
            "minimum_severity": "Low",
            "verify_ssl": True,
            "timeout_seconds": 30,
            "default_tags": ["ai-attack", "auto-pentest"],
        },
    },
    "workflow": {
        "engine": "temporal",
        "task_timeout_seconds": 1800,
        "max_retries": 2,
        "resource_quota": {
            "enabled": True,
            "max_parallel_tasks": 2,
            "max_targets_per_run": 20,
        },
        "state_store": {
            "directory": "workflow/state",
        },
        "strategies": {
            "linux_path": "workflows/strategy_linux.yaml",
            "windows_path": "workflows/strategy_windows.yaml",
        },
        "temporal": {
            "enabled": False,
            "address": "localhost:7233",
            "namespace": "default",
            "task_queue": "ai-attack-task-queue",
            "workflow_id_prefix": "ai-attack-poc",
            "execution_timeout_seconds": 3600,
            "run_timeout_seconds": 3600,
            "activity_start_to_close_timeout_seconds": 1200,
            "activity_schedule_to_close_timeout_seconds": 1800,
            "retry": {
                "max_attempts": 3,
                "initial_interval_seconds": 2,
                "max_interval_seconds": 30,
                "backoff_coefficient": 2.0,
            },
        },
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@lru_cache(maxsize=1)
def get_settings() -> dict[str, Any]:
    settings_path = Path(os.getenv("APP_SETTINGS_PATH", "settings.yaml"))
    loaded: dict[str, Any] = {}

    if settings_path.exists():
        with settings_path.open("r", encoding="utf-8") as file_obj:
            parsed = yaml.safe_load(file_obj) or {}
            if isinstance(parsed, dict):
                loaded = parsed

    return _deep_merge(DEFAULTS, loaded)
