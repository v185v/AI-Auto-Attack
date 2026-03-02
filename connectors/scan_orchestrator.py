from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
from typing import Any

from backend.core.config import get_settings
from backend.security.action_gate import ActionGate, get_action_gate
from backend.security.policy_loader import load_policy
from connectors.base import ToolConnector
from connectors.models import ConnectorResult
from connectors.nmap_connector import NmapConnector
from connectors.nuclei_connector import NucleiConnector
from connectors.zap_connector import ZapConnector


WEB_PORTS = {80, 443, 8080, 8443}


@dataclass(frozen=True)
class BranchStrategy:
    key: str
    name: str
    match_os: str
    default_tools: list[str]
    web_tools: list[str]
    description: str


class ScanOrchestrator:
    def __init__(
        self,
        connectors: list[ToolConnector],
        action_gate: ActionGate,
        strategies: dict[str, BranchStrategy] | None = None,
    ) -> None:
        self.connectors = connectors
        self.action_gate = action_gate
        self.strategies = strategies or _default_branch_strategies()

    def execute(
        self,
        *,
        target: str,
        requested_by: str,
        strategy_hint: str | None = None,
        target_profile: dict[str, Any] | None = None,
        force_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        profile = target_profile or {}
        selected_strategy = self._select_strategy(
            strategy_hint=(strategy_hint or "").strip(),
            target_profile=profile,
        )
        enabled_tools = self._resolve_enabled_tools(
            strategy=selected_strategy,
            target=target,
            target_profile=profile,
            force_tools=force_tools or [],
        )
        enabled_set = set(enabled_tools)

        tool_results: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        executed_tools = 0
        blocked_tools = 0
        failed_tools = 0
        skipped_tools = 0

        for connector in self.connectors:
            if connector.tool_name not in enabled_set:
                skipped_tools += 1
                continue
            prepared = connector.prepare(target)
            command_string = " ".join(prepared.command)
            gate_decision = self.action_gate.evaluate(
                target=target,
                command=command_string,
                requested_by=requested_by,
            )
            if not gate_decision.allowed:
                blocked_tools += 1
                blocked = ConnectorResult(
                    tool=prepared.tool,
                    target=prepared.target,
                    status="blocked",
                    command=prepared.command,
                    return_code=0,
                    duration_ms=0,
                    timed_out=False,
                    parsed={},
                    findings=[],
                    validation={"valid": False, "reason": gate_decision.reason},
                    error=gate_decision.reason,
                    gate={
                        "reason": gate_decision.reason,
                        "risk_level": gate_decision.risk_level,
                        "approval_id": gate_decision.approval_id,
                        "approval_status": gate_decision.approval_status,
                    },
                )
                tool_results.append(blocked.to_dict())
                continue

            result = connector.execute_prepared(prepared)
            executed_tools += 1
            if result.status != "success":
                failed_tools += 1
            findings.extend(result.findings)
            tool_results.append(result.to_dict())

        if executed_tools == 0:
            status = "failed"
            failure_reason = "no_tools_executed"
        elif failed_tools == executed_tools:
            status = "failed"
            failure_reason = "all_tools_failed"
        else:
            status = "completed"
            failure_reason = ""

        return {
            "status": status,
            "failure_reason": failure_reason,
            "target": target,
            "strategy": {
                "key": selected_strategy.key,
                "name": selected_strategy.name,
                "match_os": selected_strategy.match_os,
                "enabled_tools": enabled_tools,
            },
            "tool_results": tool_results,
            "executed_tools": executed_tools,
            "blocked_tools": blocked_tools,
            "failed_tools": failed_tools,
            "skipped_tools": skipped_tools,
            "findings": findings,
            "finding_count": len(findings),
        }

    def _select_strategy(
        self,
        *,
        strategy_hint: str,
        target_profile: dict[str, Any],
    ) -> BranchStrategy:
        if strategy_hint and strategy_hint in self.strategies:
            return self.strategies[strategy_hint]
        os_guess = str(target_profile.get("os_guess", "")).strip().lower()
        if os_guess == "windows" and "strategy_windows" in self.strategies:
            return self.strategies["strategy_windows"]
        if os_guess == "linux" and "strategy_linux" in self.strategies:
            return self.strategies["strategy_linux"]
        return self.strategies.get("strategy_generic", _default_branch_strategies()["strategy_generic"])

    def _resolve_enabled_tools(
        self,
        *,
        strategy: BranchStrategy,
        target: str,
        target_profile: dict[str, Any],
        force_tools: list[str],
    ) -> list[str]:
        ordered = [item.tool_name for item in self.connectors]
        enabled = list(strategy.default_tools or ordered)
        if _should_enable_web_checks(target=target, target_profile=target_profile):
            for tool in strategy.web_tools:
                if tool not in enabled:
                    enabled.append(tool)
        if force_tools:
            force_set = {str(item).strip() for item in force_tools if str(item).strip()}
            enabled = [tool for tool in enabled if tool in force_set]
        filtered = [tool for tool in ordered if tool in enabled]
        if force_tools:
            return filtered
        return filtered or ordered


@lru_cache(maxsize=1)
def get_scan_orchestrator() -> ScanOrchestrator:
    settings = get_settings()
    tools = settings.get("tools", {})
    timeout = int(tools.get("command_timeout_seconds", 180))
    zap_default = "zap.bat" if os.name == "nt" else "zap.sh"
    zap_binary = str(tools.get("zap_bin", zap_default))
    if os.name == "nt" and zap_binary == "zap.sh":
        zap_binary = "zap.bat"

    connectors: list[ToolConnector] = [
        NmapConnector(binary=str(tools.get("nmap_bin", "nmap")), timeout_seconds=timeout),
        NucleiConnector(binary=str(tools.get("nuclei_bin", "nuclei")), timeout_seconds=timeout),
        ZapConnector(binary=zap_binary, timeout_seconds=timeout),
    ]
    workflow = settings.get("workflow", {})
    strategy_settings = workflow.get("strategies", {})
    strategies = _default_branch_strategies()
    linux_path = str(strategy_settings.get("linux_path", "workflows/strategy_linux.yaml"))
    windows_path = str(strategy_settings.get("windows_path", "workflows/strategy_windows.yaml"))
    strategies["strategy_linux"] = _load_branch_strategy(
        path=linux_path,
        fallback=strategies["strategy_linux"],
    )
    strategies["strategy_windows"] = _load_branch_strategy(
        path=windows_path,
        fallback=strategies["strategy_windows"],
    )
    return ScanOrchestrator(
        connectors=connectors,
        action_gate=get_action_gate(),
        strategies=strategies,
    )


def clear_scan_orchestrator_cache() -> None:
    get_scan_orchestrator.cache_clear()


def _default_branch_strategies() -> dict[str, BranchStrategy]:
    return {
        "strategy_generic": BranchStrategy(
            key="strategy_generic",
            name="generic",
            match_os="unknown",
            default_tools=["nmap", "nuclei", "zaproxy"],
            web_tools=[],
            description="Default scan path for unknown target OS.",
        ),
        "strategy_linux": BranchStrategy(
            key="strategy_linux",
            name="linux",
            match_os="linux",
            default_tools=["nmap"],
            web_tools=["nuclei", "zaproxy"],
            description="Linux-first branch: service and middleware focused checks.",
        ),
        "strategy_windows": BranchStrategy(
            key="strategy_windows",
            name="windows",
            match_os="windows",
            default_tools=["nmap"],
            web_tools=["nuclei", "zaproxy"],
            description="Windows-first branch: SMB/RDP/WinRM controlled validation.",
        ),
    }


def _load_branch_strategy(path: str, fallback: BranchStrategy) -> BranchStrategy:
    policy = load_policy(path)
    if not policy:
        return fallback
    tools = policy.get("tools", {}) if isinstance(policy.get("tools"), dict) else {}
    default_tools = tools.get("default", fallback.default_tools)
    web_tools = tools.get("web_checks", fallback.web_tools)
    return BranchStrategy(
        key=str(policy.get("key", fallback.key)),
        name=str(policy.get("name", fallback.name)),
        match_os=str(policy.get("match_os", fallback.match_os)),
        default_tools=_as_str_list(default_tools, fallback.default_tools),
        web_tools=_as_str_list(web_tools, fallback.web_tools),
        description=str(policy.get("description", fallback.description)),
    )


def _as_str_list(value: Any, default: list[str]) -> list[str]:
    if not isinstance(value, list):
        return list(default)
    items = [str(item).strip() for item in value if str(item).strip()]
    return items or list(default)


def _should_enable_web_checks(*, target: str, target_profile: dict[str, Any]) -> bool:
    lowered = target.strip().lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return True
    target_type = str(target_profile.get("target_type", "")).lower()
    if target_type == "url":
        return True
    open_ports = target_profile.get("open_ports", [])
    if isinstance(open_ports, list):
        for port in open_ports:
            if isinstance(port, int) and port in WEB_PORTS:
                return True
            if isinstance(port, str) and port.isdigit() and int(port) in WEB_PORTS:
                return True
    return False
