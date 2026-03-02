from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
import shlex

from backend.core.config import get_settings
from backend.security.approval_store import ApprovalStore, get_approval_store
from backend.security.policy_loader import load_policy


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    risk_level: str
    command_token: str
    approval_id: str | None = None
    approval_status: str | None = None


class ActionGate:
    def __init__(self, policy: dict, approval_store: ApprovalStore) -> None:
        self.policy = policy
        self.approval_store = approval_store

        allowlist = policy.get("command_allowlist", {})
        self.low_risk = {str(item).lower() for item in allowlist.get("low_risk", [])}
        self.medium_risk = {str(item).lower() for item in allowlist.get("medium_risk", [])}
        self.high_risk = {str(item).lower() for item in allowlist.get("high_risk", [])}
        gates = policy.get("gates", {})
        self.require_approval_for_high_risk = bool(gates.get("require_approval_for_high_risk", True))

    def evaluate(
        self,
        target: str,
        command: str,
        requested_by: str,
        approval_id: str | None = None,
    ) -> ActionDecision:
        token = _normalize_command_token(command)
        if not token:
            return ActionDecision(
                allowed=False,
                reason="invalid_command",
                risk_level="blocked",
                command_token="",
            )

        risk_level = self._classify(token)
        if risk_level == "blocked":
            return ActionDecision(
                allowed=False,
                reason="command_not_allowlisted",
                risk_level=risk_level,
                command_token=token,
            )

        if risk_level == "high" and self.require_approval_for_high_risk:
            return self._evaluate_high_risk(
                target=target,
                command=command,
                token=token,
                requested_by=requested_by,
                approval_id=approval_id,
            )

        return ActionDecision(
            allowed=True,
            reason="action_allowed",
            risk_level=risk_level,
            command_token=token,
        )

    def _evaluate_high_risk(
        self,
        target: str,
        command: str,
        token: str,
        requested_by: str,
        approval_id: str | None,
    ) -> ActionDecision:
        if not approval_id:
            record = self.approval_store.create(
                target=target,
                command=command,
                risk_level="high",
                requested_by=requested_by,
            )
            return ActionDecision(
                allowed=False,
                reason="approval_required",
                risk_level="high",
                command_token=token,
                approval_id=record.approval_id,
                approval_status=record.status,
            )

        record = self.approval_store.get(approval_id)
        if record is None:
            return ActionDecision(
                allowed=False,
                reason="approval_not_found",
                risk_level="high",
                command_token=token,
                approval_id=approval_id,
            )

        if record.target != target or record.command != command:
            return ActionDecision(
                allowed=False,
                reason="approval_mismatch",
                risk_level="high",
                command_token=token,
                approval_id=approval_id,
                approval_status=record.status,
            )

        if record.status == "pending":
            return ActionDecision(
                allowed=False,
                reason="approval_pending",
                risk_level="high",
                command_token=token,
                approval_id=approval_id,
                approval_status=record.status,
            )

        if record.status == "rejected":
            return ActionDecision(
                allowed=False,
                reason="approval_rejected",
                risk_level="high",
                command_token=token,
                approval_id=approval_id,
                approval_status=record.status,
            )

        return ActionDecision(
            allowed=True,
            reason="approval_granted",
            risk_level="high",
            command_token=token,
            approval_id=approval_id,
            approval_status=record.status,
        )

    def _classify(self, command_token: str) -> str:
        if command_token in self.low_risk:
            return "low"
        if command_token in self.medium_risk:
            return "medium"
        if command_token in self.high_risk:
            return "high"
        return "blocked"


def _normalize_command_token(command: str) -> str:
    value = command.strip()
    if not value:
        return ""
    try:
        parts = shlex.split(value, posix=False)
    except ValueError:
        parts = value.split()
    if not parts:
        return ""
    first = parts[0].strip("'\"")
    token = os.path.basename(first).lower()
    return token


@lru_cache(maxsize=1)
def get_action_gate() -> ActionGate:
    settings = get_settings()
    path = str(settings.get("security", {}).get("action_policy_path", "policies/action_policy.yaml"))
    policy = load_policy(path)
    return ActionGate(policy=policy, approval_store=get_approval_store())


def clear_action_gate_cache() -> None:
    get_action_gate.cache_clear()
