"""Security policy enforcement components."""

from backend.security.action_gate import ActionGate, ActionDecision, get_action_gate
from backend.security.approval_store import ApprovalRecord, ApprovalStore, get_approval_store
from backend.security.redaction import RedactionSettings, get_redaction_settings, redact_payload, redact_text
from backend.security.secrets_manager import SecretManager, get_secret_manager
from backend.security.scope_guard import ScopeDecision, ScopeGuard, get_scope_guard

__all__ = [
    "ActionGate",
    "ActionDecision",
    "ApprovalRecord",
    "ApprovalStore",
    "RedactionSettings",
    "SecretManager",
    "ScopeDecision",
    "ScopeGuard",
    "get_action_gate",
    "get_approval_store",
    "get_redaction_settings",
    "get_secret_manager",
    "get_scope_guard",
    "redact_payload",
    "redact_text",
]
