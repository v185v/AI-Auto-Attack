from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from fastapi import HTTPException, Request

from backend.core.config import get_settings
from backend.security.secrets_manager import get_secret_manager


Role = Literal["admin", "auditor", "executor"]


@dataclass(frozen=True)
class Actor:
    actor_id: str
    role: Role


@dataclass(frozen=True)
class RBACSettings:
    enabled: bool
    header_user: str
    header_role: str
    default_user: str
    default_role: Role
    enforce_headers: bool
    approval_signing_key: str


PERMISSIONS: dict[str, set[str]] = {
    "actions:validate": {"executor", "admin"},
    "approvals:read": {"executor", "auditor", "admin"},
    "approvals:decide": {"admin"},
    "retention:prune": {"admin"},
}


def get_actor(request: Request) -> Actor:
    settings = get_rbac_settings()
    if not settings.enabled:
        return Actor(actor_id=settings.default_user, role=settings.default_role)

    raw_user = request.headers.get(settings.header_user, "").strip()
    raw_role = request.headers.get(settings.header_role, "").strip().lower()

    if settings.enforce_headers and (not raw_user or not raw_role):
        raise HTTPException(
            status_code=401,
            detail={"reason": "auth_headers_required"},
        )

    actor_id = raw_user or settings.default_user
    role = _normalize_role(raw_role or settings.default_role)
    return Actor(actor_id=actor_id, role=role)


def require_permission(actor: Actor, permission: str) -> None:
    allowed_roles = PERMISSIONS.get(permission, set())
    if actor.role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "permission_denied",
                "permission": permission,
                "role": actor.role,
            },
        )


def _normalize_role(value: str) -> Role:
    role = str(value).strip().lower()
    mapping = {
        "admin": "admin",
        "auditor": "auditor",
        "executor": "executor",
        "operator": "executor",
    }
    normalized = mapping.get(role)
    if normalized is None:
        raise HTTPException(
            status_code=401,
            detail={"reason": "invalid_role", "role": role},
        )
    return normalized  # type: ignore[return-value]


@lru_cache(maxsize=1)
def get_rbac_settings() -> RBACSettings:
    settings = get_settings()
    auth = settings.get("auth", {})
    secret_manager = get_secret_manager()
    configured_signing_key = str(auth.get("approval_signing_key", "dev-approval-signing-key"))
    signing_key = secret_manager.get("approval_signing_key", configured_signing_key or "dev-approval-signing-key")
    return RBACSettings(
        enabled=bool(auth.get("enabled", True)),
        header_user=str(auth.get("header_user", "X-Actor-Id")),
        header_role=str(auth.get("header_role", "X-Role")),
        default_user=str(auth.get("default_user", "system")),
        default_role=_normalize_role(str(auth.get("default_role", "executor"))),
        enforce_headers=bool(auth.get("enforce_headers", False)),
        approval_signing_key=signing_key,
    )


def clear_rbac_caches() -> None:
    get_rbac_settings.cache_clear()
