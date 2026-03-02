from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import ipaddress
from urllib.parse import urlparse

from backend.core.config import get_settings
from backend.security.policy_loader import load_policy


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None
    normalized_target: str | None = None


class ScopeGuard:
    def __init__(self, policy: dict):
        self.policy = policy
        self.default_decision = str(policy.get("default_decision", "deny")).lower()

        authorized = policy.get("authorized_targets", {})
        self.hosts = {str(item).lower() for item in authorized.get("hosts", [])}
        self.domains = {str(item).lower() for item in authorized.get("domains", [])}
        self.api_base_urls = tuple(
            str(item).rstrip("/").lower() for item in authorized.get("api_base_urls", [])
        )

        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in authorized.get("cidr", []):
            cidr_str = str(cidr).strip()
            if not cidr_str:
                continue
            try:
                self.networks.append(ipaddress.ip_network(cidr_str, strict=False))
            except ValueError:
                continue

    def authorize(self, target: str) -> ScopeDecision:
        raw_target = target.strip()
        if not raw_target:
            return ScopeDecision(allowed=False, reason="invalid_target")

        parsed = urlparse(raw_target)
        has_scheme = bool(parsed.scheme and parsed.netloc)
        normalized_url = raw_target.rstrip("/").lower() if has_scheme else None

        if normalized_url and self.api_base_urls:
            for base in self.api_base_urls:
                if normalized_url == base or normalized_url.startswith(f"{base}/"):
                    return ScopeDecision(
                        allowed=True,
                        reason="api_base_url_allowed",
                        matched_rule=f"api_base_url:{base}",
                        normalized_target=normalized_url,
                    )

        host = self._extract_host(raw_target)
        if not host:
            return ScopeDecision(allowed=False, reason="invalid_target")

        host_lower = host.lower()
        if host_lower in self.hosts:
            return ScopeDecision(
                allowed=True,
                reason="host_allowed",
                matched_rule=f"host:{host_lower}",
                normalized_target=host_lower,
            )

        ip_match = self._match_ip(host_lower)
        if ip_match is not None:
            return ip_match

        for domain in self.domains:
            if host_lower == domain or host_lower.endswith(f".{domain}"):
                return ScopeDecision(
                    allowed=True,
                    reason="domain_allowed",
                    matched_rule=f"domain:{domain}",
                    normalized_target=host_lower,
                )

        if self.default_decision == "allow":
            return ScopeDecision(
                allowed=True,
                reason="default_allow",
                matched_rule="default_decision:allow",
                normalized_target=host_lower,
            )
        return ScopeDecision(
            allowed=False,
            reason="target_out_of_scope",
            normalized_target=host_lower,
        )

    def _match_ip(self, host: str) -> ScopeDecision | None:
        try:
            ip_value = ipaddress.ip_address(host)
        except ValueError:
            return None

        for network in self.networks:
            if ip_value in network:
                return ScopeDecision(
                    allowed=True,
                    reason="cidr_allowed",
                    matched_rule=f"cidr:{network}",
                    normalized_target=str(ip_value),
                )
        if self.default_decision == "allow":
            return ScopeDecision(
                allowed=True,
                reason="default_allow",
                matched_rule="default_decision:allow",
                normalized_target=str(ip_value),
            )
        return ScopeDecision(
            allowed=False,
            reason="ip_out_of_scope",
            normalized_target=str(ip_value),
        )

    @staticmethod
    def _extract_host(target: str) -> str | None:
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return parsed.hostname

        pseudo = urlparse(f"//{target}")
        if pseudo.hostname:
            return pseudo.hostname

        cleaned = target.split("/", maxsplit=1)[0].split("?", maxsplit=1)[0].strip()
        return cleaned or None


@lru_cache(maxsize=1)
def get_scope_guard() -> ScopeGuard:
    settings = get_settings()
    path = str(settings.get("security", {}).get("scope_policy_path", "policies/scope_policy.yaml"))
    policy = load_policy(path)
    return ScopeGuard(policy)


def clear_scope_guard_cache() -> None:
    get_scope_guard.cache_clear()
