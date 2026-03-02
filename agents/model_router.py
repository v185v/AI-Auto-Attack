from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from threading import Lock
import time
from typing import Any

from backend.core.config import get_settings


_SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass(frozen=True)
class ModelPrice:
    input_per_1k_tokens_usd: float
    output_per_1k_tokens_usd: float


@dataclass(frozen=True)
class RoutingContext:
    target: str
    finding_count: int
    max_severity: str


@dataclass(frozen=True)
class ModelRoutingDecision:
    model: str
    fallback_model: str
    tier: str
    reason: str


@dataclass(frozen=True)
class ModelRouterSettings:
    enabled: bool
    high_capability_model: str
    low_cost_model: str
    fallback_model: str
    high_risk_severities: set[str]
    high_risk_finding_threshold: int
    cache_enabled: bool
    cache_ttl_seconds: int
    cache_max_entries: int
    max_per_task_usd: float
    max_llm_latency_ms: int
    prices: dict[str, ModelPrice]


class DecisionCache:
    def __init__(self, *, enabled: bool, ttl_seconds: int, max_entries: int) -> None:
        self.enabled = enabled
        self.ttl_seconds = max(ttl_seconds, 1)
        self.max_entries = max(max_entries, 1)
        self._items: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        with self._lock:
            now = time.time()
            self._evict_expired_locked(now=now)
            entry = self._items.get(key)
            if entry is None:
                return None
            expires_at, payload = entry
            if now > expires_at:
                self._items.pop(key, None)
                return None
            # move to end (LRU)
            self._items.pop(key, None)
            self._items[key] = (expires_at, dict(payload))
            return dict(payload)

    def set(self, key: str, value: dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._lock:
            now = time.time()
            self._evict_expired_locked(now=now)
            expires_at = now + self.ttl_seconds
            if key in self._items:
                self._items.pop(key, None)
            self._items[key] = (expires_at, dict(value))
            while len(self._items) > self.max_entries:
                oldest_key = next(iter(self._items))
                self._items.pop(oldest_key, None)

    def _evict_expired_locked(self, *, now: float) -> None:
        expired = [key for key, (expires_at, _) in self._items.items() if now > expires_at]
        for key in expired:
            self._items.pop(key, None)


class ModelRouter:
    def __init__(self, settings: ModelRouterSettings) -> None:
        self.settings = settings
        self.cache = DecisionCache(
            enabled=settings.cache_enabled,
            ttl_seconds=settings.cache_ttl_seconds,
            max_entries=settings.cache_max_entries,
        )

    def route(self, context: RoutingContext) -> ModelRoutingDecision:
        if not self.settings.enabled:
            return ModelRoutingDecision(
                model=self.settings.high_capability_model,
                fallback_model=self.settings.fallback_model,
                tier="default",
                reason="routing_disabled",
            )

        high_risk = self._is_high_risk(context.max_severity) or context.finding_count >= self.settings.high_risk_finding_threshold
        if high_risk:
            return ModelRoutingDecision(
                model=self.settings.high_capability_model,
                fallback_model=self._resolve_fallback(self.settings.high_capability_model),
                tier="high_capability",
                reason="high_risk_context",
            )
        return ModelRoutingDecision(
            model=self.settings.low_cost_model,
            fallback_model=self._resolve_fallback(self.settings.low_cost_model),
            tier="low_cost",
            reason="low_risk_context",
        )

    def estimate_tokens(self, text: str) -> int:
        # Approximation used for provider-agnostic, low-overhead cost telemetry.
        return max(1, (len(text) + 3) // 4)

    def estimate_cost_usd(self, *, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        price = self.settings.prices.get(model)
        if price is None:
            return 0.0
        prompt_cost = (max(prompt_tokens, 0) / 1000.0) * price.input_per_1k_tokens_usd
        completion_cost = (max(completion_tokens, 0) / 1000.0) * price.output_per_1k_tokens_usd
        return round(prompt_cost + completion_cost, 8)

    def evaluate_budget(self, *, estimated_cost_usd: float, latency_ms: int) -> dict[str, Any]:
        breaches = []
        if estimated_cost_usd > self.settings.max_per_task_usd:
            breaches.append(
                {
                    "metric": "max_per_task_usd",
                    "actual": round(float(estimated_cost_usd), 8),
                    "target": self.settings.max_per_task_usd,
                }
            )
        if latency_ms > self.settings.max_llm_latency_ms:
            breaches.append(
                {
                    "metric": "max_llm_latency_ms",
                    "actual": int(latency_ms),
                    "target": self.settings.max_llm_latency_ms,
                }
            )
        return {
            "status": "breached" if breaches else "healthy",
            "breached": bool(breaches),
            "breaches": breaches,
            "targets": {
                "max_per_task_usd": self.settings.max_per_task_usd,
                "max_llm_latency_ms": self.settings.max_llm_latency_ms,
            },
        }

    @staticmethod
    def build_cache_key(payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _is_high_risk(self, severity: str) -> bool:
        return severity.strip().lower() in self.settings.high_risk_severities

    def _resolve_fallback(self, primary_model: str) -> str:
        fallback = self.settings.fallback_model
        if fallback and fallback != primary_model:
            return fallback
        if self.settings.high_capability_model != primary_model:
            return self.settings.high_capability_model
        return primary_model


def extract_max_severity(findings: list[dict[str, Any]]) -> str:
    best = "info"
    best_weight = _SEVERITY_WEIGHT.get(best, 1)
    for item in findings:
        raw = str(item.get("severity", "info")).strip().lower()
        weight = _SEVERITY_WEIGHT.get(raw, 0)
        if weight > best_weight:
            best = raw
            best_weight = weight
    return best


@lru_cache(maxsize=1)
def get_model_router_settings() -> ModelRouterSettings:
    settings = get_settings()
    llm = settings.get("llm", {})
    routing = llm.get("routing", {})
    cost = llm.get("cost", {})
    prices_raw = cost.get("model_prices", {})
    prices: dict[str, ModelPrice] = {}
    if isinstance(prices_raw, dict):
        for model, value in prices_raw.items():
            if not isinstance(value, dict):
                continue
            prices[str(model)] = ModelPrice(
                input_per_1k_tokens_usd=float(value.get("input_per_1k_tokens_usd", 0.0)),
                output_per_1k_tokens_usd=float(value.get("output_per_1k_tokens_usd", 0.0)),
            )
    default_model = str(llm.get("default_model", "openai/gpt-4.1-mini"))
    fallback_model = str(llm.get("fallback_model", "deepseek/deepseek-chat"))
    high_risk_severities = routing.get("high_risk_severities", ["critical", "high"])
    normalized_levels = {
        str(level).strip().lower()
        for level in (high_risk_severities if isinstance(high_risk_severities, list) else [])
        if str(level).strip()
    } or {"critical", "high"}
    return ModelRouterSettings(
        enabled=bool(routing.get("enabled", True)),
        high_capability_model=str(routing.get("high_capability_model", default_model)),
        low_cost_model=str(routing.get("low_cost_model", fallback_model or default_model)),
        fallback_model=str(routing.get("fallback_model", fallback_model or default_model)),
        high_risk_severities=normalized_levels,
        high_risk_finding_threshold=int(routing.get("high_risk_finding_threshold", 3)),
        cache_enabled=bool(routing.get("cache_enabled", True)),
        cache_ttl_seconds=int(routing.get("cache_ttl_seconds", 600)),
        cache_max_entries=int(routing.get("cache_max_entries", 256)),
        max_per_task_usd=float(cost.get("max_per_task_usd", 1.0)),
        max_llm_latency_ms=int(cost.get("max_llm_latency_ms", 15000)),
        prices=prices,
    )


@lru_cache(maxsize=1)
def get_model_router() -> ModelRouter:
    return ModelRouter(get_model_router_settings())


def clear_model_router_cache() -> None:
    get_model_router_settings.cache_clear()
    get_model_router.cache_clear()
