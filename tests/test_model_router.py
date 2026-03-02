from concurrent.futures import ThreadPoolExecutor

from agents.model_router import (
    ModelPrice,
    ModelRouter,
    ModelRouterSettings,
    RoutingContext,
    extract_max_severity,
)


def _settings() -> ModelRouterSettings:
    return ModelRouterSettings(
        enabled=True,
        high_capability_model="openai/gpt-4.1-mini",
        low_cost_model="deepseek/deepseek-chat",
        fallback_model="deepseek/deepseek-chat",
        high_risk_severities={"critical", "high"},
        high_risk_finding_threshold=3,
        cache_enabled=True,
        cache_ttl_seconds=600,
        cache_max_entries=64,
        max_per_task_usd=1.0,
        max_llm_latency_ms=15000,
        prices={
            "openai/gpt-4.1-mini": ModelPrice(input_per_1k_tokens_usd=0.0004, output_per_1k_tokens_usd=0.0016),
            "deepseek/deepseek-chat": ModelPrice(input_per_1k_tokens_usd=0.00014, output_per_1k_tokens_usd=0.00028),
        },
    )


def test_model_router_routes_high_risk_to_high_capability_model() -> None:
    router = ModelRouter(_settings())
    decision = router.route(RoutingContext(target="10.0.0.1", finding_count=1, max_severity="high"))
    assert decision.model == "openai/gpt-4.1-mini"
    assert decision.tier == "high_capability"
    assert decision.reason == "high_risk_context"


def test_model_router_routes_low_risk_to_low_cost_model() -> None:
    router = ModelRouter(_settings())
    decision = router.route(RoutingContext(target="10.0.0.1", finding_count=1, max_severity="low"))
    assert decision.model == "deepseek/deepseek-chat"
    assert decision.tier == "low_cost"
    assert decision.reason == "low_risk_context"


def test_model_router_cache_and_budget() -> None:
    router = ModelRouter(_settings())
    key = router.build_cache_key({"target": "10.20.1.8", "finding_count": 1})
    router.cache.set(key, {"a": 1})
    cached = router.cache.get(key)
    assert cached == {"a": 1}

    budget = router.evaluate_budget(estimated_cost_usd=2.0, latency_ms=20000)
    assert budget["breached"] is True
    assert len(budget["breaches"]) == 2


def test_extract_max_severity_prefers_highest_weight() -> None:
    findings = [
        {"severity": "low"},
        {"severity": "medium"},
        {"severity": "critical"},
    ]
    assert extract_max_severity(findings) == "critical"


def test_decision_cache_thread_safe_under_parallel_access() -> None:
    router = ModelRouter(_settings())
    keys = [router.build_cache_key({"target": f"10.20.1.{idx}"}) for idx in range(16)]

    def worker(index: int) -> bool:
        key = keys[index % len(keys)]
        router.cache.set(key, {"index": index})
        value = router.cache.get(key)
        return value is None or "index" in value

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(500)))

    assert all(results)
