from agents.decision_engine import DecisionEngine
from agents.model_router import clear_model_router_cache


class StubLLMClient:
    def __init__(self, text: str, raise_error: bool = False) -> None:
        self.text = text
        self.raise_error = raise_error
        self.calls: list[str] = []

    def complete(self, *, model, messages, temperature, max_tokens, timeout_seconds) -> str:
        self.calls.append(str(model))
        if self.raise_error:
            raise RuntimeError("llm_down")
        return self.text


def test_decision_engine_parses_structured_json_response() -> None:
    clear_model_router_cache()
    raw = """
    {
      "target_profile": {"os_guess":"linux","exposed_services":["http"],"attack_surface_summary":"web target"},
      "risk_hypotheses": [{"hypothesis":"x","severity":"high","confidence":0.9,"rationale":"e"}],
      "next_actions": [{"action":"a","objective":"o","required_tool":"nuclei","risk_level":"low"}],
      "evidence_interpretation": {"verified_signals":["s"],"uncertain_signals":[],"overall_decision":"risk_confirmed","confidence":0.88}
    }
    """
    client = StubLLMClient(raw)
    engine = DecisionEngine(
        client=client,
        prompts={},
        model="openai/gpt-4.1-mini",
        fallback_model="deepseek/deepseek-chat",
        temperature=0.1,
        max_tokens=1200,
        timeout_seconds=30,
        llm_enabled=True,
    )
    result = engine.decide(
        target="10.20.1.8",
        analysis={"allowed": True},
        scan={"findings": [{"type": "open_port", "severity": "medium", "confidence": 0.8, "evidence": "80/tcp"}]},
    )
    assert result["mode"] == "llm"
    assert result["model"] == "deepseek/deepseek-chat"
    assert result["evidence_interpretation"]["overall_decision"] == "risk_confirmed"
    assert len(result["risk_hypotheses"]) == 1
    assert result["llm_runtime"]["cache_hit"] is False
    assert result["llm_runtime"]["estimated_cost_usd"] >= 0.0
    assert client.calls


def test_decision_engine_falls_back_to_heuristic_on_client_error() -> None:
    clear_model_router_cache()
    engine = DecisionEngine(
        client=StubLLMClient("{}", raise_error=True),
        prompts={},
        model="openai/gpt-4.1-mini",
        fallback_model="deepseek/deepseek-chat",
        temperature=0.1,
        max_tokens=1200,
        timeout_seconds=30,
        llm_enabled=True,
    )
    result = engine.decide(
        target="10.20.1.8",
        analysis={"allowed": True, "target_profile": {"os_guess": "windows", "os_confidence": 0.82, "strategy_hint": "strategy_windows"}},
        scan={"findings": []},
    )
    assert result["mode"] == "heuristic_fallback"
    assert "error" in result
    assert result["target_profile"]["os_guess"] == "windows"
    assert result["summary"]["overall_decision"] in {"risk_confirmed", "no_confirmed_risk"}
    assert result["llm_runtime"]["attempted"] is True


def test_decision_engine_uses_cache_for_identical_requests() -> None:
    clear_model_router_cache()
    raw = """
    {
      "target_profile": {"os_guess":"linux","exposed_services":["http"],"attack_surface_summary":"web target"},
      "risk_hypotheses": [{"hypothesis":"x","severity":"high","confidence":0.9,"rationale":"e"}],
      "next_actions": [{"action":"a","objective":"o","required_tool":"nuclei","risk_level":"low"}],
      "evidence_interpretation": {"verified_signals":["s"],"uncertain_signals":[],"overall_decision":"risk_confirmed","confidence":0.88}
    }
    """
    client = StubLLMClient(raw)
    engine = DecisionEngine(
        client=client,
        prompts={},
        model="openai/gpt-4.1-mini",
        fallback_model="deepseek/deepseek-chat",
        temperature=0.1,
        max_tokens=1200,
        timeout_seconds=30,
        llm_enabled=True,
    )
    payload = {
        "target": "10.20.1.8",
        "analysis": {"allowed": True},
        "scan": {"findings": [{"type": "open_port", "severity": "medium", "confidence": 0.8, "evidence": "80/tcp"}]},
    }
    first = engine.decide(**payload)
    second = engine.decide(**payload)

    assert first["mode"] == "llm"
    assert second["mode"] == "llm"
    assert first["llm_runtime"]["cache_hit"] is False
    assert second["llm_runtime"]["cache_hit"] is True
    assert len(client.calls) == 1
