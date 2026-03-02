from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from time import perf_counter
from typing import Any, Protocol

from agents.model_router import (
    ModelRouter,
    RoutingContext,
    extract_max_severity,
    get_model_router,
)
from backend.core.config import get_settings


class LLMClient(Protocol):
    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        timeout_seconds: int,
    ) -> str:
        ...


class LiteLLMClient:
    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        timeout_seconds: int,
    ) -> str:
        from litellm import completion

        response = completion(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout_seconds,
        )
        choice = response.choices[0]
        content = getattr(choice.message, "content", None)
        if isinstance(content, str):
            return content
        return str(content or "")


class HeuristicDecisionClient:
    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        timeout_seconds: int,
    ) -> str:
        return "{}"


class DecisionEngine:
    def __init__(
        self,
        *,
        client: LLMClient,
        prompts: dict[str, str],
        model: str,
        fallback_model: str,
        temperature: float,
        max_tokens: int,
        timeout_seconds: int,
        llm_enabled: bool,
        model_router: ModelRouter | None = None,
    ) -> None:
        self.client = client
        self.prompts = prompts
        self.model = model
        self.fallback_model = fallback_model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.llm_enabled = llm_enabled
        self.model_router = model_router or get_model_router()

    def decide(
        self,
        *,
        target: str,
        analysis: dict[str, Any],
        scan: dict[str, Any],
    ) -> dict[str, Any]:
        findings = list(scan.get("findings", []))
        if not self.llm_enabled:
            heuristic = self._heuristic_decision(target=target, analysis=analysis, findings=findings)
            heuristic["mode"] = "heuristic"
            heuristic["model"] = self.model
            heuristic["llm_runtime"] = {
                "cache_hit": False,
                "attempted": False,
                "latency_ms": 0,
                "prompt_tokens_est": 0,
                "completion_tokens_est": 0,
                "total_tokens_est": 0,
                "estimated_cost_usd": 0.0,
                "budget": self.model_router.evaluate_budget(estimated_cost_usd=0.0, latency_ms=0),
            }
            return heuristic

        max_severity = extract_max_severity(findings)
        route = self.model_router.route(
            RoutingContext(
                target=target,
                finding_count=len(findings),
                max_severity=max_severity,
            )
        )
        prompt = self._compose_prompt(target=target, analysis=analysis, findings=findings)
        messages = [
            {"role": "system", "content": "You are an authorized security testing decision engine. Output JSON only."},
            {"role": "user", "content": prompt},
        ]
        cache_key = self.model_router.build_cache_key(
            {
                "target": target,
                "analysis": analysis,
                "findings": findings,
                "model": route.model,
            }
        )
        cached = self.model_router.cache.get(cache_key)
        if cached is not None:
            runtime = dict(cached.get("llm_runtime", {}))
            runtime["cache_hit"] = True
            runtime["latency_ms"] = 0
            cached["llm_runtime"] = runtime
            return cached

        prompt_tokens = self.model_router.estimate_tokens(_messages_text(messages))
        used_model = route.model
        attempts = 0
        last_error = ""
        raw = ""
        latency_ms = 0
        try:
            attempts += 1
            started = perf_counter()
            raw = self.client.complete(
                model=route.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout_seconds=self.timeout_seconds,
            )
            latency_ms = int((perf_counter() - started) * 1000)
        except Exception as exc:
            last_error = str(exc)
            if route.fallback_model and route.fallback_model != route.model:
                try:
                    attempts += 1
                    used_model = route.fallback_model
                    started = perf_counter()
                    raw = self.client.complete(
                        model=route.fallback_model,
                        messages=messages,
                        temperature=self.temperature,
                        max_tokens=self.max_tokens,
                        timeout_seconds=self.timeout_seconds,
                    )
                    latency_ms = int((perf_counter() - started) * 1000)
                except Exception as fallback_exc:
                    fallback = self._heuristic_decision(target=target, analysis=analysis, findings=findings)
                    fallback["mode"] = "heuristic_fallback"
                    fallback["model"] = self.fallback_model
                    fallback["error"] = str(fallback_exc)
                    fallback["llm_runtime"] = {
                        "cache_hit": False,
                        "attempted": True,
                        "attempts": attempts,
                        "latency_ms": 0,
                        "prompt_tokens_est": prompt_tokens,
                        "completion_tokens_est": 0,
                        "total_tokens_est": prompt_tokens,
                        "estimated_cost_usd": 0.0,
                        "route": {
                            "tier": route.tier,
                            "reason": route.reason,
                            "primary_model": route.model,
                            "fallback_model": route.fallback_model,
                        },
                        "budget": self.model_router.evaluate_budget(estimated_cost_usd=0.0, latency_ms=0),
                    }
                    return fallback
            else:
                fallback = self._heuristic_decision(target=target, analysis=analysis, findings=findings)
                fallback["mode"] = "heuristic_fallback"
                fallback["model"] = self.fallback_model
                fallback["error"] = last_error
                fallback["llm_runtime"] = {
                    "cache_hit": False,
                    "attempted": True,
                    "attempts": attempts,
                    "latency_ms": 0,
                    "prompt_tokens_est": prompt_tokens,
                    "completion_tokens_est": 0,
                    "total_tokens_est": prompt_tokens,
                    "estimated_cost_usd": 0.0,
                    "route": {
                        "tier": route.tier,
                        "reason": route.reason,
                        "primary_model": route.model,
                        "fallback_model": route.fallback_model,
                    },
                    "budget": self.model_router.evaluate_budget(estimated_cost_usd=0.0, latency_ms=0),
                }
                return fallback
        try:
            parsed = _parse_json_response(raw)
            normalized = self._normalize_llm_response(parsed, target=target, analysis=analysis, findings=findings)
            normalized["mode"] = "llm"
            normalized["model"] = used_model
            completion_tokens = self.model_router.estimate_tokens(raw)
            total_tokens = prompt_tokens + completion_tokens
            estimated_cost = self.model_router.estimate_cost_usd(
                model=used_model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
            normalized["llm_runtime"] = {
                "cache_hit": False,
                "attempted": True,
                "attempts": attempts,
                "latency_ms": latency_ms,
                "prompt_tokens_est": prompt_tokens,
                "completion_tokens_est": completion_tokens,
                "total_tokens_est": total_tokens,
                "estimated_cost_usd": estimated_cost,
                "route": {
                    "tier": route.tier,
                    "reason": route.reason,
                    "primary_model": route.model,
                    "fallback_model": route.fallback_model,
                },
                "budget": self.model_router.evaluate_budget(
                    estimated_cost_usd=estimated_cost,
                    latency_ms=latency_ms,
                ),
            }
            self.model_router.cache.set(cache_key, normalized)
            return normalized
        except Exception as exc:
            fallback = self._heuristic_decision(target=target, analysis=analysis, findings=findings)
            fallback["mode"] = "heuristic_fallback"
            fallback["model"] = self.fallback_model
            fallback["error"] = str(exc)
            fallback["llm_runtime"] = {
                "cache_hit": False,
                "attempted": True,
                "attempts": attempts,
                "latency_ms": latency_ms,
                "prompt_tokens_est": prompt_tokens,
                "completion_tokens_est": 0,
                "total_tokens_est": prompt_tokens,
                "estimated_cost_usd": 0.0,
                "route": {
                    "tier": route.tier,
                    "reason": route.reason,
                    "primary_model": route.model,
                    "fallback_model": route.fallback_model,
                },
                "budget": self.model_router.evaluate_budget(estimated_cost_usd=0.0, latency_ms=latency_ms),
            }
            return fallback

    def _compose_prompt(self, *, target: str, analysis: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        payload = {
            "target": target,
            "analysis": analysis,
            "findings": findings,
        }
        sections = [
            ("target_profile", self.prompts.get("target_profile", "")),
            ("risk_hypothesis", self.prompts.get("risk_hypothesis", "")),
            ("next_action", self.prompts.get("next_action", "")),
            ("evidence_interpretation", self.prompts.get("evidence_interpretation", "")),
        ]
        instructions = "\n\n".join([f"[{name}]\n{text}" for name, text in sections if text])
        return (
            f"{instructions}\n\n"
            "Return ONE JSON object with keys: target_profile, risk_hypotheses, next_actions, evidence_interpretation.\n"
            f"Context JSON:\n{json.dumps(payload, ensure_ascii=True)}"
        )

    def _normalize_llm_response(
        self,
        parsed: dict[str, Any],
        *,
        target: str,
        analysis: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        base = self._heuristic_decision(target=target, analysis=analysis, findings=findings)
        target_profile = parsed.get("target_profile", {})
        risk_hypotheses = parsed.get("risk_hypotheses", [])
        next_actions = parsed.get("next_actions", [])
        evidence_interpretation = parsed.get("evidence_interpretation", {})

        if isinstance(target_profile, dict):
            base["target_profile"].update(target_profile)
        if isinstance(risk_hypotheses, list):
            base["risk_hypotheses"] = risk_hypotheses
        if isinstance(next_actions, list):
            base["next_actions"] = next_actions
        if isinstance(evidence_interpretation, dict):
            base["evidence_interpretation"].update(evidence_interpretation)
        return base

    def _heuristic_decision(
        self,
        *,
        target: str,
        analysis: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        profiled = analysis.get("target_profile", {})
        profile_from_analysis = profiled if isinstance(profiled, dict) else {}
        severities = [str(item.get("severity", "unknown")).lower() for item in findings]
        high_like = [s for s in severities if s in {"critical", "high"}]
        medium_like = [s for s in severities if s == "medium"]
        confidence = 0.8 if high_like else (0.65 if medium_like else 0.4)
        overall = "risk_confirmed" if high_like or medium_like else "no_confirmed_risk"
        profiled_services = profile_from_analysis.get("exposed_services", [])
        services = _extract_services(findings)
        if isinstance(profiled_services, list):
            for item in profiled_services:
                if isinstance(item, str) and item and item not in services:
                    services.append(item)
        target_profile = {
            "os_guess": str(profile_from_analysis.get("os_guess", "unknown")),
            "os_confidence": float(profile_from_analysis.get("os_confidence", 0.0)),
            "strategy_hint": str(profile_from_analysis.get("strategy_hint", "strategy_generic")),
            "exposed_services": sorted(set(services)),
            "attack_surface_summary": f"findings={len(findings)} on target {target}",
        }
        risk_hypotheses = []
        for item in findings[:5]:
            risk_hypotheses.append(
                {
                    "hypothesis": f"Potential risk from {item.get('type', 'unknown')}",
                    "severity": str(item.get("severity", "medium")).lower(),
                    "confidence": float(item.get("confidence", 0.6)),
                    "rationale": str(item.get("evidence", "tool evidence")),
                }
            )
        if not risk_hypotheses:
            risk_hypotheses.append(
                {
                    "hypothesis": "No strong exploitable signal found yet",
                    "severity": "info",
                    "confidence": 0.4,
                    "rationale": "Current scan did not provide high-confidence findings",
                }
            )

        next_actions = [
            {
                "action": "expand_service_validation",
                "objective": "confirm exposed service risk with targeted checks",
                "required_tool": "nmap",
                "risk_level": "low",
            },
            {
                "action": "run_web_template_validation",
                "objective": "validate web-layer vulnerabilities",
                "required_tool": "nuclei",
                "risk_level": "low",
            },
        ]
        if high_like:
            next_actions.insert(
                0,
                {
                    "action": "prioritize_high_severity_verification",
                    "objective": "reproduce highest-risk findings with evidence",
                    "required_tool": "zaproxy",
                    "risk_level": "medium",
                },
            )

        evidence_interpretation = {
            "verified_signals": [str(item.get("evidence", "")) for item in findings[:3]],
            "uncertain_signals": [] if findings else ["no actionable evidence from current scan"],
            "overall_decision": overall,
            "confidence": confidence,
        }
        return {
            "target_profile": target_profile,
            "risk_hypotheses": risk_hypotheses,
            "next_actions": next_actions,
            "evidence_interpretation": evidence_interpretation,
            "summary": {
                "target": target,
                "finding_count": len(findings),
                "overall_decision": overall,
                "analysis_reason": analysis.get("reason", ""),
            },
        }


def _extract_services(findings: list[dict[str, Any]]) -> list[str]:
    services = set()
    for item in findings:
        details = item.get("details", {})
        if isinstance(details, dict):
            service = details.get("service")
            if isinstance(service, str) and service:
                services.add(service)
    return sorted(services)


def _parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", maxsplit=1)[1]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    if text.startswith("{") and text.endswith("}"):
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        parsed = json.loads(text[start : end + 1])
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("invalid_json_response")


def _messages_text(messages: list[dict[str, str]]) -> str:
    return "\n".join(str(item.get("content", "")) for item in messages)


def load_prompt_templates(prompts_dir: str | Path = "agents/prompts") -> dict[str, str]:
    base = Path(prompts_dir)
    files = {
        "target_profile": "target_profile.md",
        "risk_hypothesis": "risk_hypothesis.md",
        "next_action": "next_action.md",
        "evidence_interpretation": "evidence_interpretation.md",
    }
    prompts: dict[str, str] = {}
    for key, file_name in files.items():
        path = base / file_name
        if path.exists():
            prompts[key] = path.read_text(encoding="utf-8")
        else:
            prompts[key] = ""
    return prompts


@lru_cache(maxsize=1)
def get_decision_engine() -> DecisionEngine:
    settings = get_settings()
    llm = settings.get("llm", {})
    enabled = bool(llm.get("enabled", False))
    model = str(llm.get("default_model", "openai/gpt-4.1-mini"))
    fallback_model = str(llm.get("fallback_model", "deepseek/deepseek-chat"))
    temperature = float(llm.get("temperature", 0.1))
    max_tokens = int(llm.get("max_tokens", 1200))
    timeout_seconds = int(llm.get("request_timeout_seconds", 45))
    prompts = load_prompt_templates()

    client: LLMClient
    if enabled:
        client = LiteLLMClient()
    else:
        client = HeuristicDecisionClient()

    return DecisionEngine(
        client=client,
        prompts=prompts,
        model=model,
        fallback_model=fallback_model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout_seconds=timeout_seconds,
        llm_enabled=enabled,
        model_router=get_model_router(),
    )


def clear_decision_engine_cache() -> None:
    get_decision_engine.cache_clear()
