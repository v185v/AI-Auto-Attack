# Cost and Performance Control (P5-3)

## Objective

Provide an enterprise baseline for LLM cost and performance governance:
- route model selection by risk context,
- deduplicate repeated model decisions with cache,
- expose cost and latency metrics for continuous monitoring.

## Model Routing

Implemented in:
- `agents/model_router.py`

Routing signals:
- finding count,
- maximum finding severity.

Routing behavior:
- high-risk context -> `high_capability_model`
- low-risk context -> `low_cost_model`
- route includes fallback model and reason for traceability.

Configuration (`settings.yaml -> llm.routing`):
- `enabled`
- `high_capability_model`
- `low_cost_model`
- `fallback_model`
- `high_risk_severities`
- `high_risk_finding_threshold`

## Decision Cache (Dedup)

Implemented in:
- `agents/model_router.py` (`DecisionCache`)
- integrated into `agents/decision_engine.py`

Behavior:
- SHA-256 cache key from stable decision context payload.
- TTL + max-entry bounded cache.
- repeated requests reuse prior normalized decision output.

Configuration (`settings.yaml -> llm.routing`):
- `cache_enabled`
- `cache_ttl_seconds`
- `cache_max_entries`

## Runtime Cost Telemetry

Decision engine writes runtime metadata in `llm_decision.llm_runtime`:
- `cache_hit`
- `attempted`, `attempts`
- `latency_ms`
- `prompt_tokens_est`
- `completion_tokens_est`
- `total_tokens_est`
- `estimated_cost_usd`
- `route` (tier/reason/primary/fallback)
- `budget` (healthy/breached)

Token/cost notes:
- token count is provider-agnostic approximation for low-overhead telemetry,
- cost is estimated from configurable per-model prices.

Configuration (`settings.yaml -> llm.cost`):
- `max_per_task_usd`
- `max_llm_latency_ms`
- `model_prices.<model>.input_per_1k_tokens_usd`
- `model_prices.<model>.output_per_1k_tokens_usd`

## Monitoring API

Endpoint:
- `GET /metrics/workflows/cost?window_hours=168`

Output includes:
- task and LLM call counts,
- cache hit ratio,
- total estimated cost,
- average cost per task,
- average LLM latency,
- per-model cost/latency split,
- budget status and breaches.
