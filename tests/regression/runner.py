from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Callable
import argparse
import json

import yaml

from agents.workflow_graph import run_poc_workflow


@dataclass(frozen=True)
class BenchmarkExpected:
    status: str
    min_finding_count: int
    min_verified_findings: int
    allow_failure_reasons: tuple[str, ...]
    max_duration_seconds: float | None


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    name: str
    description: str
    workflow: str
    target: str
    requested_by: str
    expected: BenchmarkExpected
    metadata: dict[str, Any]


@dataclass(frozen=True)
class RegressionPolicy:
    max_coverage_drop: float
    max_reproducibility_drop: float
    max_stability_drop: float


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    workflow: str
    target: str
    status: str
    finding_count: int
    verified_findings: int
    failure_reason: str
    duration_seconds: float
    passed: bool
    checks: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "workflow": self.workflow,
            "target": self.target,
            "status": self.status,
            "finding_count": self.finding_count,
            "verified_findings": self.verified_findings,
            "failure_reason": self.failure_reason,
            "duration_seconds": round(self.duration_seconds, 4),
            "passed": self.passed,
            "checks": dict(self.checks),
        }


BenchmarkExecutor = Callable[[BenchmarkCase], dict[str, Any]]


def load_benchmarks(benchmark_dir: str | Path) -> list[BenchmarkCase]:
    directory = Path(benchmark_dir)
    if not directory.exists():
        raise ValueError(f"benchmark_dir_not_found:{directory.as_posix()}")

    files = [
        item
        for item in sorted(directory.rglob("*.y*ml"))
        if item.is_file() and item.name.lower() not in {"policy.yaml", "policy.yml"}
    ]
    cases: list[BenchmarkCase] = []
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        case_id = str(data.get("id", path.stem)).strip()
        workflow = str(data.get("workflow", "poc_single_target")).strip()
        target = str(data.get("target", "")).strip()
        if not case_id or not target:
            continue
        expected_raw = data.get("expected", {})
        if not isinstance(expected_raw, dict):
            expected_raw = {}
        allow = expected_raw.get("allow_failure_reasons", [])
        allow_failure_reasons = tuple(str(item).strip() for item in allow if str(item).strip()) if isinstance(allow, list) else ()
        max_duration_seconds = expected_raw.get("max_duration_seconds")
        expected = BenchmarkExpected(
            status=str(expected_raw.get("status", "completed")).strip().lower(),
            min_finding_count=int(expected_raw.get("min_finding_count", 0)),
            min_verified_findings=int(expected_raw.get("min_verified_findings", 0)),
            allow_failure_reasons=allow_failure_reasons,
            max_duration_seconds=float(max_duration_seconds) if max_duration_seconds is not None else None,
        )
        case = BenchmarkCase(
            case_id=case_id,
            name=str(data.get("name", case_id)),
            description=str(data.get("description", "")),
            workflow=workflow,
            target=target,
            requested_by=str(data.get("requested_by", "regression-runner")),
            expected=expected,
            metadata={"path": path.as_posix(), "tags": data.get("tags", [])},
        )
        cases.append(case)
    if not cases:
        raise ValueError("benchmark_cases_not_found")
    return cases


def load_regression_policy(policy_path: str | Path | None = None) -> RegressionPolicy:
    defaults = RegressionPolicy(
        max_coverage_drop=0.05,
        max_reproducibility_drop=0.05,
        max_stability_drop=0.05,
    )
    if policy_path is None:
        return defaults
    path = Path(policy_path)
    if not path.exists():
        return defaults
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return defaults
    return RegressionPolicy(
        max_coverage_drop=float(raw.get("max_coverage_drop", defaults.max_coverage_drop)),
        max_reproducibility_drop=float(raw.get("max_reproducibility_drop", defaults.max_reproducibility_drop)),
        max_stability_drop=float(raw.get("max_stability_drop", defaults.max_stability_drop)),
    )


def run_regression_suite(
    *,
    benchmark_dir: str | Path,
    output_dir: str | Path,
    baseline_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    write_baseline: bool = False,
    executor: BenchmarkExecutor | None = None,
) -> dict[str, Any]:
    cases = load_benchmarks(benchmark_dir)
    policy = load_regression_policy(policy_path)
    run_case_executor = executor or _default_executor
    results = [run_case(case=case, executor=run_case_executor) for case in cases]
    metrics = summarize_case_results(results)
    baseline = load_baseline_metrics(baseline_path)
    comparison = compare_with_baseline(current=metrics, baseline=baseline, policy=policy)
    suite_pass = all(item.passed for item in results) and comparison.get("status") != "regressed"

    summary = {
        "generated_at": _utc_now(),
        "status": "passed" if suite_pass else "failed",
        "total_cases": len(results),
        "passed_cases": sum(1 for item in results if item.passed),
        "metrics": metrics,
        "comparison": comparison,
        "policy": {
            "max_coverage_drop": policy.max_coverage_drop,
            "max_reproducibility_drop": policy.max_reproducibility_drop,
            "max_stability_drop": policy.max_stability_drop,
        },
        "cases": [item.to_dict() for item in results],
    }
    artifacts = export_summary(summary=summary, output_dir=output_dir)
    summary["artifacts"] = artifacts

    if write_baseline and baseline_path is not None:
        write_baseline_metrics(path=baseline_path, metrics=metrics)
        summary["baseline_written"] = str(Path(baseline_path).as_posix())

    return summary


def run_case(*, case: BenchmarkCase, executor: BenchmarkExecutor) -> CaseResult:
    started = perf_counter()
    raw = executor(case)
    duration = perf_counter() - started

    status = str(raw.get("status", "failed")).strip().lower()
    scan = raw.get("scan", {})
    verification = raw.get("verification", {})
    finding_count = int(scan.get("finding_count", 0)) if isinstance(scan, dict) else 0
    verified_findings = int(verification.get("verified_findings", 0)) if isinstance(verification, dict) else 0
    failure_reason = str(raw.get("failure_reason", "")).strip()

    checks = {
        "status_ok": _status_check(expected_status=case.expected.status, actual_status=status),
        "finding_count_ok": finding_count >= case.expected.min_finding_count,
        "verified_findings_ok": verified_findings >= case.expected.min_verified_findings,
        "failure_reason_ok": _failure_reason_check(
            expected_status=case.expected.status,
            allow_failure_reasons=case.expected.allow_failure_reasons,
            failure_reason=failure_reason,
        ),
        "duration_ok": (
            duration <= case.expected.max_duration_seconds
            if case.expected.max_duration_seconds is not None
            else True
        ),
    }
    passed = all(checks.values())
    return CaseResult(
        case_id=case.case_id,
        workflow=case.workflow,
        target=case.target,
        status=status,
        finding_count=finding_count,
        verified_findings=verified_findings,
        failure_reason=failure_reason,
        duration_seconds=duration,
        passed=passed,
        checks=checks,
    )


def summarize_case_results(results: list[CaseResult]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for item in results if item.passed)
    tasks_with_findings = sum(1 for item in results if item.finding_count > 0)
    tasks_with_verified = sum(1 for item in results if item.verified_findings > 0)
    avg_duration = (sum(item.duration_seconds for item in results) / total) if total else 0.0
    coverage_rate = (tasks_with_findings / total) if total else 0.0
    reproducibility_rate = (tasks_with_verified / tasks_with_findings) if tasks_with_findings else 0.0
    stability_rate = (passed / total) if total else 0.0
    return {
        "coverage_rate": round(coverage_rate, 4),
        "reproducibility_rate": round(reproducibility_rate, 4),
        "stability_rate": round(stability_rate, 4),
        "average_duration_seconds": round(avg_duration, 4),
        "tasks_with_findings": tasks_with_findings,
        "tasks_with_verified_findings": tasks_with_verified,
    }


def load_baseline_metrics(path: str | Path | None) -> dict[str, float] | None:
    if path is None:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        parsed = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    metrics = parsed.get("metrics", parsed)
    if not isinstance(metrics, dict):
        return None
    return {
        "coverage_rate": float(metrics.get("coverage_rate", 0.0)),
        "reproducibility_rate": float(metrics.get("reproducibility_rate", 0.0)),
        "stability_rate": float(metrics.get("stability_rate", 0.0)),
    }


def write_baseline_metrics(*, path: str | Path, metrics: dict[str, Any]) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _utc_now(),
        "metrics": {
            "coverage_rate": float(metrics.get("coverage_rate", 0.0)),
            "reproducibility_rate": float(metrics.get("reproducibility_rate", 0.0)),
            "stability_rate": float(metrics.get("stability_rate", 0.0)),
        },
    }
    file_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare_with_baseline(
    *,
    current: dict[str, Any],
    baseline: dict[str, float] | None,
    policy: RegressionPolicy,
) -> dict[str, Any]:
    if baseline is None:
        return {
            "status": "no_baseline",
            "regressions": [],
            "baseline_metrics": None,
        }

    regressions = []
    checks = [
        ("coverage_rate", policy.max_coverage_drop),
        ("reproducibility_rate", policy.max_reproducibility_drop),
        ("stability_rate", policy.max_stability_drop),
    ]
    for metric, max_drop in checks:
        baseline_value = float(baseline.get(metric, 0.0))
        current_value = float(current.get(metric, 0.0))
        drop = baseline_value - current_value
        if drop > max_drop:
            regressions.append(
                {
                    "metric": metric,
                    "baseline": round(baseline_value, 4),
                    "current": round(current_value, 4),
                    "drop": round(drop, 4),
                    "allowed_drop": round(max_drop, 4),
                }
            )

    return {
        "status": "regressed" if regressions else "healthy",
        "regressions": regressions,
        "baseline_metrics": baseline,
    }


def export_summary(*, summary: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    output_root = Path(output_dir)
    date_part = str(summary.get("generated_at", _utc_now()))[:10]
    run_id = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    folder = output_root / date_part / f"regression-{run_id}"
    folder.mkdir(parents=True, exist_ok=True)

    json_path = folder / "summary.json"
    md_path = folder / "summary.md"
    json_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_to_markdown(summary), encoding="utf-8")
    return {
        "json_path": json_path.as_posix(),
        "markdown_path": md_path.as_posix(),
    }


def _to_markdown(summary: dict[str, Any]) -> str:
    metrics = summary.get("metrics", {})
    lines = [
        "# Regression Summary",
        "",
        f"- Generated At: {summary.get('generated_at', '')}",
        f"- Status: {summary.get('status', '')}",
        f"- Total Cases: {summary.get('total_cases', 0)}",
        f"- Passed Cases: {summary.get('passed_cases', 0)}",
        "",
        "## KPI",
        "",
        f"- Coverage Rate: {metrics.get('coverage_rate', 0)}",
        f"- Reproducibility Rate: {metrics.get('reproducibility_rate', 0)}",
        f"- Stability Rate: {metrics.get('stability_rate', 0)}",
        f"- Average Duration Seconds: {metrics.get('average_duration_seconds', 0)}",
        "",
        "## Comparison",
        "",
        "```json",
        json.dumps(summary.get("comparison", {}), ensure_ascii=True, indent=2),
        "```",
        "",
        "## Case Results",
        "",
        "```json",
        json.dumps(summary.get("cases", []), ensure_ascii=True, indent=2),
        "```",
    ]
    return "\n".join(lines) + "\n"


def _status_check(*, expected_status: str, actual_status: str) -> bool:
    if expected_status in {"", "any"}:
        return True
    return actual_status == expected_status


def _failure_reason_check(
    *,
    expected_status: str,
    allow_failure_reasons: tuple[str, ...],
    failure_reason: str,
) -> bool:
    if expected_status != "failed":
        return True
    if not allow_failure_reasons:
        return True
    return any(failure_reason.startswith(item) for item in allow_failure_reasons)


def _default_executor(case: BenchmarkCase) -> dict[str, Any]:
    workflow = case.workflow.strip().lower()
    if workflow in {"poc_single_target", "poc"}:
        return run_poc_workflow(
            target=case.target,
            requested_by=case.requested_by,
            task_id=f"benchmark-{case.case_id}",
            trace_id=f"benchmark-{case.case_id}",
            agent_id="regression-runner",
        )
    raise ValueError(f"unsupported_workflow:{case.workflow}")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run regression benchmark suite.")
    parser.add_argument("--benchmark-dir", default="tests/regression/benchmarks")
    parser.add_argument("--output-dir", default="tests/regression/results")
    parser.add_argument("--baseline-path", default="tests/regression/baseline_summary.json")
    parser.add_argument("--policy-path", default="tests/regression/benchmarks/policy.yaml")
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    summary = run_regression_suite(
        benchmark_dir=args.benchmark_dir,
        output_dir=args.output_dir,
        baseline_path=args.baseline_path,
        policy_path=args.policy_path,
        write_baseline=args.write_baseline,
    )
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0 if summary.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
