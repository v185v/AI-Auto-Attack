from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import argparse
import json
import subprocess
from typing import Any

import yaml


@dataclass(frozen=True)
class CommandResult:
    command: str
    return_code: int
    passed: bool
    output: str
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "return_code": self.return_code,
            "passed": self.passed,
            "output": self.output,
            "timed_out": self.timed_out,
        }


def load_manifest(manifest_path: str | Path) -> dict[str, Any]:
    path = Path(manifest_path)
    if not path.exists():
        raise ValueError(f"manifest_not_found:{path.as_posix()}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("invalid_manifest")
    required_paths = raw.get("required_paths", [])
    required_commands = raw.get("required_commands", [])
    if not isinstance(required_paths, list):
        required_paths = []
    if not isinstance(required_commands, list):
        required_commands = []
    return {
        "name": str(raw.get("name", "release-manifest")),
        "version": int(raw.get("version", 1)),
        "required_paths": [str(item) for item in required_paths if str(item).strip()],
        "required_commands": [str(item) for item in required_commands if str(item).strip()],
    }


def validate_required_paths(*, base_dir: str | Path, required_paths: list[str]) -> dict[str, Any]:
    root = Path(base_dir)
    existing = []
    missing = []
    for rel in required_paths:
        candidate = root / rel
        if candidate.exists():
            existing.append(rel)
        else:
            missing.append(rel)
    return {
        "total": len(required_paths),
        "existing_count": len(existing),
        "missing_count": len(missing),
        "existing": existing,
        "missing": missing,
        "passed": len(missing) == 0,
    }


def run_commands(
    *,
    base_dir: str | Path,
    commands: list[str],
    execute: bool,
    command_timeout_seconds: int = 300,
) -> dict[str, Any]:
    if not execute:
        return {
            "executed": False,
            "total": len(commands),
            "passed_count": 0,
            "failed_count": 0,
            "items": [],
            "passed": True,
        }

    items: list[CommandResult] = []
    timeout = max(1, int(command_timeout_seconds))
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=str(Path(base_dir)),
                text=True,
                capture_output=True,
                check=False,
                shell=True,
                timeout=timeout,
            )
            output = _join_command_output(completed.stdout, completed.stderr)
            items.append(
                CommandResult(
                    command=command,
                    return_code=int(completed.returncode),
                    passed=int(completed.returncode) == 0,
                    output=output[-2000:],
                )
            )
        except subprocess.TimeoutExpired as exc:
            output = _join_command_output(exc.stdout, exc.stderr)
            timeout_note = f"timeout_after_seconds:{timeout}"
            merged = f"{timeout_note}\n{output}".strip() if output else timeout_note
            items.append(
                CommandResult(
                    command=command,
                    return_code=-1,
                    passed=False,
                    output=merged[-2000:],
                    timed_out=True,
                )
            )

    passed_count = sum(1 for item in items if item.passed)
    failed_count = len(items) - passed_count
    return {
        "executed": True,
        "total": len(items),
        "timeout_seconds": timeout,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "items": [item.to_dict() for item in items],
        "passed": failed_count == 0,
    }


def build_release_report(
    *,
    base_dir: str | Path,
    manifest_path: str | Path = "infra/release_manifest.yaml",
    execute_commands: bool = False,
    command_timeout_seconds: int = 300,
    output_dir: str | Path = "infra/release_reports",
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    paths_result = validate_required_paths(
        base_dir=base_dir,
        required_paths=list(manifest.get("required_paths", [])),
    )
    commands_result = run_commands(
        base_dir=base_dir,
        commands=list(manifest.get("required_commands", [])),
        execute=execute_commands,
        command_timeout_seconds=command_timeout_seconds,
    )
    overall_passed = bool(paths_result.get("passed")) and bool(commands_result.get("passed"))
    report = {
        "generated_at": _utc_now(),
        "status": "passed" if overall_passed else "failed",
        "manifest": {
            "name": manifest.get("name", ""),
            "version": manifest.get("version", 1),
            "path": Path(manifest_path).as_posix(),
        },
        "paths": paths_result,
        "commands": commands_result,
    }
    artifacts = export_report(report=report, output_dir=output_dir)
    report["artifacts"] = artifacts
    return report


def export_report(*, report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    root = Path(output_dir)
    date_part = str(report.get("generated_at", _utc_now()))[:10]
    run_id = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
    folder = root / date_part / f"release-{run_id}"
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / "release_report.json"
    md_path = folder / "release_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_to_markdown(report), encoding="utf-8")
    return {
        "json_path": json_path.as_posix(),
        "markdown_path": md_path.as_posix(),
    }


def _to_markdown(report: dict[str, Any]) -> str:
    paths = report.get("paths", {})
    commands = report.get("commands", {})
    lines = [
        "# Release Validation Report",
        "",
        f"- Generated At: {report.get('generated_at', '')}",
        f"- Status: {report.get('status', '')}",
        "",
        "## Path Checks",
        "",
        f"- Total: {paths.get('total', 0)}",
        f"- Existing: {paths.get('existing_count', 0)}",
        f"- Missing: {paths.get('missing_count', 0)}",
        "",
        "## Command Checks",
        "",
        f"- Executed: {commands.get('executed', False)}",
        f"- Total: {commands.get('total', 0)}",
        f"- Passed: {commands.get('passed_count', 0)}",
        f"- Failed: {commands.get('failed_count', 0)}",
    ]
    missing = paths.get("missing", [])
    if isinstance(missing, list) and missing:
        lines.extend(["", "## Missing Paths", ""])
        lines.extend([f"- {item}" for item in missing])
    return "\n".join(lines) + "\n"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _join_command_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    def _normalize(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    return _normalize(stdout) + _normalize(stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate release readiness with manifest checks.")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--manifest", default="infra/release_manifest.yaml")
    parser.add_argument("--output-dir", default="infra/release_reports")
    parser.add_argument("--execute-commands", action="store_true")
    parser.add_argument("--command-timeout-seconds", type=int, default=300)
    args = parser.parse_args()

    report = build_release_report(
        base_dir=args.base_dir,
        manifest_path=args.manifest,
        output_dir=args.output_dir,
        execute_commands=args.execute_commands,
        command_timeout_seconds=args.command_timeout_seconds,
    )
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
