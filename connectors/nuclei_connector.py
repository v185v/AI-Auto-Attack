from __future__ import annotations

import json
from urllib.parse import urlparse

from connectors.base import ToolConnector
from connectors.models import CommandExecution, PreparedCommand


class NucleiConnector(ToolConnector):
    def __init__(self, *, binary: str = "nuclei", timeout_seconds: int = 180, runner=None) -> None:
        super().__init__(
            tool_name="nuclei",
            binary=binary,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )

    def prepare(self, target: str) -> PreparedCommand:
        web_target = _normalize_web_target(target)
        command = [self.binary, "-u", web_target, "-jsonl", "-silent"]
        return PreparedCommand(
            tool=self.tool_name,
            target=web_target,
            command=command,
            timeout_seconds=self.timeout_seconds,
            metadata={"profile": "template_scan"},
        )

    def parse(self, execution: CommandExecution, prepared: PreparedCommand) -> dict:
        items: list[dict] = []
        findings: list[dict] = []
        for line in execution.stdout.splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            items.append(item)
            info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
            severity = str(info.get("severity", "unknown")).lower()
            template_id = str(item.get("template-id", "unknown"))
            findings.append(
                {
                    "id": f"nuclei-{template_id}",
                    "tool": "nuclei",
                    "type": "template_match",
                    "severity": severity,
                    "confidence": 0.85,
                    "evidence": str(item.get("matched-at", prepared.target)),
                    "details": item,
                }
            )
        return {
            "target": prepared.target,
            "matches": items,
            "match_count": len(items),
            "findings": findings,
        }

    def validate(self, parsed: dict) -> dict:
        if "matches" not in parsed:
            return {"valid": False, "reason": "missing_matches"}
        return {"valid": True, "reason": "ok"}


def _normalize_web_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return target
    return f"http://{target.strip()}"

