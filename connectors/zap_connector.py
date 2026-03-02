from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from connectors.base import ToolConnector
from connectors.models import CommandExecution, PreparedCommand


SEVERITY_RE = re.compile(r"\b(high|medium|low|informational|info)\b", re.IGNORECASE)
ALERT_RE = re.compile(r"\b(alert|warn|fail)\b", re.IGNORECASE)


class ZapConnector(ToolConnector):
    def __init__(self, *, binary: str = "zap.sh", timeout_seconds: int = 300, runner=None) -> None:
        super().__init__(
            tool_name="zaproxy",
            binary=binary,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )

    def prepare(self, target: str) -> PreparedCommand:
        web_target = _normalize_web_target(target)
        command = [self.binary, "-cmd", "-quickurl", web_target, "-quickprogress"]
        return PreparedCommand(
            tool=self.tool_name,
            target=web_target,
            command=command,
            timeout_seconds=self.timeout_seconds,
            metadata={"profile": "quick_scan"},
        )

    def parse(self, execution: CommandExecution, prepared: PreparedCommand) -> dict:
        findings: list[dict] = []
        alerts = _extract_alert_lines(execution.stdout)
        for idx, line in enumerate(alerts, start=1):
            severity_match = SEVERITY_RE.search(line)
            severity = severity_match.group(1).lower() if severity_match else "unknown"
            findings.append(
                {
                    "id": f"zap-alert-{idx}",
                    "tool": "zaproxy",
                    "type": "web_alert",
                    "severity": severity,
                    "confidence": 0.75,
                    "evidence": line,
                    "details": {"line": line},
                }
            )

        extra: dict = {}
        stripped = execution.stdout.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                extra["raw_json"] = json.loads(stripped)
            except json.JSONDecodeError:
                pass

        return {
            "target": prepared.target,
            "alert_lines": alerts,
            "alert_count": len(alerts),
            "findings": findings,
            **extra,
        }

    def validate(self, parsed: dict) -> dict:
        if "alert_count" not in parsed:
            return {"valid": False, "reason": "missing_alert_count"}
        return {"valid": True, "reason": "ok"}


def _extract_alert_lines(text: str) -> list[str]:
    items: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ALERT_RE.search(line):
            items.append(line)
    return items


def _normalize_web_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return target
    return f"http://{target.strip()}"

