from __future__ import annotations

import re
from urllib.parse import urlparse

from connectors.base import ToolConnector
from connectors.models import CommandExecution, PreparedCommand


OPEN_PORT_RE = re.compile(r"^(?P<port>\d+)\/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)\s*(?P<extra>.*)$")


class NmapConnector(ToolConnector):
    def __init__(self, *, binary: str = "nmap", timeout_seconds: int = 120, runner=None) -> None:
        super().__init__(
            tool_name="nmap",
            binary=binary,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )

    def prepare(self, target: str) -> PreparedCommand:
        host = _normalize_host_target(target)
        command = [self.binary, "-Pn", "-sV", "-T4", "--open", host]
        return PreparedCommand(
            tool=self.tool_name,
            target=host,
            command=command,
            timeout_seconds=self.timeout_seconds,
            metadata={"profile": "service_discovery"},
        )

    def parse(self, execution: CommandExecution, prepared: PreparedCommand) -> dict:
        open_ports: list[dict] = []
        for line in execution.stdout.splitlines():
            match = OPEN_PORT_RE.match(line.strip())
            if not match:
                continue
            data = match.groupdict()
            open_ports.append(
                {
                    "port": int(data["port"]),
                    "protocol": data["proto"],
                    "service": data["service"],
                    "extra": data["extra"].strip(),
                }
            )

        findings = [
            {
                "id": f"nmap-open-port-{item['port']}",
                "tool": "nmap",
                "type": "open_port",
                "severity": "medium",
                "confidence": 0.9,
                "evidence": f"{item['port']}/{item['protocol']} {item['service']}",
                "details": item,
            }
            for item in open_ports
        ]

        return {
            "host": prepared.target,
            "host_up": "Host is up" in execution.stdout,
            "open_ports": open_ports,
            "findings": findings,
        }

    def validate(self, parsed: dict) -> dict:
        if "open_ports" not in parsed:
            return {"valid": False, "reason": "missing_open_ports"}
        return {"valid": True, "reason": "ok"}


def _normalize_host_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc and parsed.hostname:
        return parsed.hostname
    pseudo = urlparse(f"//{target}")
    if pseudo.hostname:
        return pseudo.hostname
    return target.split("/", maxsplit=1)[0].strip()

