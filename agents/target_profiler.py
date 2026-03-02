from __future__ import annotations

from functools import lru_cache
import ipaddress
from typing import Any
from urllib.parse import urlparse


WINDOWS_PORT_SIGNALS = {135, 139, 445, 3389, 5985, 5986}
LINUX_PORT_SIGNALS = {22, 111, 2049}
WEB_PORT_SIGNALS = {80, 443, 8080, 8443}

WINDOWS_SERVICE_KEYWORDS = {
    "msrpc",
    "microsoft-ds",
    "netbios",
    "rdp",
    "smb",
    "winrm",
    "wsman",
}
LINUX_SERVICE_KEYWORDS = {
    "ssh",
    "rpcbind",
    "nfs",
    "cups",
}


class TargetProfiler:
    def profile(self, *, target: str, scan: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized_target = target.strip()
        host = _extract_host(normalized_target)
        target_type = _classify_target_type(normalized_target, host)
        open_ports, services = _extract_scan_features(scan or {})

        windows_score = 0.0
        linux_score = 0.0
        signals: list[str] = []

        for port in open_ports:
            if port in WINDOWS_PORT_SIGNALS:
                windows_score += 1.0
                signals.append(f"windows_port:{port}")
            if port in LINUX_PORT_SIGNALS:
                linux_score += 1.0
                signals.append(f"linux_port:{port}")
            if port in WEB_PORT_SIGNALS:
                signals.append(f"web_port:{port}")

        for service in services:
            lowered = service.lower()
            if any(keyword in lowered for keyword in WINDOWS_SERVICE_KEYWORDS):
                windows_score += 1.2
                signals.append(f"windows_service:{service}")
            if any(keyword in lowered for keyword in LINUX_SERVICE_KEYWORDS):
                linux_score += 1.2
                signals.append(f"linux_service:{service}")

        os_guess, confidence = _resolve_os_guess(windows_score=windows_score, linux_score=linux_score)
        strategy_hint = _resolve_strategy_hint(os_guess=os_guess)

        return {
            "target": normalized_target,
            "host": host,
            "target_type": target_type,
            "os_guess": os_guess,
            "os_confidence": confidence,
            "strategy_hint": strategy_hint,
            "open_ports": sorted(open_ports),
            "exposed_services": sorted(set(services)),
            "score": {
                "windows": round(windows_score, 2),
                "linux": round(linux_score, 2),
            },
            "signals": signals[:20],
        }


def _extract_host(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc and parsed.hostname:
        return parsed.hostname
    pseudo = urlparse(f"//{target}")
    if pseudo.hostname:
        return pseudo.hostname
    return target.split("/", maxsplit=1)[0].strip()


def _classify_target_type(target: str, host: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return "url"
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "hostname"


def _extract_scan_features(scan: dict[str, Any]) -> tuple[set[int], list[str]]:
    ports: set[int] = set()
    services: list[str] = []

    tool_results = scan.get("tool_results", [])
    if isinstance(tool_results, list):
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            parsed = item.get("parsed", {})
            if not isinstance(parsed, dict):
                continue
            open_ports = parsed.get("open_ports", [])
            if isinstance(open_ports, list):
                for entry in open_ports:
                    if not isinstance(entry, dict):
                        continue
                    port = entry.get("port")
                    if isinstance(port, int):
                        ports.add(port)
                    service = entry.get("service")
                    if isinstance(service, str) and service:
                        services.append(service)

    findings = scan.get("findings", [])
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            details = item.get("details", {})
            if isinstance(details, dict):
                port = details.get("port")
                if isinstance(port, int):
                    ports.add(port)
                service = details.get("service")
                if isinstance(service, str) and service:
                    services.append(service)
            evidence = str(item.get("evidence", "")).strip()
            if "/" in evidence:
                prefix = evidence.split("/", maxsplit=1)[0]
                if prefix.isdigit():
                    ports.add(int(prefix))
    return ports, services


def _resolve_os_guess(*, windows_score: float, linux_score: float) -> tuple[str, float]:
    total = windows_score + linux_score
    if total <= 0:
        return "unknown", 0.3

    delta = abs(windows_score - linux_score)
    if delta < 0.8:
        confidence = min(0.7, 0.45 + total * 0.05)
        return "unknown", round(confidence, 2)

    guess = "windows" if windows_score > linux_score else "linux"
    confidence = min(0.95, 0.55 + (delta / (total + 1.0)) * 0.4)
    return guess, round(confidence, 2)


def _resolve_strategy_hint(*, os_guess: str) -> str:
    if os_guess == "windows":
        return "strategy_windows"
    if os_guess == "linux":
        return "strategy_linux"
    return "strategy_generic"


@lru_cache(maxsize=1)
def get_target_profiler() -> TargetProfiler:
    return TargetProfiler()


def clear_target_profiler_cache() -> None:
    get_target_profiler.cache_clear()
