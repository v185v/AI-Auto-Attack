from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import ssl
from typing import Any, Callable
from urllib import error, request
from uuid import uuid4

from backend.core.config import get_settings
from backend.security.secrets_manager import get_secret_manager


HTTPRequester = Callable[
    [str, str, dict[str, str], bytes | None, int, bool],
    tuple[int, Any, str],
]


@dataclass(frozen=True)
class DefectDojoSettings:
    enabled: bool
    base_url: str
    api_token: str
    engagement_id: int
    scan_type: str
    minimum_severity: str
    verify_ssl: bool
    timeout_seconds: int
    default_tags: list[str]


class DefectDojoConnector:
    def __init__(
        self,
        settings: DefectDojoSettings,
        requester: HTTPRequester | None = None,
    ) -> None:
        self.settings = settings
        self.requester = requester or _default_http_request

    def upload_report(
        self,
        *,
        report: dict[str, Any],
        report_artifacts: dict[str, Any],
        task_id: str = "",
        trace_id: str = "",
        scan_name: str = "",
    ) -> dict[str, Any]:
        if not self.settings.enabled:
            return {
                "enabled": False,
                "status": "skipped",
                "reason": "defectdojo_disabled",
            }
        if not self._is_configured():
            return {
                "enabled": True,
                "status": "failed",
                "reason": "defectdojo_config_incomplete",
            }

        json_path = str(report_artifacts.get("json_path", "")).strip()
        if not json_path:
            return {
                "enabled": True,
                "status": "failed",
                "reason": "report_json_path_missing",
            }
        path = Path(json_path)
        if not path.exists():
            return {
                "enabled": True,
                "status": "failed",
                "reason": "report_json_file_not_found",
                "json_path": path.as_posix(),
            }

        final_scan_name = scan_name or f"ai-attack:{report.get('workflow_name', 'poc')}:{report.get('report_id', 'unknown')}"
        fields = {
            "scan_type": self.settings.scan_type,
            "engagement": str(self.settings.engagement_id),
            "minimum_severity": self.settings.minimum_severity,
            "active": "true",
            "verified": "true",
            "close_old_findings": "false",
            "scan_date": str(report.get("generated_at", ""))[:10],
            "test_title": final_scan_name,
        }
        tags = list(self.settings.default_tags)
        if task_id:
            tags.append(f"task:{task_id}")
        if trace_id:
            tags.append(f"trace:{trace_id}")
        if tags:
            fields["tags"] = ",".join(sorted(set(tags)))

        file_bytes = path.read_bytes()
        body, content_type = _encode_multipart_form(
            fields=fields,
            file_field="file",
            filename=path.name,
            file_bytes=file_bytes,
            file_content_type="application/json",
        )
        endpoint = f"{self.settings.base_url.rstrip('/')}/api/v2/import-scan/"
        headers = {
            "Authorization": f"Token {self.settings.api_token}",
            "Content-Type": content_type,
            "Accept": "application/json",
        }

        try:
            http_status, response_data, response_text = self.requester(
                "POST",
                endpoint,
                headers,
                body,
                self.settings.timeout_seconds,
                self.settings.verify_ssl,
            )
        except Exception as exc:
            return {
                "enabled": True,
                "status": "failed",
                "reason": "defectdojo_request_error",
                "error": str(exc),
                "endpoint": endpoint,
            }

        result = {
            "enabled": True,
            "endpoint": endpoint,
            "http_status": int(http_status),
            "status": "completed" if int(http_status) in {200, 201, 202} else "failed",
            "scan_name": final_scan_name,
            "engagement_id": self.settings.engagement_id,
            "response": response_data if isinstance(response_data, dict) else {},
        }
        if result["status"] == "failed":
            result["reason"] = _extract_error_reason(response_data=response_data, response_text=response_text)
        else:
            import_id = _extract_import_id(response_data)
            if import_id is not None:
                result["import_id"] = import_id
        return result

    def update_finding_status(
        self,
        *,
        finding_id: int,
        status: str,
        note: str = "",
    ) -> dict[str, Any]:
        if not self.settings.enabled:
            return {
                "enabled": False,
                "status": "skipped",
                "reason": "defectdojo_disabled",
            }
        if not self._is_configured():
            return {
                "enabled": True,
                "status": "failed",
                "reason": "defectdojo_config_incomplete",
            }
        payload = _map_lifecycle_status(status=status, note=note)
        if payload is None:
            return {
                "enabled": True,
                "status": "failed",
                "reason": "unsupported_lifecycle_status",
                "lifecycle_status": status,
            }

        endpoint = f"{self.settings.base_url.rstrip('/')}/api/v2/findings/{int(finding_id)}/"
        headers = {
            "Authorization": f"Token {self.settings.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        try:
            http_status, response_data, response_text = self.requester(
                "PATCH",
                endpoint,
                headers,
                body,
                self.settings.timeout_seconds,
                self.settings.verify_ssl,
            )
        except Exception as exc:
            return {
                "enabled": True,
                "status": "failed",
                "reason": "defectdojo_request_error",
                "error": str(exc),
                "endpoint": endpoint,
            }

        result = {
            "enabled": True,
            "endpoint": endpoint,
            "http_status": int(http_status),
            "status": "completed" if int(http_status) in {200, 202} else "failed",
            "lifecycle_status": status,
            "response": response_data if isinstance(response_data, dict) else {},
        }
        if result["status"] == "failed":
            result["reason"] = _extract_error_reason(response_data=response_data, response_text=response_text)
        return result

    def _is_configured(self) -> bool:
        return bool(self.settings.base_url and self.settings.api_token and self.settings.engagement_id > 0)


def _encode_multipart_form(
    *,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    file_bytes: bytes,
    file_content_type: str,
) -> tuple[bytes, str]:
    boundary = f"----aiattack{uuid4().hex}"
    body = bytearray()

    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{value}\r\n".encode("utf-8"))

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode("utf-8")
    )
    body.extend(f"Content-Type: {file_content_type}\r\n\r\n".encode("utf-8"))
    body.extend(file_bytes)
    body.extend("\r\n".encode("utf-8"))
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _default_http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout_seconds: int,
    verify_ssl: bool,
) -> tuple[int, Any, str]:
    req = request.Request(url=url, data=body, method=method, headers=headers)
    context = None
    if url.lower().startswith("https://") and not verify_ssl:
        context = ssl._create_unverified_context()

    try:
        with request.urlopen(req, timeout=timeout_seconds, context=context) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return int(response.status), _parse_json_text(raw), raw
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), _parse_json_text(raw), raw


def _parse_json_text(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


def _extract_import_id(response_data: Any) -> int | None:
    if isinstance(response_data, dict):
        for key in ("id", "test", "test_id"):
            value = response_data.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
    return None


def _extract_error_reason(*, response_data: Any, response_text: str) -> str:
    if isinstance(response_data, dict):
        for key in ("message", "detail", "error", "errors"):
            value = response_data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list) and value:
                return str(value[0])
            if isinstance(value, dict) and value:
                return str(value)
    raw = response_text.strip()
    return raw[:300] if raw else "defectdojo_request_failed"


def _map_lifecycle_status(*, status: str, note: str) -> dict[str, Any] | None:
    normalized = status.strip().lower()
    payload: dict[str, Any]
    if normalized == "new":
        payload = {"active": True, "verified": True, "is_mitigated": False}
    elif normalized == "fixed":
        payload = {"active": False, "verified": True, "is_mitigated": True}
    elif normalized == "retest_failed":
        payload = {"active": True, "verified": True, "is_mitigated": False}
    elif normalized == "closed":
        payload = {"active": False, "verified": True, "is_mitigated": True}
    else:
        return None
    if note:
        payload["mitigation"] = note
    return payload


@lru_cache(maxsize=1)
def get_defectdojo_settings() -> DefectDojoSettings:
    settings = get_settings()
    integrations = settings.get("integrations", {})
    defectdojo = integrations.get("defectdojo", {})
    secret_manager = get_secret_manager()
    configured_token = str(defectdojo.get("api_token", "")).strip()
    token = configured_token or secret_manager.get("defectdojo_api_token", "")
    tags = defectdojo.get("default_tags", [])
    return DefectDojoSettings(
        enabled=bool(defectdojo.get("enabled", False)),
        base_url=str(defectdojo.get("base_url", "")).strip(),
        api_token=token,
        engagement_id=int(defectdojo.get("engagement_id", 0)),
        scan_type=str(defectdojo.get("scan_type", "Generic Findings Import")),
        minimum_severity=str(defectdojo.get("minimum_severity", "Low")),
        verify_ssl=bool(defectdojo.get("verify_ssl", True)),
        timeout_seconds=int(defectdojo.get("timeout_seconds", 30)),
        default_tags=[str(item) for item in tags] if isinstance(tags, list) else [],
    )


@lru_cache(maxsize=1)
def get_defectdojo_connector() -> DefectDojoConnector:
    return DefectDojoConnector(get_defectdojo_settings())


def clear_defectdojo_connector_cache() -> None:
    get_defectdojo_settings.cache_clear()
    get_defectdojo_connector.cache_clear()
