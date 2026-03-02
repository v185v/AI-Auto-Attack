from __future__ import annotations

import json

from connectors.defectdojo_connector import DefectDojoConnector, DefectDojoSettings


def test_defectdojo_upload_skips_when_disabled(tmp_path) -> None:
    connector = DefectDojoConnector(
        DefectDojoSettings(
            enabled=False,
            base_url="https://dojo.local",
            api_token="token",
            engagement_id=10,
            scan_type="Generic Findings Import",
            minimum_severity="Low",
            verify_ssl=True,
            timeout_seconds=30,
            default_tags=[],
        )
    )
    result = connector.upload_report(
        report={"report_id": "r1"},
        report_artifacts={"json_path": str(tmp_path / "report.json")},
    )
    assert result["status"] == "skipped"
    assert result["reason"] == "defectdojo_disabled"


def test_defectdojo_upload_report_success(tmp_path) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"ok": True}) + "\n", encoding="utf-8")
    captured: dict = {}

    def requester(method, url, headers, body, timeout_seconds, verify_ssl):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = body
        captured["timeout_seconds"] = timeout_seconds
        captured["verify_ssl"] = verify_ssl
        return 201, {"id": 233, "message": "imported"}, '{"id":233}'

    connector = DefectDojoConnector(
        DefectDojoSettings(
            enabled=True,
            base_url="https://dojo.local",
            api_token="token",
            engagement_id=23,
            scan_type="Generic Findings Import",
            minimum_severity="Low",
            verify_ssl=False,
            timeout_seconds=15,
            default_tags=["ai-attack"],
        ),
        requester=requester,
    )
    result = connector.upload_report(
        report={"workflow_name": "poc_single_target", "report_id": "abc123", "generated_at": "2026-03-02T00:00:00+00:00"},
        report_artifacts={"json_path": report_file.as_posix()},
        task_id="task-1",
        trace_id="trace-1",
        scan_name="ai-attack:test",
    )
    assert result["status"] == "completed"
    assert result["import_id"] == 233
    assert result["engagement_id"] == 23
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/v2/import-scan/")
    assert captured["headers"]["Authorization"] == "Token token"
    assert "multipart/form-data" in captured["headers"]["Content-Type"]
    assert captured["timeout_seconds"] == 15
    assert captured["verify_ssl"] is False

    body = captured["body"]
    assert isinstance(body, (bytes, bytearray))
    body_text = bytes(body).decode("utf-8", errors="replace")
    assert 'name="engagement"' in body_text
    assert "23" in body_text
    assert 'name="tags"' in body_text
    assert "task:task-1" in body_text
    assert "trace:trace-1" in body_text


def test_defectdojo_update_finding_status(tmp_path) -> None:
    captured: dict = {}

    def requester(method, url, headers, body, timeout_seconds, verify_ssl):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = body
        return 200, {"id": 88, "active": False, "is_mitigated": True}, '{"id":88}'

    connector = DefectDojoConnector(
        DefectDojoSettings(
            enabled=True,
            base_url="https://dojo.local",
            api_token="token",
            engagement_id=23,
            scan_type="Generic Findings Import",
            minimum_severity="Low",
            verify_ssl=True,
            timeout_seconds=20,
            default_tags=[],
        ),
        requester=requester,
    )
    result = connector.update_finding_status(
        finding_id=88,
        status="fixed",
        note="patched",
    )
    assert result["status"] == "completed"
    assert captured["method"] == "PATCH"
    assert captured["url"].endswith("/api/v2/findings/88/")
    payload = json.loads(captured["body"].decode("utf-8"))
    assert payload["active"] is False
    assert payload["is_mitigated"] is True
    assert payload["mitigation"] == "patched"
