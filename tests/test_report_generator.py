import json
from pathlib import Path

from reports.generator import ReportGenerator


def test_report_generator_writes_json_and_markdown(tmp_path) -> None:
    generator = ReportGenerator(output_dir=str(tmp_path / "reports"), enable_pdf=False)
    state = {
        "workflow_name": "poc_single_target",
        "target": "10.20.1.8",
        "status": "completed",
        "analysis": {"allowed": True, "reason": "cidr_allowed", "api_key": "sensitive-key"},
        "scan": {
            "finding_count": 1,
            "findings": [
                {
                    "type": "open_port",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence": "Authorization: Bearer scan-secret-token",
                }
            ],
        },
        "llm_decision": {
            "mode": "stub",
            "evidence_interpretation": {"overall_decision": "risk_confirmed", "confidence": 0.8},
        },
        "verification": {"verified_findings": 1, "decision": "risk_confirmed"},
        "audit_events": [{"event_id": "evt-1", "evidence_dir": "evidence/a"}],
    }

    report, artifacts = generator.generate(state=state)
    assert report["status"] == "completed"
    assert report["summary"]["target"] == "10.20.1.8"
    assert report["summary"]["finding_count"] == 1
    assert report["evidence"]["audit_event_count"] == 1
    assert "defectdojo" in report["integrations"]
    assert report["analysis"]["api_key"] == "***REDACTED***"
    assert "scan-secret-token" not in report["scan"]["findings"][0]["evidence"]

    json_path = Path(artifacts["json_path"])
    md_path = Path(artifacts["markdown_path"])
    assert json_path.exists()
    assert md_path.exists()
    assert artifacts["pdf_path"] is None
    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["analysis"]["api_key"] == "***REDACTED***"
