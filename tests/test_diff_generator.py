from pathlib import Path

from reports.diff_generator import DiffReportGenerator


def test_diff_generator_builds_resolved_and_new_findings(tmp_path) -> None:
    generator = DiffReportGenerator(output_dir=str(tmp_path / "diff"))
    before_report = {
        "report_id": "before-1",
        "status": "completed",
        "summary": {"target": "10.20.1.8", "verified_count": 1},
        "scan": {
            "findings": [
                {
                    "id": "finding-1",
                    "type": "open_port",
                    "tool": "nmap",
                    "severity": "medium",
                    "confidence": 0.9,
                    "evidence": "80/tcp",
                }
            ]
        },
    }
    after_report = {
        "report_id": "after-1",
        "status": "completed",
        "summary": {"target": "10.20.1.8", "verified_count": 0},
        "scan": {
            "findings": [
                {
                    "id": "finding-2",
                    "type": "template_match",
                    "tool": "nuclei",
                    "severity": "low",
                    "confidence": 0.8,
                    "evidence": "http://10.20.1.8",
                }
            ]
        },
    }

    payload, artifacts = generator.generate(
        source_task_id="task-a",
        retest_task_id="task-a-retest",
        before_report=before_report,
        after_report=after_report,
        focus_findings=[{"id": "finding-1"}],
        focus_tools=["nmap"],
    )

    assert payload["summary"]["before_count"] == 1
    assert payload["summary"]["after_count"] == 1
    assert payload["summary"]["resolved_count"] == 1
    assert payload["summary"]["new_count"] == 1
    assert payload["status"] == "mixed"
    assert Path(artifacts["json_path"]).exists()
    assert Path(artifacts["markdown_path"]).exists()
