from datetime import UTC, datetime, timedelta
from pathlib import Path

from backend.audit.retention import RetentionService, RetentionSettings


def _mkdatedir(root: Path, days_ago: int) -> Path:
    date_dir = root / (datetime.now(UTC).date() - timedelta(days=days_ago)).isoformat()
    date_dir.mkdir(parents=True, exist_ok=True)
    (date_dir / "dummy.txt").write_text("x", encoding="utf-8")
    return date_dir


def test_retention_service_prune_dry_run_keeps_files(tmp_path) -> None:
    evidence_root = tmp_path / "evidence"
    report_root = tmp_path / "reports"
    diff_root = tmp_path / "diff"
    old_evidence = _mkdatedir(evidence_root, days_ago=20)
    old_report = _mkdatedir(report_root, days_ago=40)
    old_diff = _mkdatedir(diff_root, days_ago=40)

    service = RetentionService(
        RetentionSettings(
            enabled=True,
            evidence_days=7,
            reports_days=30,
            evidence_root=evidence_root.as_posix(),
            report_output_dir=report_root.as_posix(),
            report_diff_output_dir=diff_root.as_posix(),
        )
    )
    result = service.prune(dry_run=True)

    assert result["status"] == "completed"
    assert result["dry_run"] is True
    assert result["evidence"]["pruned_count"] == 1
    assert result["reports"]["pruned_count"] == 1
    assert result["diff_reports"]["pruned_count"] == 1
    assert old_evidence.exists()
    assert old_report.exists()
    assert old_diff.exists()


def test_retention_service_prune_deletes_old_dirs(tmp_path) -> None:
    evidence_root = tmp_path / "evidence"
    report_root = tmp_path / "reports"
    diff_root = tmp_path / "diff"
    old_evidence = _mkdatedir(evidence_root, days_ago=12)
    keep_evidence = _mkdatedir(evidence_root, days_ago=1)
    old_report = _mkdatedir(report_root, days_ago=50)
    keep_report = _mkdatedir(report_root, days_ago=2)
    old_diff = _mkdatedir(diff_root, days_ago=50)
    keep_diff = _mkdatedir(diff_root, days_ago=2)

    service = RetentionService(
        RetentionSettings(
            enabled=True,
            evidence_days=7,
            reports_days=30,
            evidence_root=evidence_root.as_posix(),
            report_output_dir=report_root.as_posix(),
            report_diff_output_dir=diff_root.as_posix(),
        )
    )
    result = service.prune(dry_run=False)

    assert result["status"] == "completed"
    assert old_evidence.exists() is False
    assert old_report.exists() is False
    assert old_diff.exists() is False
    assert keep_evidence.exists() is True
    assert keep_report.exists() is True
    assert keep_diff.exists() is True


def test_retention_service_skips_when_disabled(tmp_path) -> None:
    service = RetentionService(
        RetentionSettings(
            enabled=False,
            evidence_days=7,
            reports_days=30,
            evidence_root=(tmp_path / "evidence").as_posix(),
            report_output_dir=(tmp_path / "reports").as_posix(),
            report_diff_output_dir=(tmp_path / "diff").as_posix(),
        )
    )

    result = service.prune(dry_run=True)
    assert result["status"] == "skipped"
    assert result["reason"] == "retention_disabled"
