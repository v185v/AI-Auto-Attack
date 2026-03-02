from __future__ import annotations

from pathlib import Path
import sys

from infra.release_validator import (
    build_release_report,
    load_manifest,
    run_commands,
    validate_required_paths,
)


def test_load_manifest_and_validate_paths(tmp_path) -> None:
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        "\n".join(
            [
                "name: test-manifest",
                "version: 1",
                "required_paths:",
                "  - README.md",
                "  - docs/missing.md",
                "required_commands:",
                "  - pytest -q",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = load_manifest(manifest_path)
    assert manifest["name"] == "test-manifest"
    assert len(manifest["required_paths"]) == 2
    assert manifest["required_commands"] == ["pytest -q"]

    checked = validate_required_paths(base_dir=tmp_path, required_paths=manifest["required_paths"])
    assert checked["existing_count"] == 1
    assert checked["missing_count"] == 1
    assert checked["passed"] is False


def test_build_release_report_without_command_execution(tmp_path) -> None:
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "architecture.md").write_text("arch\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        "\n".join(
            [
                "name: test-manifest",
                "version: 1",
                "required_paths:",
                "  - README.md",
                "  - docs/architecture.md",
                "required_commands:",
                "  - pytest -q",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = build_release_report(
        base_dir=tmp_path,
        manifest_path=manifest_path,
        execute_commands=False,
        output_dir=tmp_path / "release-reports",
    )

    assert report["status"] == "passed"
    assert report["paths"]["passed"] is True
    assert report["commands"]["executed"] is False
    assert Path(report["artifacts"]["json_path"]).exists()
    assert Path(report["artifacts"]["markdown_path"]).exists()


def test_run_commands_marks_timeout_and_preserves_shell_parsing(tmp_path) -> None:
    ok = f"\"{sys.executable}\" -c \"print('ok')\""
    timeout = f"\"{sys.executable}\" -c \"import time; time.sleep(2)\""
    result = run_commands(
        base_dir=tmp_path,
        commands=[ok, timeout],
        execute=True,
        command_timeout_seconds=1,
    )

    assert result["executed"] is True
    assert result["total"] == 2
    assert result["timeout_seconds"] == 1
    assert result["passed_count"] == 1
    assert result["failed_count"] == 1
    assert result["passed"] is False
    items = result["items"]
    assert items[0]["passed"] is True
    assert items[0]["timed_out"] is False
    assert items[1]["passed"] is False
    assert items[1]["timed_out"] is True
