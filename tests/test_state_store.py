from backend.workflow.state_store import StateStoreSettings, WorkflowStateStore


def test_state_store_save_list_latest_and_get_version(tmp_path) -> None:
    store = WorkflowStateStore(StateStoreSettings(directory=str(tmp_path / "state")))
    task_id = "task-123"
    trace_id = "trace-123"

    first = store.save_snapshot(
        task_id=task_id,
        trace_id=trace_id,
        step="init",
        status="in_progress",
        state={"task_id": task_id, "trace_id": trace_id, "current_step": "init"},
        node_input={"target": "10.20.1.8"},
        node_output={"ok": True},
        reason="workflow_initialized",
    )
    second = store.save_snapshot(
        task_id=task_id,
        trace_id=trace_id,
        step="scan_target",
        status="failed",
        state={"task_id": task_id, "trace_id": trace_id, "current_step": "scan_target"},
        node_input={"target": "10.20.1.8"},
        node_output={"status": "failed"},
        reason="scan_failed",
    )

    assert first["version"] == 1
    assert second["version"] == 2
    assert first["state"]["state_version"] == 1
    assert second["state"]["state_version"] == 2

    all_items = store.list_snapshots(task_id)
    assert len(all_items) == 2
    assert all_items[0]["step"] == "init"
    assert all_items[1]["step"] == "scan_target"

    latest = store.get_latest_snapshot(task_id)
    assert latest is not None
    assert latest["version"] == 2
    assert latest["status"] == "failed"

    version_1 = store.get_snapshot(task_id, 1)
    assert version_1 is not None
    assert version_1["step"] == "init"
