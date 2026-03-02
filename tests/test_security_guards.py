import pytest
import json

from backend.security.action_gate import ActionGate
from backend.security.approval_store import ApprovalRecord, ApprovalStore, SQLiteApprovalBackend
from backend.security.scope_guard import ScopeGuard


def test_scope_guard_allows_and_denies_targets() -> None:
    policy = {
        "default_decision": "deny",
        "authorized_targets": {
            "cidr": ["10.10.0.0/16"],
            "hosts": ["demo.internal.local"],
            "domains": ["corp.example.com"],
            "api_base_urls": ["https://api.safe.local/v1"],
        },
    }
    guard = ScopeGuard(policy)

    assert guard.authorize("10.10.1.23").allowed is True
    assert guard.authorize("demo.internal.local").allowed is True
    assert guard.authorize("service.corp.example.com").allowed is True
    assert guard.authorize("https://api.safe.local/v1/users").allowed is True

    denied = guard.authorize("172.16.10.8")
    assert denied.allowed is False
    assert denied.reason in {"ip_out_of_scope", "target_out_of_scope"}


def test_action_gate_requires_and_honors_approval_for_high_risk() -> None:
    policy = {
        "command_allowlist": {
            "low_risk": ["nmap"],
            "medium_risk": ["nikto"],
            "high_risk": ["msfconsole"],
        },
        "gates": {"require_approval_for_high_risk": True},
    }
    store = ApprovalStore()
    gate = ActionGate(policy=policy, approval_store=store)

    first = gate.evaluate(
        target="10.10.1.10",
        command="msfconsole -q",
        requested_by="tester",
    )
    assert first.allowed is False
    assert first.reason == "approval_required"
    assert first.approval_id is not None

    pending = gate.evaluate(
        target="10.10.1.10",
        command="msfconsole -q",
        requested_by="tester",
        approval_id=first.approval_id,
    )
    assert pending.allowed is False
    assert pending.reason == "approval_pending"

    store.decide(first.approval_id, "approved", "sec-lead")
    approved = gate.evaluate(
        target="10.10.1.10",
        command="msfconsole -q",
        requested_by="tester",
        approval_id=first.approval_id,
    )
    assert approved.allowed is True
    assert approved.reason == "approval_granted"


def test_action_gate_normalizes_binary_path_token() -> None:
    policy = {
        "command_allowlist": {
            "low_risk": ["zap.bat"],
            "medium_risk": [],
            "high_risk": [],
        },
        "gates": {"require_approval_for_high_risk": True},
    }
    gate = ActionGate(policy=policy, approval_store=ApprovalStore())
    decision = gate.evaluate(
        target="10.10.1.10",
        command='"C:\\Program Files\\ZAP\\zap.bat" -cmd -quickurl http://10.10.1.10',
        requested_by="tester",
    )
    assert decision.allowed is True
    assert decision.risk_level == "low"


def test_approval_store_persists_records_across_restarts(tmp_path) -> None:
    storage_path = tmp_path / "approvals.json"
    first_store = ApprovalStore(signing_key="test-key", storage_path=storage_path.as_posix())
    created = first_store.create(
        target="10.10.1.10",
        command="msfconsole -q",
        risk_level="high",
        requested_by="tester",
    )
    first_store.decide(created.approval_id, "approved", "sec-lead")

    second_store = ApprovalStore(signing_key="test-key", storage_path=storage_path.as_posix())
    recovered = second_store.get(created.approval_id)
    assert recovered is not None
    assert recovered.status == "approved"
    assert recovered.approver == "sec-lead"
    assert isinstance(recovered.decision_signature, str)
    assert len(recovered.decision_signature or "") == 64
    assert recovered.version == 2


def test_approval_store_increments_version_and_is_idempotent_on_second_decision(tmp_path) -> None:
    storage_path = tmp_path / "approvals.json"
    store = ApprovalStore(signing_key="test-key", storage_path=storage_path.as_posix())
    created = store.create(
        target="10.10.1.20",
        command="msfconsole -q",
        risk_level="high",
        requested_by="tester",
    )
    assert created.version == 1

    decided = store.decide(created.approval_id, "approved", "sec-lead")
    assert decided is not None
    assert decided.version == 2
    assert decided.status == "approved"

    again = store.decide(created.approval_id, "rejected", "sec-lead")
    assert again is not None
    assert again.status == "approved"
    assert again.version == 2


def test_file_backend_migrates_legacy_snapshot_without_losing_high_version_records(tmp_path) -> None:
    storage_path = tmp_path / "approvals.json"
    legacy = {
        "version": 1,
        "updated_at": "2026-03-02T00:00:00+00:00",
        "records": [
            {
                "approval_id": "legacy-1",
                "target": "10.10.9.9",
                "command": "msfconsole -q",
                "risk_level": "high",
                "requested_by": "tester",
                "status": "approved",
                "created_at": "2026-03-01T00:00:00+00:00",
                "updated_at": "2026-03-01T00:10:00+00:00",
                "approver": "sec-lead",
                "decision_signature": "a" * 64,
                "decision_history": [
                    {
                        "status": "approved",
                        "approver": "sec-lead",
                        "decided_at": "2026-03-01T00:10:00+00:00",
                        "signature": "a" * 64,
                    }
                ],
                "version": 2,
            }
        ],
    }
    storage_path.write_text(json.dumps(legacy, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    first = ApprovalStore(signing_key="test-key", storage_path=storage_path.as_posix(), backend="file")
    assert first.get("legacy-1") is not None
    first.create(
        target="10.10.8.8",
        command="msfconsole -q",
        risk_level="high",
        requested_by="tester",
    )

    second = ApprovalStore(signing_key="test-key", storage_path=storage_path.as_posix(), backend="file")
    recovered = second.get("legacy-1")
    assert recovered is not None
    assert recovered.status == "approved"
    assert recovered.version == 2
    assert len(second.list()) == 2


def test_approval_store_sqlite_backend_persists_records_across_restarts(tmp_path) -> None:
    sqlite_path = tmp_path / "approvals.db"
    first_store = ApprovalStore(
        signing_key="test-key",
        backend="sqlite",
        sqlite_path=sqlite_path.as_posix(),
        postgres_table="approval_records_test",
    )
    created = first_store.create(
        target="10.10.2.10",
        command="msfconsole -q",
        risk_level="high",
        requested_by="tester",
    )
    first_store.decide(created.approval_id, "approved", "sec-lead")

    second_store = ApprovalStore(
        signing_key="test-key",
        backend="sqlite",
        sqlite_path=sqlite_path.as_posix(),
        postgres_table="approval_records_test",
    )
    recovered = second_store.get(created.approval_id)
    assert recovered is not None
    assert recovered.status == "approved"
    assert recovered.approver == "sec-lead"
    assert len(second_store.list(status="approved")) == 1
    assert recovered.version == 2


def test_sqlite_backend_rejects_stale_version_update(tmp_path) -> None:
    sqlite_path = tmp_path / "approvals.db"
    table = "approval_records_test_stale"
    store_1 = ApprovalStore(
        signing_key="test-key",
        backend="sqlite",
        sqlite_path=sqlite_path.as_posix(),
        postgres_table=table,
    )
    store_2 = ApprovalStore(
        signing_key="test-key",
        backend="sqlite",
        sqlite_path=sqlite_path.as_posix(),
        postgres_table=table,
    )
    created = store_1.create(
        target="10.10.2.30",
        command="msfconsole -q",
        risk_level="high",
        requested_by="tester",
    )
    stale = store_2.get(created.approval_id)
    assert stale is not None
    assert stale.version == 1

    applied = store_1.decide(created.approval_id, "approved", "sec-lead")
    assert applied is not None
    assert applied.version == 2

    stale_update = ApprovalRecord(
        approval_id=stale.approval_id,
        target=stale.target,
        command=stale.command,
        risk_level=stale.risk_level,
        requested_by=stale.requested_by,
        status="rejected",
        created_at=stale.created_at,
        updated_at=stale.updated_at,
        approver="sec-lead",
        decision_signature="x" * 64,
        decision_history=[{"status": "rejected", "approver": "sec-lead"}],
        version=2,
    )
    backend = SQLiteApprovalBackend(db_path=sqlite_path.as_posix(), table=table)
    assert backend.update_if_version(stale_update, expected_version=1) is False

    latest = store_2.get(created.approval_id)
    assert latest is not None
    assert latest.status == "approved"
    assert latest.version == 2


def test_approval_store_postgres_requires_dsn() -> None:
    with pytest.raises(ValueError, match="postgres_dsn_required"):
        ApprovalStore(
            backend="postgres",
            postgres_dsn="",
        )
