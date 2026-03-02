from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import Lock
import time
from typing import Any, Literal, Protocol
from uuid import uuid4

from backend.auth.rbac import get_rbac_settings
from backend.core.config import get_settings


ApprovalStatus = Literal["pending", "approved", "rejected"]


@dataclass
class ApprovalRecord:
    approval_id: str
    target: str
    command: str
    risk_level: str
    requested_by: str
    status: ApprovalStatus
    created_at: str
    updated_at: str
    approver: str | None = None
    decision_signature: str | None = None
    decision_history: list[dict[str, str]] | None = None
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalPersistenceBackend(Protocol):
    def get(self, approval_id: str) -> ApprovalRecord | None:
        raise NotImplementedError

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        raise NotImplementedError

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        raise NotImplementedError

    def update_if_version(self, record: ApprovalRecord, expected_version: int) -> bool:
        raise NotImplementedError


class InMemoryApprovalBackend:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(approval_id)
            return _copy_record(record) if record else None

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        with self._lock:
            items = [_copy_record(item) for item in self._records.values()]
        if status is None:
            return items
        return [item for item in items if item.status == status]

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        with self._lock:
            if record.approval_id in self._records:
                raise ValueError(f"approval_id_conflict:{record.approval_id}")
            self._records[record.approval_id] = _copy_record(record)
            return _copy_record(record)

    def update_if_version(self, record: ApprovalRecord, expected_version: int) -> bool:
        with self._lock:
            current = self._records.get(record.approval_id)
            current_version = current.version if current else 0
            if current_version != max(int(expected_version), 0):
                return False
            self._records[record.approval_id] = _copy_record(record)
            return True


class FileApprovalBackend:
    def __init__(self, *, path: str | None) -> None:
        self.path = Path(path) if path else None
        self._lock = Lock()
        self._records: dict[str, ApprovalRecord] = {}
        self._last_mtime_ns: int = -1
        self._legacy_snapshot_loaded = False
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._sync_locked(force=True)

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            self._sync_locked()
            record = self._records.get(approval_id)
            return _copy_record(record) if record else None

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        with self._lock:
            self._sync_locked()
            items = [_copy_record(item) for item in self._records.values()]
        if status is None:
            return items
        return [item for item in items if item.status == status]

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        path = self.path
        if path is None:
            raise ValueError("file_backend_path_required")
        with self._lock, self._file_lock(path):
            self._sync_locked(force=True)
            if record.approval_id in self._records:
                raise ValueError(f"approval_id_conflict:{record.approval_id}")
            event = {
                "event": "upsert",
                "expected_version": 0,
                "record": record.to_dict(),
                "timestamp": _utc_now(),
            }
            self._append_event_locked(event)
            self._records[record.approval_id] = _copy_record(record)
            return _copy_record(record)

    def update_if_version(self, record: ApprovalRecord, expected_version: int) -> bool:
        path = self.path
        if path is None:
            raise ValueError("file_backend_path_required")
        expected = max(int(expected_version), 0)
        with self._lock, self._file_lock(path):
            self._sync_locked(force=True)
            current = self._records.get(record.approval_id)
            current_version = current.version if current else 0
            if current_version != expected:
                return False
            event = {
                "event": "upsert",
                "expected_version": expected,
                "record": record.to_dict(),
                "timestamp": _utc_now(),
            }
            self._append_event_locked(event)
            self._records[record.approval_id] = _copy_record(record)
            return True

    @contextmanager
    def _file_lock(self, path: Path):
        lock_path = path.with_suffix(f"{path.suffix}.lock")
        deadline = time.time() + 5.0
        fd: int | None = None
        while True:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                break
            except FileExistsError:
                if time.time() >= deadline:
                    raise TimeoutError("approval_store_file_lock_timeout")
                time.sleep(0.01)
        try:
            yield
        finally:
            if fd is not None:
                os.close(fd)
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _sync_locked(self, *, force: bool = False) -> None:
        path = self.path
        if path is None:
            self._records = {}
            self._last_mtime_ns = -1
            return
        if not path.exists():
            self._records = {}
            self._last_mtime_ns = -1
            return
        stat = path.stat()
        mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
        if not force and mtime_ns == self._last_mtime_ns:
            return
        records, legacy_snapshot = self._load_records_from_file(path)
        self._records = records
        self._legacy_snapshot_loaded = legacy_snapshot
        self._last_mtime_ns = mtime_ns

    def _append_event_locked(self, event: dict[str, Any]) -> None:
        path = self.path
        if path is None:
            return
        self._migrate_legacy_snapshot_locked(path)
        with path.open("a", encoding="utf-8") as file_obj:
            file_obj.write(json.dumps(event, ensure_ascii=True) + "\n")
        stat = path.stat()
        self._last_mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))

    def _load_records_from_file(self, path: Path) -> tuple[dict[str, ApprovalRecord], bool]:
        text = path.read_text(encoding="utf-8")
        stripped = text.strip()
        if not stripped:
            return {}, False

        # Backward compatible with legacy snapshot format: {"records": [...]}.
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
            loaded: dict[str, ApprovalRecord] = {}
            for item in parsed.get("records", []):
                record = _parse_record(item)
                if record is not None:
                    loaded[record.approval_id] = record
            return loaded, True

        events: list[dict[str, Any]] = []
        if isinstance(parsed, dict):
            events = [parsed]
        elif isinstance(parsed, list):
            events = [item for item in parsed if isinstance(item, dict)]
        else:
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    events.append(item)

        state: dict[str, ApprovalRecord] = {}
        for item in events:
            event_type = str(item.get("event", "")).strip().lower()
            if event_type not in {"upsert", "snapshot"}:
                continue
            record = _parse_record(item.get("record", {}))
            if record is None:
                continue
            current = state.get(record.approval_id)
            current_version = current.version if current else 0
            if event_type == "snapshot":
                # Snapshot migration event: trust latest absolute state.
                if record.version >= current_version:
                    state[record.approval_id] = record
                continue
            expected_value = item.get("expected_version", record.version - 1)
            expected = max(_to_int(expected_value, default=max(record.version - 1, 0)), 0)
            if current_version != expected:
                continue
            if record.version != expected + 1:
                continue
            state[record.approval_id] = record
        return state, False

    def _migrate_legacy_snapshot_locked(self, path: Path) -> None:
        if not self._legacy_snapshot_loaded:
            return
        lines = []
        for record in self._records.values():
            payload = {
                "event": "snapshot",
                "record": record.to_dict(),
                "timestamp": _utc_now(),
            }
            lines.append(json.dumps(payload, ensure_ascii=True))
        path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
        self._legacy_snapshot_loaded = False
        if path.exists():
            stat = path.stat()
            self._last_mtime_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))


class SQLiteApprovalBackend:
    def __init__(self, *, db_path: str, table: str = "approval_records") -> None:
        if not db_path:
            raise ValueError("sqlite_path_required")
        self.db_path = Path(db_path)
        self.table = _normalize_identifier(table, default="approval_records")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def get(self, approval_id: str) -> ApprovalRecord | None:
        query = (
            f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
            f"approver,decision_signature,decision_history,version FROM {self.table} WHERE approval_id=?"
        )
        with self._connect() as conn:
            row = conn.execute(query, (approval_id,)).fetchone()
        return self._row_to_record(row)

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        if status is None:
            query = (
                f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
                f"approver,decision_signature,decision_history,version FROM {self.table}"
            )
            params: tuple[Any, ...] = ()
        else:
            query = (
                f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
                f"approver,decision_signature,decision_history,version FROM {self.table} WHERE status=?"
            )
            params = (status,)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        items = [self._row_to_record(row) for row in rows]
        return [item for item in items if item is not None]

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        query = (
            f"INSERT INTO {self.table} ("
            "approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
            "approver,decision_signature,decision_history,version"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        values = (
            record.approval_id,
            record.target,
            record.command,
            record.risk_level,
            record.requested_by,
            record.status,
            record.created_at,
            record.updated_at,
            record.approver,
            record.decision_signature,
            _dump_history(record.decision_history),
            record.version,
        )
        try:
            with self._connect() as conn:
                conn.execute(query, values)
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"approval_id_conflict:{record.approval_id}") from exc
        return _copy_record(record)

    def update_if_version(self, record: ApprovalRecord, expected_version: int) -> bool:
        query = (
            f"UPDATE {self.table} SET "
            "target=?, command=?, risk_level=?, requested_by=?, status=?, created_at=?, updated_at=?, "
            "approver=?, decision_signature=?, decision_history=?, version=? "
            "WHERE approval_id=? AND version=?"
        )
        values = (
            record.target,
            record.command,
            record.risk_level,
            record.requested_by,
            record.status,
            record.created_at,
            record.updated_at,
            record.approver,
            record.decision_signature,
            _dump_history(record.decision_history),
            record.version,
            record.approval_id,
            max(int(expected_version), 0),
        )
        with self._connect() as conn:
            cursor = conn.execute(query, values)
            conn.commit()
            return int(cursor.rowcount) == 1

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path.as_posix(), timeout=30)

    def _ensure_schema(self) -> None:
        create_sql = (
            f"CREATE TABLE IF NOT EXISTS {self.table} ("
            "approval_id TEXT PRIMARY KEY,"
            "target TEXT NOT NULL,"
            "command TEXT NOT NULL,"
            "risk_level TEXT NOT NULL,"
            "requested_by TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "created_at TEXT NOT NULL,"
            "updated_at TEXT NOT NULL,"
            "approver TEXT,"
            "decision_signature TEXT,"
            "decision_history TEXT NOT NULL DEFAULT '[]',"
            "version INTEGER NOT NULL DEFAULT 1"
            ")"
        )
        index_sql = f"CREATE INDEX IF NOT EXISTS idx_{self.table}_status ON {self.table}(status)"
        with self._connect() as conn:
            conn.execute(create_sql)
            conn.execute(index_sql)
            if not self._column_exists(conn, "version"):
                conn.execute(f"ALTER TABLE {self.table} ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
            conn.execute(f"UPDATE {self.table} SET version=1 WHERE version IS NULL OR version < 1")
            conn.commit()

    def _column_exists(self, conn: sqlite3.Connection, column: str) -> bool:
        rows = conn.execute(f"PRAGMA table_info({self.table})").fetchall()
        for row in rows:
            if len(row) > 1 and str(row[1]).strip().lower() == column.lower():
                return True
        return False

    @staticmethod
    def _row_to_record(row: Any) -> ApprovalRecord | None:
        if row is None:
            return None
        return _parse_record(
            {
                "approval_id": row[0],
                "target": row[1],
                "command": row[2],
                "risk_level": row[3],
                "requested_by": row[4],
                "status": row[5],
                "created_at": row[6],
                "updated_at": row[7],
                "approver": row[8],
                "decision_signature": row[9],
                "decision_history": _load_history(row[10]),
                "version": row[11],
            }
        )


class PostgresApprovalBackend:
    def __init__(self, *, dsn: str, table: str = "approval_records") -> None:
        if not dsn:
            raise ValueError("postgres_dsn_required")
        self.dsn = dsn
        self.table = _normalize_identifier(table, default="approval_records")
        self._driver = _resolve_postgres_driver()
        self._ensure_schema()

    def get(self, approval_id: str) -> ApprovalRecord | None:
        query = (
            f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
            f"approver,decision_signature,decision_history,version FROM {self.table} WHERE approval_id=%s"
        )
        with self._connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (approval_id,))
                row = cursor.fetchone()
        return self._row_to_record(row)

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        if status is None:
            query = (
                f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
                f"approver,decision_signature,decision_history,version FROM {self.table}"
            )
            params: tuple[Any, ...] = ()
        else:
            query = (
                f"SELECT approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
                f"approver,decision_signature,decision_history,version FROM {self.table} WHERE status=%s"
            )
            params = (status,)
        with self._connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
        items = [self._row_to_record(row) for row in rows]
        return [item for item in items if item is not None]

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        query = (
            f"INSERT INTO {self.table} ("
            "approval_id,target,command,risk_level,requested_by,status,created_at,updated_at,"
            "approver,decision_signature,decision_history,version"
            ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)"
        )
        values = (
            record.approval_id,
            record.target,
            record.command,
            record.risk_level,
            record.requested_by,
            record.status,
            record.created_at,
            record.updated_at,
            record.approver,
            record.decision_signature,
            json.dumps(record.decision_history or [], ensure_ascii=True),
            record.version,
        )
        try:
            with self._connect() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, values)
                conn.commit()
        except Exception as exc:
            message = str(exc).lower()
            if "duplicate key" in message or "unique" in message:
                raise ValueError(f"approval_id_conflict:{record.approval_id}") from exc
            raise
        return _copy_record(record)

    def update_if_version(self, record: ApprovalRecord, expected_version: int) -> bool:
        query = (
            f"UPDATE {self.table} SET "
            "target=%s, command=%s, risk_level=%s, requested_by=%s, status=%s, created_at=%s, updated_at=%s, "
            "approver=%s, decision_signature=%s, decision_history=%s::jsonb, version=%s "
            "WHERE approval_id=%s AND version=%s"
        )
        values = (
            record.target,
            record.command,
            record.risk_level,
            record.requested_by,
            record.status,
            record.created_at,
            record.updated_at,
            record.approver,
            record.decision_signature,
            json.dumps(record.decision_history or [], ensure_ascii=True),
            record.version,
            record.approval_id,
            max(int(expected_version), 0),
        )
        with self._connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
                rowcount = int(cursor.rowcount)
            conn.commit()
        return rowcount == 1

    def _connect(self) -> Any:
        if self._driver == "psycopg":
            import psycopg  # type: ignore

            return psycopg.connect(self.dsn)
        import psycopg2  # type: ignore

        return psycopg2.connect(self.dsn)

    def _ensure_schema(self) -> None:
        create_sql = (
            f"CREATE TABLE IF NOT EXISTS {self.table} ("
            "approval_id TEXT PRIMARY KEY,"
            "target TEXT NOT NULL,"
            "command TEXT NOT NULL,"
            "risk_level TEXT NOT NULL,"
            "requested_by TEXT NOT NULL,"
            "status TEXT NOT NULL,"
            "created_at TEXT NOT NULL,"
            "updated_at TEXT NOT NULL,"
            "approver TEXT,"
            "decision_signature TEXT,"
            "decision_history JSONB NOT NULL DEFAULT '[]'::jsonb,"
            "version INTEGER NOT NULL DEFAULT 1"
            ")"
        )
        index_sql = f"CREATE INDEX IF NOT EXISTS idx_{self.table}_status ON {self.table}(status)"
        alter_version_sql = f"ALTER TABLE {self.table} ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1"
        fix_version_sql = f"UPDATE {self.table} SET version=1 WHERE version IS NULL OR version < 1"
        with self._connect() as conn:
            with conn.cursor() as cursor:
                cursor.execute(create_sql)
                cursor.execute(index_sql)
                cursor.execute(alter_version_sql)
                cursor.execute(fix_version_sql)
            conn.commit()

    @staticmethod
    def _row_to_record(row: Any) -> ApprovalRecord | None:
        if row is None:
            return None
        return _parse_record(
            {
                "approval_id": row[0],
                "target": row[1],
                "command": row[2],
                "risk_level": row[3],
                "requested_by": row[4],
                "status": row[5],
                "created_at": row[6],
                "updated_at": row[7],
                "approver": row[8],
                "decision_signature": row[9],
                "decision_history": _load_history(row[10]),
                "version": row[11],
            }
        )


class ApprovalStore:
    def __init__(
        self,
        signing_key: str = "dev-approval-signing-key",
        storage_path: str | None = None,
        backend: str | None = None,
        sqlite_path: str | None = None,
        postgres_dsn: str | None = None,
        postgres_table: str = "approval_records",
    ) -> None:
        self.signing_key = signing_key
        backend_name = str(backend or ("file" if storage_path else "memory")).strip().lower()
        self._backend = _build_backend(
            backend=backend_name,
            storage_path=storage_path,
            sqlite_path=sqlite_path,
            postgres_dsn=postgres_dsn,
            table=postgres_table,
        )

    def create(self, target: str, command: str, risk_level: str, requested_by: str) -> ApprovalRecord:
        now = _utc_now()
        record = ApprovalRecord(
            approval_id=str(uuid4()),
            target=target,
            command=command,
            risk_level=risk_level,
            requested_by=requested_by,
            status="pending",
            created_at=now,
            updated_at=now,
            decision_history=[],
            version=1,
        )
        return self._backend.create(record)

    def get(self, approval_id: str) -> ApprovalRecord | None:
        return self._backend.get(approval_id)

    def decide(self, approval_id: str, status: ApprovalStatus, approver: str) -> ApprovalRecord | None:
        record, _ = self.decide_with_result(
            approval_id=approval_id,
            status=status,
            approver=approver,
        )
        return record

    def decide_with_result(
        self,
        *,
        approval_id: str,
        status: ApprovalStatus,
        approver: str,
    ) -> tuple[ApprovalRecord | None, bool]:
        retries = 3
        for _ in range(retries):
            record = self._backend.get(approval_id)
            if record is None:
                return None, False
            if record.status != "pending":
                return record, False
            decided_at = _utc_now()
            signature = self._sign_decision(
                approval_id=record.approval_id,
                status=status,
                approver=approver,
                decided_at=decided_at,
            )
            history = list(record.decision_history or [])
            history.append(
                {
                    "status": status,
                    "approver": approver,
                    "decided_at": decided_at,
                    "signature": signature,
                }
            )
            updated = ApprovalRecord(
                approval_id=record.approval_id,
                target=record.target,
                command=record.command,
                risk_level=record.risk_level,
                requested_by=record.requested_by,
                status=status,
                created_at=record.created_at,
                updated_at=decided_at,
                approver=approver,
                decision_signature=signature,
                decision_history=history,
                version=record.version + 1,
            )
            if self._backend.update_if_version(updated, expected_version=record.version):
                return updated, True
        return self._backend.get(approval_id), False

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        return self._backend.list(status=status)

    def _sign_decision(
        self,
        *,
        approval_id: str,
        status: ApprovalStatus,
        approver: str,
        decided_at: str,
    ) -> str:
        raw = f"{approval_id}|{status}|{approver}|{decided_at}|{self.signing_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_backend(
    *,
    backend: str,
    storage_path: str | None,
    sqlite_path: str | None,
    postgres_dsn: str | None,
    table: str,
) -> ApprovalPersistenceBackend:
    if backend in {"memory", "in_memory", "none"}:
        return InMemoryApprovalBackend()
    if backend == "file":
        return FileApprovalBackend(path=storage_path)
    if backend == "sqlite":
        return SQLiteApprovalBackend(db_path=str(sqlite_path or ""), table=table)
    if backend == "postgres":
        return PostgresApprovalBackend(dsn=str(postgres_dsn or ""), table=table)
    raise ValueError(f"unsupported_approval_store_backend:{backend}")


def _resolve_postgres_driver() -> str:
    try:
        import psycopg  # type: ignore # noqa: F401

        return "psycopg"
    except Exception:
        pass
    try:
        import psycopg2  # type: ignore # noqa: F401

        return "psycopg2"
    except Exception as exc:
        raise ValueError("postgres_driver_missing:install_psycopg_or_psycopg2") from exc


def _normalize_identifier(value: str, *, default: str) -> str:
    candidate = str(value).strip() or default
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
        return default
    return candidate


def _dump_history(history: list[dict[str, str]] | None) -> str:
    return json.dumps(history or [], ensure_ascii=True)


def _load_history(value: Any) -> list[dict[str, str]]:
    if isinstance(value, list):
        result: list[dict[str, str]] = []
        for item in value:
            if isinstance(item, dict):
                result.append({str(k): str(v) for k, v in item.items()})
        return result
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            result = []
            for item in parsed:
                if isinstance(item, dict):
                    result.append({str(k): str(v) for k, v in item.items()})
            return result
    return []


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def get_approval_store() -> ApprovalStore:
    signing_key = get_rbac_settings().approval_signing_key
    settings = get_settings()
    security = settings.get("security", {})
    store_cfg_raw = security.get("approval_store", {})
    store_cfg = store_cfg_raw if isinstance(store_cfg_raw, dict) else {}
    storage = settings.get("storage", {})

    file_path = str(
        store_cfg.get(
            "file_path",
            security.get("approval_store_path", "workflow/approvals/approvals.jsonl"),
        )
    )
    backend = str(store_cfg.get("backend", "file")).strip().lower()
    sqlite_path = str(store_cfg.get("sqlite_path", "workflow/approvals/approvals.db"))
    postgres_dsn = str(store_cfg.get("postgres_dsn", storage.get("postgres_dsn", "")))
    store_table = str(store_cfg.get("table", store_cfg.get("postgres_table", "approval_records")))

    return ApprovalStore(
        signing_key=signing_key,
        backend=backend,
        storage_path=file_path,
        sqlite_path=sqlite_path,
        postgres_dsn=postgres_dsn,
        postgres_table=store_table,
    )


def clear_approval_store() -> None:
    get_approval_store.cache_clear()


def _parse_record(raw: Any) -> ApprovalRecord | None:
    if not isinstance(raw, dict):
        return None
    approval_id = str(raw.get("approval_id", "")).strip()
    target = str(raw.get("target", "")).strip()
    command = str(raw.get("command", "")).strip()
    risk_level = str(raw.get("risk_level", "")).strip()
    requested_by = str(raw.get("requested_by", "")).strip()
    status = str(raw.get("status", "")).strip()
    created_at = str(raw.get("created_at", "")).strip()
    updated_at = str(raw.get("updated_at", "")).strip()
    if status not in {"pending", "approved", "rejected"}:
        return None
    if not approval_id or not target or not command or not risk_level or not requested_by:
        return None
    if not created_at or not updated_at:
        return None
    history = _load_history(raw.get("decision_history", []))
    version = max(_to_int(raw.get("version", 1), default=1), 1)
    return ApprovalRecord(
        approval_id=approval_id,
        target=target,
        command=command,
        risk_level=risk_level,
        requested_by=requested_by,
        status=status,
        created_at=created_at,
        updated_at=updated_at,
        approver=str(raw.get("approver")) if raw.get("approver") is not None else None,
        decision_signature=str(raw.get("decision_signature")) if raw.get("decision_signature") is not None else None,
        decision_history=history,
        version=version,
    )


def _copy_record(record: ApprovalRecord) -> ApprovalRecord:
    return ApprovalRecord(**record.to_dict())


def _to_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default
