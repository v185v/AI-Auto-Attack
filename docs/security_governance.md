# Security Governance (P5-1)

## Goal

Establish role-based access control (RBAC) and approval decision signatures for high-risk operations.

## Roles

- `admin`
  - full approval governance
  - can approve/reject pending high-risk actions
- `auditor`
  - read-only visibility for approval records
- `executor`
  - can request action validation and execute authorized tasks
  - cannot issue approval decisions

## Permission Matrix

| Permission | admin | auditor | executor |
|---|---|---|---|
| `actions:validate` | yes | no | yes |
| `approvals:read` | yes | yes | yes |
| `approvals:decide` | yes | no | no |

## Auth Headers

- user header: `X-Actor-Id`
- role header: `X-Role`

Role values:
- `admin`
- `auditor`
- `executor`
- alias `operator` maps to `executor`

## Config

`settings.yaml -> auth`:

```yaml
auth:
  enabled: true
  header_user: X-Actor-Id
  header_role: X-Role
  default_user: system
  default_role: executor
  enforce_headers: false
  approval_signing_key: dev-approval-signing-key
```

## Approval Signature

When a pending approval is decided, system stores:

- `decision_signature` (SHA-256)
- `decision_history[]` with:
  - status
  - approver
  - decided_at
  - signature

Signature input:

`approval_id | status | approver | decided_at | approval_signing_key`

## Approval Persistence Backend

Approval records can be persisted with configurable backend:

- `file` (JSON file, default)
- `sqlite` (single-node durable store)
- `postgres` (shared enterprise database)

`settings.yaml -> security.approval_store`:

```yaml
security:
  approval_store:
    backend: file
    file_path: workflow/approvals/approvals.jsonl
    sqlite_path: workflow/approvals/approvals.db
    postgres_dsn: ""
    table: approval_records
```

Notes:

- For `postgres`, install `psycopg` or `psycopg2`.
- Legacy `security.approval_store_path` is still accepted as default file path.
- Approval record includes `version` for optimistic locking.
- Decision update path uses `expected_version` compare-and-set semantics to prevent stale overwrite.

## API Behavior Notes

- Approval decision requires:
  - role with `approvals:decide` (`admin`)
  - payload approver must match actor id (`approver_actor_mismatch` if not)
- Unauthorized role receives:
  - HTTP `403`
  - reason: `permission_denied`
