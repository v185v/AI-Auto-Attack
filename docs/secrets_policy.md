# Secrets and Sensitive Data Policy (P5-2)

## Objective

Establish a minimum enterprise baseline for secret handling and sensitive data governance:
- central secret resolution interface,
- output redaction for audit/report artifacts,
- configurable retention cleanup for evidence and reports.

## Secret Management

Implemented module:
- `backend/security/secrets_manager.py`

Current provider:
- `env` (environment variables)

Configuration:
- `secrets.provider`
- `secrets.env_prefix`
- `secrets.env_mapping`

Default logical mappings:
- `defectdojo_api_token` -> `DEFECTDOJO_API_TOKEN`
- `approval_signing_key` -> `APPROVAL_SIGNING_KEY`

Integrated consumers:
- `connectors/defectdojo_connector.py`
- `backend/auth/rbac.py`

## Redaction Policy

Implemented module:
- `backend/security/redaction.py`

Redaction is applied at artifact write boundaries:
- audit evidence files (`input.json`, `output.json`, `raw_output.txt`, text attachments, metadata),
- generated reports (`reports/generator.py`),
- retest diff reports (`reports/diff_generator.py`).

Configuration:
- `security.redaction.enabled`
- `security.redaction.mask`
- `security.redaction.sensitive_keys`

Covered data classes:
- sensitive key/value fields (`token`, `api_key`, `password`, `secret`, etc.),
- bearer token strings,
- key-value secret strings,
- URL embedded credentials.

Note:
- Hashes (`input_hash`, `output_hash`) are computed from original payloads to preserve integrity checks.

## Retention Policy

Implemented module:
- `backend/audit/retention.py`

Retention scope:
- evidence root date folders,
- generated report date folders,
- diff report date folders.

Configuration:
- `audit.retention.enabled`
- `audit.retention.evidence_days`
- `audit.retention.reports_days`

Operational API:
- `POST /audit/retention/prune?dry_run=true|false`
- permission: `retention:prune` (admin only)

Behavior:
- `dry_run=true`: returns prune candidates without deleting files,
- `dry_run=false`: deletes folders older than configured windows.
