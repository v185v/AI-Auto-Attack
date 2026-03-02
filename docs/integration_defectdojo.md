# DefectDojo Integration (P4-1)

## Goal

Synchronize workflow findings to DefectDojo for lifecycle tracking and remediation closure.

## Current Integration Scope

- Automatic import after report generation (`build_report` stage).
- Upload endpoint: `POST /api/v2/import-scan/`.
- Optional finding lifecycle update helper:
  - `PATCH /api/v2/findings/{id}/`
  - supported statuses: `new`, `fixed`, `retest_failed`, `closed`.

## Configuration

Configure in `settings.yaml`:

```yaml
integrations:
  defectdojo:
    enabled: true
    base_url: "https://defectdojo.example.com"
    api_token: "your_token"
    engagement_id: 123
    scan_type: "Generic Findings Import"
    minimum_severity: "Low"
    verify_ssl: true
    timeout_seconds: 30
    default_tags:
      - ai-attack
      - auto-pentest
```

## Runtime Behavior

During `build_report`:

1. Generate report artifacts (`json`, `md`, optional `pdf`).
2. Upload report JSON to DefectDojo import API.
3. Persist sync result into workflow state:
   - `defectdojo_sync`
4. Record audit event:
   - `action=workflow_sync_defectdojo`
   - `tool=defectdojo_connector`

When integration is disabled:

- workflow continues normally
- `defectdojo_sync.status=skipped`
- audit event still records skip reason for traceability

## Evidence Fields

- workflow state:
  - `defectdojo_sync.status`
  - `defectdojo_sync.http_status`
  - `defectdojo_sync.import_id` (if returned)
- report payload:
  - `integrations.defectdojo`

## Notes

- `engagement_id` must exist in DefectDojo.
- API token requires permission for import and finding update.
- For strict environments, keep `verify_ssl=true` and use trusted certificates.
