# Evidence Schema (P0-4)

## Purpose

Provide reproducible, traceable, and measurable audit artifacts for each security action decision.

## Audit Event Fields

- `event_id`: unique audit event id
- `timestamp`: UTC ISO-8601 timestamp
- `trace_id`: end-to-end correlation id
- `task_id`: workflow task id
- `agent_id`: executing agent or API component id
- `operator`: user/service account who triggered the action
- `action`: logical action name (`validate_action`, `approval_decision`, etc.)
- `target`: tested target identifier (IP/host/domain/API id)
- `tool`: tool or control point (`scope_guard`, `action_gate`, `nmap`, etc.)
- `decision`: `allowed`, `blocked`, `pending_approval`, `approved`, `rejected`
- `reason`: normalized decision reason code
- `input_hash`: SHA-256 hash of normalized input payload
- `output_hash`: SHA-256 hash of normalized output payload
- `evidence_dir`: physical directory path of evidence artifacts
- `metadata`: additional structured key-value context

## Evidence Directory Layout

```text
<evidence_root>/
  audit-events.jsonl
  <YYYY-MM-DD>/
    <trace_id>/
      <event_id>/
        event.json
        input.json
        output.json
        raw_output.txt            # optional
        attachments/              # optional
          <file1>
          <file2>
```

## Integrity Rules

1. `input_hash` must be SHA-256 over canonical JSON of `input.json`.
2. `output_hash` must be SHA-256 over canonical JSON of `output.json`.
3. `event.json` must include all required fields listed above.

## Current Integration Points

- `POST /actions/validate`
  - records scope blocked, action blocked/pending, and action allowed decisions
- `POST /approvals/{approval_id}/decision`
  - records approval state transitions
- `GET /audit/events?trace_id=<id>` or `?task_id=<id>`
  - retrieves indexed audit events with pagination (`limit`, `offset`)
