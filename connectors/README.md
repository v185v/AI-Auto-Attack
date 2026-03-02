# Connectors

This directory contains adapters for security tools.

Each connector should expose a consistent interface:
- `prepare()`
- `run()`
- `parse()`
- `validate()`

Current connectors:
- `nmap_connector.py`
- `nuclei_connector.py`
- `zap_connector.py`
- `defectdojo_connector.py` (vulnerability management platform integration)

Orchestration:
- `scan_orchestrator.py` executes connectors with ActionGate enforcement and unified result schema.
