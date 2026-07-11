# Architecture

```text
Linux auth.log ─┐
Windows JSON ───┼─> Parser adapters ─> NormalizedEvent[] ─> DetectionEngine
Windows EVTX ───┘                                      │
                                                       v
                                              AnalysisReport
                                                       │
                                 ┌─────────────────────┴─────────────────────┐
                                 v                                           v
                           REST response                              SQLite/PostgreSQL
```

## Design decisions

- **Parser adapters** isolate source-specific formats from detection logic.
- **Normalized events** provide one internal schema for Linux and Windows telemetry.
- **Rule-based correlation** keeps detections explainable: every finding contains evidence and a stable rule ID.
- **Storage abstraction through SQLAlchemy** allows local SQLite development and PostgreSQL deployment.
- **Stateless API plus persisted reports** makes the service easy to integrate into a lab, SOAR workflow, or analyst toolkit.

## Security boundaries

This is a defensive portfolio/lab project. Uploaded files are processed locally and are not executed. EVTX files are written to a temporary directory only for parsing. Production hardening should add authentication, tenant isolation, malware scanning, retention controls, rate limits, and object storage.
