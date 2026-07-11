# SOC Log Analyzer

[![CI](https://github.com/nikulinakate/SOC-Log-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/nikulinakate/SOC-Log-Analyzer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Defensive SOC portfolio project:** ingests Linux authentication logs and Windows Event Logs, normalizes security events, correlates suspicious activity, and returns an explainable analyst report through a REST API.

The project is designed to demonstrate practical skills relevant to **SOC analyst, information security, security automation, and antifraud engineering** roles: log parsing, event normalization, detection logic, MITRE ATT&CK mapping, API design, persistence, tests, Docker, and CI.

> Status: portfolio/lab MVP. It is not a replacement for a production SIEM.

## What it detects

| Detection | Data source | Severity | MITRE ATT&CK |
|---|---|---:|---|
| SSH brute-force burst | Linux `auth.log` / `secure` | High | T1110 |
| Repeated failed logins | Linux / Windows 4625 | High | T1110 |
| New user account | Linux `useradd`, Windows 4720 | Medium | T1136 |
| Privileged command via sudo | Linux | Low | T1548.003 |
| Suspicious process / LOLBin | Windows 4688 | High/Critical | T1059, T1218 |
| New Windows service | Windows 7045 | High | T1543.003 |

Each finding contains a stable rule ID, severity, description, event count, ATT&CK mapping, and evidence suitable for analyst review.

## Supported inputs

- Linux authentication logs: `/var/log/auth.log`, `/var/log/secure`, copied text, or uploaded file.
- Windows Event Log exported as JSON or NDJSON.
- Native binary `.evtx` upload through `python-evtx`.

A PowerShell converter is included so EventData field names are preserved:

```powershell
.\scripts\export_windows_events.ps1 `
  -Path .\Security.evtx `
  -Output .\security-events.json
```

## Architecture

```text
Log files -> source parsers -> normalized events -> correlation rules -> findings/report
                                                        |
                                             SQLite or PostgreSQL
```

See [architecture details](docs/architecture.md) and the [detection catalog](docs/detection-rules.md).

## Quick start with Docker

```bash
git clone https://github.com/nikulinakate/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
docker compose up --build
```

Open Swagger UI at `http://localhost:8000/docs` and health check at `http://localhost:8000/health`.

Run sample analyses:

```bash
make demo-linux
make demo-windows
```

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

SQLite is used by default. To run PostgreSQL, use Docker Compose or set:

```bash
export SOC_DATABASE_URL='postgresql+psycopg://soc:soc@localhost:5432/soc'
```

## REST API

### Analyze text

```bash
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H 'Content-Type: application/json' \
  -d '{
    "source_type": "linux_auth",
    "persist": true,
    "content": "2026-07-11T10:00:00Z sshd[1]: Failed password for admin from 203.0.113.10 port 50001 ssh2"
  }'
```

### Analyze a file

```bash
curl -X POST 'http://localhost:8000/api/v1/analyze/file?source_type=windows_evtx' \
  -F 'file=@Security.evtx'
```

### Example finding

```json
{
  "rule_id": "SOC-AUTH-001",
  "title": "Possible SSH brute-force attack",
  "severity": "high",
  "description": "Detected 5 failed authentication attempts for user 'admin' from source '203.0.113.10' within 5 minutes.",
  "event_count": 5,
  "mitre_attack": ["T1110 - Brute Force"],
  "evidence": [
    {
      "timestamp": "2026-07-11T10:00:00Z",
      "summary": "auth_failure | user=admin | src_ip=203.0.113.10"
    }
  ]
}
```

## Quality controls

```bash
make test   # pytest + coverage
make lint   # Ruff + mypy
```

GitHub Actions runs linting and tests on every pull request. Sample log files are synthetic and use documentation-only IP ranges.

## Roadmap

- Sigma rule import/export.
- GeoIP and threat-intelligence enrichment.
- Detection of impossible travel and account takeover patterns for antifraud scenarios.
- Analyst dashboard and report export to JSON/PDF.
- Kafka/Redis queue for streaming ingestion.
- Authentication, RBAC, audit logging, and retention policies.

## Ethical use

This repository is intended for defensive monitoring, education, and authorized security analysis. Do not upload confidential production telemetry to public environments.
