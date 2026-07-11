from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import PurePath

from app.config import Settings, get_settings
from app.schemas import Evidence, Finding, NormalizedEvent, Severity

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SUSPICIOUS_PROCESS_MARKERS = {
    "powershell.exe": "PowerShell execution",
    "pwsh.exe": "PowerShell execution",
    "certutil.exe": "Certificate utility often abused for file transfer",
    "mshta.exe": "HTML application host execution",
    "rundll32.exe": "DLL execution through rundll32",
    "regsvr32.exe": "DLL registration utility execution",
    "wmic.exe": "WMI command-line execution",
    "bitsadmin.exe": "BITS transfer utility execution",
    "procdump.exe": "Process memory dumping utility execution",
    "mimikatz.exe": "Credential dumping tool execution",
}


class DetectionEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def analyze(self, events: list[NormalizedEvent]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_failed_login_bursts(events))
        findings.extend(self._detect_new_users(events))
        findings.extend(self._detect_sudo(events))
        findings.extend(self._detect_suspicious_processes(events))
        findings.extend(self._detect_service_creation(events))
        return sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)

    def event_type_counts(self, events: list[NormalizedEvent]) -> dict[str, int]:
        return dict(Counter(event.event_type for event in events))

    def _detect_failed_login_bursts(self, events: list[NormalizedEvent]) -> list[Finding]:
        grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.event_type != "auth_failure":
                continue
            key = (event.src_ip or "unknown-ip", event.username or "unknown-user")
            grouped[key].append(event)

        findings: list[Finding] = []
        window = timedelta(minutes=self.settings.failed_login_window_minutes)
        for (src_ip, username), candidates in grouped.items():
            burst = _largest_window(candidates, window)
            if len(burst) < self.settings.failed_login_threshold:
                continue
            protocol = burst[0].details.get("protocol")
            is_ssh = protocol == "ssh"
            findings.append(
                Finding(
                    rule_id="SOC-AUTH-001" if is_ssh else "SOC-AUTH-002",
                    title="Possible SSH brute-force attack" if is_ssh else "Failed login burst",
                    severity=Severity.HIGH,
                    description=(
                        f"Detected {len(burst)} failed authentication attempts for user "
                        f"'{username}' from source '{src_ip}' within "
                        f"{self.settings.failed_login_window_minutes} minutes."
                    ),
                    event_count=len(burst),
                    mitre_attack=["T1110 - Brute Force"],
                    evidence=_evidence(burst),
                )
            )
        return findings

    def _detect_new_users(self, events: list[NormalizedEvent]) -> list[Finding]:
        selected = [event for event in events if event.event_type == "user_created"]
        if not selected:
            return []
        return [
            Finding(
                rule_id="SOC-ACCOUNT-001",
                title="New local user account created",
                severity=Severity.MEDIUM,
                description=(
                    f"Observed {len(selected)} account creation event(s). Validate authorization."
                ),
                event_count=len(selected),
                mitre_attack=["T1136 - Create Account"],
                evidence=_evidence(selected),
            )
        ]

    def _detect_sudo(self, events: list[NormalizedEvent]) -> list[Finding]:
        selected = [event for event in events if event.event_type == "sudo_command"]
        if not selected:
            return []
        return [
            Finding(
                rule_id="SOC-PRIV-001",
                title="Privileged command executed with sudo",
                severity=Severity.LOW,
                description=(
                    f"Observed {len(selected)} sudo command(s); review user and command context."
                ),
                event_count=len(selected),
                mitre_attack=["T1548.003 - Sudo and Sudo Caching"],
                evidence=_evidence(selected),
            )
        ]

    def _detect_suspicious_processes(self, events: list[NormalizedEvent]) -> list[Finding]:
        selected: list[NormalizedEvent] = []
        reasons: set[str] = set()
        for event in events:
            if event.event_type != "process_started":
                continue
            process_name = PurePath((event.process or "").replace("\\", "/")).name.lower()
            command = (event.command_line or "").lower()
            if process_name in SUSPICIOUS_PROCESS_MARKERS:
                selected.append(event)
                reasons.add(SUSPICIOUS_PROCESS_MARKERS[process_name])
            elif "powershell" in command and any(
                marker in command for marker in ("-enc", "encodedcommand")
            ):
                selected.append(event)
                reasons.add("Encoded PowerShell command")

        if not selected:
            return []
        severity = (
            Severity.CRITICAL
            if any("mimikatz" in (e.process or "").lower() for e in selected)
            else Severity.HIGH
        )
        return [
            Finding(
                rule_id="SOC-PROC-001",
                title="Suspicious process execution",
                severity=severity,
                description="; ".join(sorted(reasons)),
                event_count=len(selected),
                mitre_attack=[
                    "T1059 - Command and Scripting Interpreter",
                    "T1218 - System Binary Proxy Execution",
                ],
                evidence=_evidence(selected),
            )
        ]

    def _detect_service_creation(self, events: list[NormalizedEvent]) -> list[Finding]:
        selected = [event for event in events if event.event_type == "service_created"]
        if not selected:
            return []
        return [
            Finding(
                rule_id="SOC-PERSIST-001",
                title="Windows service created",
                severity=Severity.HIGH,
                description="A new Windows service can indicate persistence or remote execution.",
                event_count=len(selected),
                mitre_attack=["T1543.003 - Windows Service"],
                evidence=_evidence(selected),
            )
        ]


def highest_severity(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.INFO
    return max((item.severity for item in findings), key=SEVERITY_ORDER.get)


def _largest_window(events: list[NormalizedEvent], window: timedelta) -> list[NormalizedEvent]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    best: list[NormalizedEvent] = []
    left = 0
    for right, event in enumerate(ordered):
        while event.timestamp - ordered[left].timestamp > window:
            left += 1
        current = ordered[left : right + 1]
        if len(current) > len(best):
            best = current
    return best


def _evidence(events: list[NormalizedEvent], limit: int = 5) -> list[Evidence]:
    result: list[Evidence] = []
    for event in events[:limit]:
        parts = [event.event_type]
        if event.username:
            parts.append(f"user={event.username}")
        if event.src_ip:
            parts.append(f"src_ip={event.src_ip}")
        if event.process:
            parts.append(f"process={event.process}")
        if event.command_line:
            parts.append(f"command={event.command_line[:160]}")
        result.append(Evidence(timestamp=event.timestamp, summary=" | ".join(parts)))
    return result
