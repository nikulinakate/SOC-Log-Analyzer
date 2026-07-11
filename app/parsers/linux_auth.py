import re
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas import NormalizedEvent

ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
)
SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)"
)
FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$")
NEW_USER = re.compile(r"(?:useradd|adduser)(?:\[\d+\])?:.*new user: name=(?P<user>[^,\s]+)")
PAM_FAILURE = re.compile(r"authentication failure;.*(?:user=|ruser=)(?P<user>\S*)")


class LinuxAuthParser(BaseParser):
    def parse_text(self, content: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            event = self._parse_line(line)
            if event:
                events.append(event)
        return events

    def _parse_line(self, line: str) -> NormalizedEvent | None:
        timestamp, hostname = _parse_prefix(line)

        if match := FAILED_SSH.search(line):
            return NormalizedEvent(
                timestamp=timestamp,
                source="linux_auth",
                event_type="auth_failure",
                username=match.group("user"),
                src_ip=match.group("ip"),
                hostname=hostname,
                raw=line,
                details={"protocol": "ssh"},
            )

        if match := ACCEPTED_SSH.search(line):
            return NormalizedEvent(
                timestamp=timestamp,
                source="linux_auth",
                event_type="auth_success",
                username=match.group("user"),
                src_ip=match.group("ip"),
                hostname=hostname,
                raw=line,
                details={"protocol": "ssh"},
            )

        if match := NEW_USER.search(line):
            return NormalizedEvent(
                timestamp=timestamp,
                source="linux_auth",
                event_type="user_created",
                username=match.group("user"),
                hostname=hostname,
                raw=line,
            )

        if match := SUDO.search(line):
            command = match.group("command").strip()
            return NormalizedEvent(
                timestamp=timestamp,
                source="linux_auth",
                event_type="sudo_command",
                username=match.group("user"),
                hostname=hostname,
                process="sudo",
                command_line=command,
                raw=line,
            )

        if "authentication failure" in line and (match := PAM_FAILURE.search(line)):
            return NormalizedEvent(
                timestamp=timestamp,
                source="linux_auth",
                event_type="auth_failure",
                username=match.group("user") or None,
                hostname=hostname,
                raw=line,
                details={"protocol": "pam"},
            )

        return None


def _parse_prefix(line: str) -> tuple[datetime, str | None]:
    if match := ISO_PREFIX.match(line):
        value = match.group("ts").replace("Z", "+00:00")
        return datetime.fromisoformat(value), None

    if match := SYSLOG_PREFIX.match(line):
        now = datetime.now(UTC)
        parsed = datetime.strptime(
            f"{now.year} {match.group('month')} {match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=UTC)
        return parsed, match.group("host")

    return datetime.now(UTC), None
