import json
from datetime import UTC, datetime
from typing import Any

from app.parsers.base import BaseParser, LogParseError
from app.schemas import NormalizedEvent


class WindowsJsonParser(BaseParser):
    def parse_text(self, content: str) -> list[NormalizedEvent]:
        records = _load_records(content)
        events: list[NormalizedEvent] = []
        for record in records:
            event = _normalize_record(record)
            if event:
                events.append(event)
        return events


def _load_records(content: str) -> list[dict[str, Any]]:
    content = content.strip()
    if not content:
        return []
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LogParseError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
            if isinstance(item, dict):
                records.append(item)
        return records
    raise LogParseError("Windows JSON input must be an object, array, or newline-delimited JSON")


def _normalize_record(record: dict[str, Any]) -> NormalizedEvent | None:
    event_id = _as_int(
        _first(record, "EventID", "event_id", "Id", "System.EventID", "winlog.event_id")
    )
    if event_id is None:
        return None

    event_data = _first(record, "EventData", "event_data", "Properties", "winlog.event_data")
    if not isinstance(event_data, dict):
        event_data = {}

    timestamp = _parse_timestamp(
        _first(
            record,
            "TimeCreated",
            "timestamp",
            "@timestamp",
            "System.TimeCreated.SystemTime",
            "winlog.time_created",
        )
    )
    hostname = _string(_first(record, "Computer", "computer", "host.name", "winlog.computer_name"))
    username = _string(
        _first(event_data, "TargetUserName", "SubjectUserName", "AccountName", "User")
        or _first(record, "TargetUserName", "SubjectUserName", "user.name")
    )
    src_ip = _string(
        _first(event_data, "IpAddress", "SourceNetworkAddress", "ClientAddress")
        or _first(record, "IpAddress", "source.ip")
    )
    process = _string(
        _first(event_data, "NewProcessName", "ProcessName", "ImagePath", "ServiceFileName")
        or _first(record, "NewProcessName", "process.executable", "process.name")
    )
    command_line = _string(
        _first(event_data, "CommandLine", "ProcessCommandLine")
        or _first(record, "CommandLine", "process.command_line")
    )

    event_type = {
        4624: "auth_success",
        4625: "auth_failure",
        4672: "privileged_logon",
        4688: "process_started",
        4720: "user_created",
        7045: "service_created",
    }.get(event_id, "windows_event")

    return NormalizedEvent(
        timestamp=timestamp,
        source="windows_event_log",
        event_type=event_type,
        event_id=event_id,
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        process=process,
        command_line=command_line,
        raw=record,
        details=event_data,
    )


def _first(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, dict):
        value = value.get("SystemTime") or value.get("system_time")
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)
