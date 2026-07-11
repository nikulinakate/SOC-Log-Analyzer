import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from app.parsers.base import BaseParser, LogParseError
from app.parsers.windows_json import _normalize_record
from app.schemas import NormalizedEvent


class WindowsEvtxParser(BaseParser):
    def parse_text(self, content: str) -> list[NormalizedEvent]:
        raise LogParseError(
            "EVTX is a binary format; upload the .evtx file to /api/v1/analyze/file"
        )

    def parse_bytes(self, content: bytes) -> list[NormalizedEvent]:
        try:
            from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - dependency is installed in normal builds
            raise LogParseError("python-evtx is required for EVTX analysis") from exc

        with tempfile.TemporaryDirectory(prefix="soc-evtx-") as temp_dir:
            path = Path(temp_dir) / "events.evtx"
            path.write_bytes(content)
            events: list[NormalizedEvent] = []
            try:
                with Evtx(str(path)) as log:
                    for record in log.records():
                        item = _xml_to_record(record.xml())
                        event = _normalize_record(item)
                        if event:
                            events.append(event)
            except Exception as exc:
                raise LogParseError(f"Unable to parse EVTX file: {exc}") from exc
            return events


def _xml_to_record(xml_content: str) -> dict:
    root = ET.fromstring(xml_content)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", namespace)
    event_data_node = root.find("e:EventData", namespace)

    event_data: dict[str, str] = {}
    if event_data_node is not None:
        for node in event_data_node.findall("e:Data", namespace):
            name = node.attrib.get("Name")
            if name:
                event_data[name] = node.text or ""

    event_id = system.findtext("e:EventID", default="", namespaces=namespace) if system else ""
    computer = system.findtext("e:Computer", default="", namespaces=namespace) if system else ""
    time_node = system.find("e:TimeCreated", namespace) if system else None
    timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None

    return {
        "EventID": event_id,
        "Computer": computer,
        "TimeCreated": timestamp,
        "EventData": event_data,
    }
