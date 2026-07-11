from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import ReportRecord
from app.detection.engine import DetectionEngine, highest_severity
from app.parsers.base import BaseParser
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.windows_evtx import WindowsEvtxParser
from app.parsers.windows_json import WindowsJsonParser
from app.schemas import AnalysisReport, NormalizedEvent, SourceType

PARSERS: dict[SourceType, BaseParser] = {
    SourceType.LINUX_AUTH: LinuxAuthParser(),
    SourceType.WINDOWS_JSON: WindowsJsonParser(),
    SourceType.WINDOWS_EVTX: WindowsEvtxParser(),
}


class AnalysisService:
    def __init__(self, db: Session | None = None) -> None:
        self.db = db
        self.engine = DetectionEngine()

    def analyze_text(
        self, source_type: SourceType, content: str, persist: bool = True
    ) -> AnalysisReport:
        parser = PARSERS[source_type]
        events = parser.parse_text(content)
        return self._build_report(source_type, events, persist)

    def analyze_bytes(
        self, source_type: SourceType, content: bytes, persist: bool = True
    ) -> AnalysisReport:
        parser = PARSERS[source_type]
        events = parser.parse_bytes(content)
        return self._build_report(source_type, events, persist)

    def get_report(self, report_id: str) -> AnalysisReport | None:
        if self.db is None:
            return None
        record = self.db.get(ReportRecord, report_id)
        return AnalysisReport.model_validate(record.result_json) if record else None

    def list_reports(self, limit: int = 20) -> list[AnalysisReport]:
        if self.db is None:
            return []
        statement = select(ReportRecord).order_by(ReportRecord.created_at.desc()).limit(limit)
        return [
            AnalysisReport.model_validate(row.result_json) for row in self.db.scalars(statement)
        ]

    def _build_report(
        self, source_type: SourceType, events: list[NormalizedEvent], persist: bool
    ) -> AnalysisReport:
        findings = self.engine.analyze(events)
        report = AnalysisReport(
            source_type=source_type,
            event_count=len(events),
            finding_count=len(findings),
            highest_severity=highest_severity(findings),
            findings=findings,
            event_type_counts=self.engine.event_type_counts(events),
        )
        if persist and self.db is not None:
            record = ReportRecord(
                id=report.id,
                source_type=report.source_type.value,
                event_count=report.event_count,
                finding_count=report.finding_count,
                highest_severity=report.highest_severity.value,
                result_json=report.model_dump(mode="json"),
            )
            self.db.add(record)
            self.db.commit()
        return report
