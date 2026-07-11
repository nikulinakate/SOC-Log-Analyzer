from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SourceType(StrEnum):
    LINUX_AUTH = "linux_auth"
    WINDOWS_JSON = "windows_json"
    WINDOWS_EVTX = "windows_evtx"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    raw: str | dict[str, Any]
    username: str | None = None
    src_ip: str | None = None
    hostname: str | None = None
    process: str | None = None
    command_line: str | None = None
    event_id: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    timestamp: datetime
    summary: str


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    description: str
    event_count: int
    mitre_attack: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_type: SourceType
    event_count: int
    finding_count: int
    highest_severity: Severity
    findings: list[Finding]
    event_type_counts: dict[str, int]


class AnalyzeTextRequest(BaseModel):
    source_type: SourceType
    content: str = Field(min_length=1)
    persist: bool = True


class HealthResponse(BaseModel):
    status: str
    service: str
