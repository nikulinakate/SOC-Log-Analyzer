from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.parsers.base import LogParseError
from app.schemas import AnalysisReport, AnalyzeTextRequest, HealthResponse, SourceType
from app.service import AnalysisService

router = APIRouter()
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", service=get_settings().app_name)


@router.post("/api/v1/analyze/text", response_model=AnalysisReport, tags=["analysis"])
def analyze_text(payload: AnalyzeTextRequest, db: DbSession) -> AnalysisReport:
    if payload.source_type == SourceType.WINDOWS_EVTX:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="EVTX is binary; use /api/v1/analyze/file",
        )
    try:
        return AnalysisService(db).analyze_text(
            payload.source_type, payload.content, payload.persist
        )
    except LogParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/analyze/file", response_model=AnalysisReport, tags=["analysis"])
async def analyze_file(
    db: DbSession,
    source_type: Annotated[SourceType, Query()],
    file: Annotated[UploadFile, File()],
    persist: Annotated[bool, Query()] = True,
) -> AnalysisReport:
    content = await file.read()
    if len(content) > get_settings().max_upload_bytes:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds configured size limit")
    try:
        return AnalysisService(db).analyze_bytes(source_type, content, persist)
    except LogParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/api/v1/reports", response_model=list[AnalysisReport], tags=["reports"])
def list_reports(
    db: DbSession, limit: int = Query(default=20, ge=1, le=100)
) -> list[AnalysisReport]:
    return AnalysisService(db).list_reports(limit)


@router.get("/api/v1/reports/{report_id}", response_model=AnalysisReport, tags=["reports"])
def get_report(report_id: str, db: DbSession) -> AnalysisReport:
    report = AnalysisService(db).get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
