"""
로그 업로드 API
POST /upload-log
- CloudTrail JSON 파일 업로드 → 파싱 → DB 저장 → session_id 반환
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.database.db import AnalysisSession, get_db
from app.models.schemas import UploadResponse
from app.services.parser import parse_raw_json

router = APIRouter()


@router.post("/upload-log", response_model=UploadResponse, tags=["로그 관리"])
async def upload_log(
    file: UploadFile = File(..., description="CloudTrail JSON 로그 파일"),
    db: Session = Depends(get_db),
):
    """
    CloudTrail JSON 로그 파일 업로드.

    - 파일 형식: `{"Records": [...]}` 또는 이벤트 배열 JSON
    - 반환: 분석 session_id (이후 /detect, /risk-summary에서 사용)
    """
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="JSON 파일만 업로드 가능합니다.")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB 제한
        raise HTTPException(status_code=413, detail="파일 크기가 50MB를 초과합니다.")

    try:
        events = parse_raw_json(content)
    except (ValueError, Exception) as e:
        raise HTTPException(status_code=422, detail=f"로그 파싱 실패: {str(e)}")

    if not events:
        raise HTTPException(status_code=400, detail="파싱된 이벤트가 없습니다.")

    unique_users = len({e.user_arn for e in events})
    session_id = str(uuid.uuid4())

    session = AnalysisSession(
        id=session_id,
        total_events=len(events),
        unique_users=unique_users,
        status="pending",
    )
    db.add(session)
    db.commit()

    # 세션에 이벤트 캐시 (메모리, 실제 운영 시 Redis 또는 DB 전환)
    from app.core.session_store import session_store
    session_store[session_id] = events

    return UploadResponse(
        session_id=session_id,
        total_events=len(events),
        unique_users=unique_users,
        message=f"로그 {len(events)}건 업로드 완료. session_id로 탐지를 시작하세요.",
    )
