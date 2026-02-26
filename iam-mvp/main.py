"""
IAM Anomaly Detection MVP
- POST /detect : CloudTrail JSON 파일 업로드 → 사용자별 이상탐지 결과
- DB 없음 / 세션 없음 / 완전 stateless
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, UploadFile, File

import parser as ct_parser
import detector

app = FastAPI(
    title="IAM Anomaly Detection MVP",
    version="0.1.0",
)


@app.post("/detect")
async def detect(file: UploadFile = File(..., description="CloudTrail JSON 파일")):
    """
    CloudTrail JSON 파일 업로드 → 사용자별 UEBA 이상탐지.

    반환: 사용자별 Risk Score + 탐지 근거 (점수 내림차순)
    """
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="JSON 파일만 업로드 가능합니다.")

    content = await file.read()

    try:
        events = ct_parser.parse(content)
    except (ValueError, Exception) as e:
        raise HTTPException(status_code=422, detail=f"파싱 실패: {e}")

    if not events:
        raise HTTPException(status_code=400, detail="파싱된 이벤트가 없습니다.")

    results = detector.detect(events)
    anomaly_count = sum(1 for r in results if r["is_anomaly"])

    return {
        "total_events":  len(events),
        "total_users":   len(results),
        "anomaly_count": anomaly_count,
        "results":       results,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
