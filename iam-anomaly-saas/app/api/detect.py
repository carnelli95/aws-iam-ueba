"""
이상탐지 실행 API
POST /detect       → 탐지 수행 + DB 저장
GET  /risk-summary → 위험 계정 Top-N 반환
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.db import AnalysisSession, DetectionRecord, get_db
from app.models.schemas import (
    DetectRequest,
    DetectResponse,
    RULE_DESCRIPTIONS,
    RiskSummaryItem,
    RiskSummaryResponse,
    RuleViolation,
    UserDetectionResult,
)
from app.services.anomaly_engine import AnomalyEngine
from app.services.feature_engineer import extract_user_features
from app.services.risk_scoring import calculate_risk_score, rank_users

router = APIRouter()


@router.post("/detect", response_model=DetectResponse, tags=["탐지"])
def detect(
    req: DetectRequest,
    db: Session = Depends(get_db),
):
    """
    업로드된 로그에 대해 이상탐지 수행.

    - **session_id**: /upload-log에서 받은 세션 ID
    - **ml_enabled**: IsolationForest ML 탐지 활성화 여부 (기본 true)
    - **contamination**: ML 이상치 비율 추정값 (기본 0.10 = 10%)
    """
    from app.core.session_store import session_store

    events = session_store.get(req.session_id)
    if events is None:
        raise HTTPException(
            status_code=404,
            detail=f"session_id '{req.session_id}'를 찾을 수 없습니다. 먼저 /upload-log를 호출하세요.",
        )

    session = db.query(AnalysisSession).filter(
        AnalysisSession.id == req.session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션 정보가 DB에 없습니다.")

    # 1) 피처 추출
    features_list = extract_user_features(events)

    # 2) 이상탐지
    engine = AnomalyEngine(contamination=req.contamination if req.ml_enabled else 0.0)
    detection_results = engine.detect(features_list)

    # 3) Risk Score 계산
    features_map = {uf.user_arn: uf for uf in features_list}
    risk_scores = [
        calculate_risk_score(dr, features_map[dr.user_arn])
        for dr in detection_results
    ]

    # 4) DB 저장
    for dr, rs in zip(detection_results, risk_scores):
        record = DetectionRecord(
            session_id=req.session_id,
            user_arn=dr.user_arn,
            is_anomaly=dr.is_anomaly,
            risk_score=rs.score,
            risk_level=rs.level,
            detection_method=dr.detection_method,
        )
        record.set_json("triggered_rules", dr.triggered_rules)
        record.set_json("ml_anomaly_score", dr.ml_anomaly_score)
        record.set_json("score_breakdown", rs.score_breakdown)
        record.set_json("recommendations", rs.recommendations)
        record.set_json("details", dr.details)
        db.add(record)

    session.status = "completed"
    db.commit()

    # 5) 응답 구성
    results: list[UserDetectionResult] = []
    for dr, rs in zip(detection_results, risk_scores):
        rule_violations = [
            RuleViolation(
                rule_id=rule,
                description=RULE_DESCRIPTIONS.get(rule, rule),
            )
            for rule in dr.triggered_rules
        ]
        results.append(
            UserDetectionResult(
                user_arn=dr.user_arn,
                is_anomaly=dr.is_anomaly,
                risk_score=rs.score,
                risk_level=rs.level,
                detection_method=dr.detection_method,
                triggered_rules=rule_violations,
                ml_anomaly_score=dr.ml_anomaly_score,
                score_breakdown=rs.score_breakdown,
                recommendations=rs.recommendations,
                details=dr.details,
            )
        )

    anomaly_count = sum(1 for r in results if r.is_anomaly)
    return DetectResponse(
        session_id=req.session_id,
        total_users_analyzed=len(results),
        anomaly_count=anomaly_count,
        results=results,
    )


@router.get("/risk-summary", response_model=RiskSummaryResponse, tags=["탐지"])
def risk_summary(
    session_id: str = Query(..., description="분석 세션 ID"),
    top_n: int = Query(default=10, ge=1, le=100, description="상위 N명 반환"),
    db: Session = Depends(get_db),
):
    """
    위험 계정 Top-N 목록 반환.

    - 위험 점수 내림차순 정렬
    - 등급별 집계(CRITICAL/HIGH/MEDIUM/LOW) 포함
    """
    records = (
        db.query(DetectionRecord)
        .filter(DetectionRecord.session_id == session_id)
        .all()
    )
    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"session_id '{session_id}'에 대한 탐지 결과가 없습니다. 먼저 /detect를 호출하세요.",
        )

    # 점수 내림차순 정렬
    sorted_records = sorted(records, key=lambda r: r.risk_score, reverse=True)
    top_records = sorted_records[:top_n]

    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in records:
        level_counts[r.risk_level] = level_counts.get(r.risk_level, 0) + 1

    summary_items: list[RiskSummaryItem] = []
    for rank, rec in enumerate(top_records, start=1):
        triggered = rec.get_json("triggered_rules") or []
        recs_list = rec.get_json("recommendations") or []
        summary_items.append(
            RiskSummaryItem(
                rank=rank,
                user_arn=rec.user_arn,
                risk_score=rec.risk_score,
                risk_level=rec.risk_level,
                top_triggered_rules=triggered[:3],
                recommendation=recs_list[0] if recs_list else "",
            )
        )

    return RiskSummaryResponse(
        session_id=session_id,
        top_n=len(summary_items),
        summary=summary_items,
        critical_count=level_counts["CRITICAL"],
        high_count=level_counts["HIGH"],
        medium_count=level_counts["MEDIUM"],
        low_count=level_counts["LOW"],
    )
