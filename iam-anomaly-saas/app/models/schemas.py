"""
Pydantic 스키마 (API 입출력 + 내부 데이터 모델)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# CloudTrail 이벤트 (파서 출력 + DB 저장 단위)
# ──────────────────────────────────────────────

class CloudTrailEvent(BaseModel):
    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    source_ip: str
    user_agent: str
    user_arn: str
    user_type: str
    account_id: str
    mfa_used: bool = False
    request_parameters: dict[str, Any] = Field(default_factory=dict)
    policy_name: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    is_high_risk: bool = False

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────
# API 요청/응답
# ──────────────────────────────────────────────

class UploadResponse(BaseModel):
    session_id: str
    total_events: int
    unique_users: int
    message: str


class DetectRequest(BaseModel):
    session_id: str
    ml_enabled: bool = True
    contamination: float = Field(default=0.10, ge=0.01, le=0.49)


class RuleViolation(BaseModel):
    rule_id: str
    description: str


RULE_DESCRIPTIONS: dict[str, str] = {
    "R01_OFF_HOURS_ACCESS":       "야간 시간대(22:00~06:00) 접속 비율 30% 초과",
    "R02_HIGH_RISK_RATIO":        "고위험 이벤트 비율 20% 초과",
    "R03_HIGH_RISK_NO_MFA":       "고위험 이벤트 실행 시 MFA 미사용",
    "R04_MULTIPLE_SOURCE_IPS":    "3개 이상의 서로 다른 소스 IP",
    "R05_HIGH_FAILURE_RATE":      "이벤트 실패율 40% 초과",
    "R06_CONSECUTIVE_FAILURES":   "연속 인증 실패 5회 이상",
    "R07_EXCESSIVE_ADMIN_ACTIONS":"관리자 권한 액션 5회 이상",
    "R08_MULTI_REGION_ACTIVITY":  "2개 이상 AWS 리전에서 활동",
    "R09_EVENT_BURST":            "단시간 이벤트 100건 초과",
}


class UserDetectionResult(BaseModel):
    user_arn: str
    is_anomaly: bool
    risk_score: float
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    detection_method: Literal["rule", "ml", "both", "none"]
    triggered_rules: list[RuleViolation]
    ml_anomaly_score: float
    score_breakdown: dict[str, float]
    recommendations: list[str]
    details: dict[str, Any]


class DetectResponse(BaseModel):
    session_id: str
    total_users_analyzed: int
    anomaly_count: int
    results: list[UserDetectionResult]


class RiskSummaryItem(BaseModel):
    rank: int
    user_arn: str
    risk_score: float
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    top_triggered_rules: list[str]
    recommendation: str


class RiskSummaryResponse(BaseModel):
    session_id: str
    top_n: int
    summary: list[RiskSummaryItem]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


# ──────────────────────────────────────────────
# 헬스체크
# ──────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
