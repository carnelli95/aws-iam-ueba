"""
Risk Score 계산 모듈
- 탐지 결과 + 피처 → 0~100 사이 위험 점수 산정
- 가중치 기반 점수 + 페널티 조합
- 등급: CRITICAL(80+) / HIGH(60~79) / MEDIUM(40~59) / LOW(0~39)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.services.anomaly_engine import DetectionResult
from app.services.feature_engineer import UserFeatures


RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass
class RiskScore:
    user_arn: str
    score: float                    # 0.0 ~ 100.0
    level: RiskLevel
    score_breakdown: dict[str, float]  # 항목별 기여 점수
    recommendations: list[str]      # 조치 권고사항


# ──────────────────────────────────────────────
# 규칙별 기본 점수 (가중치)
# ──────────────────────────────────────────────
RULE_BASE_SCORES: dict[str, float] = {
    "R01_OFF_HOURS_ACCESS":       10.0,
    "R02_HIGH_RISK_RATIO":        15.0,
    "R03_HIGH_RISK_NO_MFA":       20.0,   # MFA 미사용은 고점수
    "R04_MULTIPLE_SOURCE_IPS":    10.0,
    "R05_HIGH_FAILURE_RATE":      15.0,
    "R06_CONSECUTIVE_FAILURES":   20.0,   # 무차별 대입 시도
    "R07_EXCESSIVE_ADMIN_ACTIONS":18.0,
    "R08_MULTI_REGION_ACTIVITY":   8.0,
    "R09_EVENT_BURST":            10.0,
}

# ML 이상 탐지 가산점
ML_ANOMALY_BONUS = 15.0

# 최대 점수 캡
MAX_SCORE = 100.0


def _level(score: float) -> RiskLevel:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _recommendations(
    result: DetectionResult, uf: UserFeatures, level: RiskLevel
) -> list[str]:
    recs: list[str] = []

    if "R03_HIGH_RISK_NO_MFA" in result.triggered_rules:
        recs.append("즉시 해당 계정에 MFA(다단계 인증) 적용 필요")

    if "R06_CONSECUTIVE_FAILURES" in result.triggered_rules:
        recs.append("연속 인증 실패 감지 — 계정 잠금 또는 IP 차단 검토")

    if "R07_EXCESSIVE_ADMIN_ACTIONS" in result.triggered_rules:
        recs.append("최소 권한 원칙(PoLP) 재검토 — 불필요한 관리자 정책 제거")

    if "R04_MULTIPLE_SOURCE_IPS" in result.triggered_rules:
        recs.append("비정상 IP 접근 확인 — VPC 엔드포인트 또는 IP 허용목록 적용 검토")

    if "R01_OFF_HOURS_ACCESS" in result.triggered_rules:
        recs.append("야간 접속 패턴 확인 — 비업무시간 접근 제한 정책 검토")

    if "R08_MULTI_REGION_ACTIVITY" in result.triggered_rules:
        recs.append("AWS SCP(서비스 제어 정책)로 허용 리전 제한 검토")

    if result.detection_method in ("ml", "both"):
        recs.append("ML 모델이 통계적 이상 패턴 감지 — 로그 상세 수동 검토 권고")

    if level == "CRITICAL":
        recs.insert(0, "[긴급] 해당 IAM 계정/Role 즉시 비활성화 후 조사 시작")

    if not recs:
        recs.append("현재 탐지된 이상 없음 — 정기 모니터링 유지")

    return recs


def calculate_risk_score(
    result: DetectionResult,
    uf: UserFeatures,
) -> RiskScore:
    """
    DetectionResult + UserFeatures → RiskScore 계산.
    """
    breakdown: dict[str, float] = {}
    total = 0.0

    # 1) 규칙 기반 점수 합산
    for rule in result.triggered_rules:
        pts = RULE_BASE_SCORES.get(rule, 5.0)
        breakdown[rule] = pts
        total += pts

    # 2) ML 이상 탐지 보너스
    if result.detection_method in ("ml", "both"):
        breakdown["ML_ANOMALY"] = ML_ANOMALY_BONUS
        total += ML_ANOMALY_BONUS

    # 3) 연속 실패 횟수 선형 페널티 (+1점/회, 최대 10점)
    consec_penalty = min(uf.consecutive_failures * 1.0, 10.0)
    if consec_penalty > 0:
        breakdown["CONSECUTIVE_FAIL_PENALTY"] = consec_penalty
        total += consec_penalty

    # 4) 점수 캡
    final_score = min(total, MAX_SCORE)
    level = _level(final_score)
    recs = _recommendations(result, uf, level)

    return RiskScore(
        user_arn=result.user_arn,
        score=round(final_score, 2),
        level=level,
        score_breakdown=breakdown,
        recommendations=recs,
    )


def rank_users(risk_scores: list[RiskScore]) -> list[RiskScore]:
    """위험 점수 내림차순 정렬 (대시보드 Top-N 표시용)."""
    return sorted(risk_scores, key=lambda r: r.score, reverse=True)
