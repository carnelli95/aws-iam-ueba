"""
이상탐지 엔진
- Layer 1: 규칙 기반 탐지 (즉시 해석 가능, 포트폴리오 핵심)
- Layer 2: IsolationForest ML 기반 탐지 (통계적 이상치)
- 두 결과를 합산하여 최종 탐지 플래그 및 근거 반환
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import numpy as np

from app.services.feature_engineer import UserFeatures, features_to_vector


# ──────────────────────────────────────────────
# 탐지 결과 구조체
# ──────────────────────────────────────────────

@dataclass
class DetectionResult:
    user_arn: str
    is_anomaly: bool
    detection_method: Literal["rule", "ml", "both", "none"]
    triggered_rules: list[str] = field(default_factory=list)
    ml_anomaly_score: float = 0.0   # IsolationForest decision_function 값 (낮을수록 이상)
    details: dict = field(default_factory=dict)


# ──────────────────────────────────────────────
# Layer 1: 규칙 기반 탐지
# ──────────────────────────────────────────────

class RuleEngine:
    """
    보안 전문가 도메인 지식 기반 탐지 규칙.
    각 규칙은 독립적으로 트리거되며, 결과는 목록으로 반환.
    """

    def evaluate(self, uf: UserFeatures) -> list[str]:
        """위반된 규칙명 리스트 반환."""
        triggered: list[str] = []

        # R01: 야간(22~06시) 접속이 전체 30% 초과
        total = max(uf.total_events, 1)
        if uf.off_hours_event_count / total > 0.30:
            triggered.append("R01_OFF_HOURS_ACCESS")

        # R02: 고위험 이벤트 비율 20% 초과
        if uf.high_risk_event_count / total > 0.20:
            triggered.append("R02_HIGH_RISK_RATIO")

        # R03: 고위험 이벤트에서 MFA 미사용
        if uf.mfa_missing_high_risk >= 1:
            triggered.append("R03_HIGH_RISK_NO_MFA")

        # R04: 3개 이상의 서로 다른 IP에서 접속
        if uf.unique_ips >= 3:
            triggered.append("R04_MULTIPLE_SOURCE_IPS")

        # R05: 실패율 40% 초과 (크리덴셜 스터핑 / 권한 스캔 의심)
        if uf.failed_event_count / total > 0.40:
            triggered.append("R05_HIGH_FAILURE_RATE")

        # R06: 연속 실패 5회 이상 (무차별 대입 의심)
        if uf.consecutive_failures >= 5:
            triggered.append("R06_CONSECUTIVE_FAILURES")

        # R07: 관리자 권한 액션 5회 이상
        if uf.admin_action_count >= 5:
            triggered.append("R07_EXCESSIVE_ADMIN_ACTIONS")

        # R08: 2개 이상 리전에서 활동
        if uf.unique_regions >= 2:
            triggered.append("R08_MULTI_REGION_ACTIVITY")

        # R09: 단시간 이벤트 폭발 (총 이벤트 100개 초과)
        if uf.total_events > 100:
            triggered.append("R09_EVENT_BURST")

        return triggered


# ──────────────────────────────────────────────
# Layer 2: ML 기반 탐지 (IsolationForest)
# ──────────────────────────────────────────────

class MLAnomalyDetector:
    """
    IsolationForest 기반 비지도 이상탐지.
    - 학습 데이터 없이 구동 가능 (비지도)
    - contamination: 이상치 비율 추정 (기본 10%)
    """

    def __init__(self, contamination: float = 0.10, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self._model = None

    def fit_predict(
        self, features_list: list[UserFeatures]
    ) -> dict[str, float]:
        """
        전체 사용자 피처로 모델 학습 후 이상 점수 반환.

        Returns
        -------
        dict[str, float]
            user_arn → anomaly_score 매핑
            (낮은 값 = 더 이상함, 0 이하이면 이상치로 분류)
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            # scikit-learn 없으면 ML 탐지 스킵
            return {uf.user_arn: 0.0 for uf in features_list}

        if len(features_list) < 2:
            return {uf.user_arn: 0.0 for uf in features_list}

        vectors = np.array([features_to_vector(uf) for uf in features_list])
        scaler = StandardScaler()
        X = scaler.fit_transform(vectors)

        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        model.fit(X)
        scores = model.decision_function(X)  # 낮을수록 이상

        return {
            features_list[i].user_arn: float(scores[i])
            for i in range(len(features_list))
        }


# ──────────────────────────────────────────────
# 통합 탐지 파이프라인
# ──────────────────────────────────────────────

class AnomalyEngine:
    """규칙 기반 + ML 기반을 조합한 최종 탐지 엔진."""

    def __init__(
        self,
        ml_threshold: float = 0.0,
        contamination: float = 0.10,
    ):
        self.rule_engine = RuleEngine()
        self.ml_detector = MLAnomalyDetector(contamination=contamination)
        self.ml_threshold = ml_threshold  # 이 값 이하이면 ML 이상 판정

    def detect(self, features_list: list[UserFeatures]) -> list[DetectionResult]:
        """
        전체 사용자에 대해 이상탐지 수행.

        Parameters
        ----------
        features_list : list[UserFeatures]
            feature_engineer.extract_user_features() 결과

        Returns
        -------
        list[DetectionResult]
            사용자별 탐지 결과
        """
        # ML 점수 일괄 계산
        ml_scores = self.ml_detector.fit_predict(features_list)

        results: list[DetectionResult] = []

        for uf in features_list:
            # 규칙 기반 탐지
            triggered_rules = self.rule_engine.evaluate(uf)
            rule_anomaly = len(triggered_rules) > 0

            # ML 기반 탐지
            ml_score = ml_scores.get(uf.user_arn, 0.0)
            ml_anomaly = ml_score <= self.ml_threshold

            # 탐지 방법 결합
            is_anomaly = rule_anomaly or ml_anomaly
            if rule_anomaly and ml_anomaly:
                method: Literal["rule", "ml", "both", "none"] = "both"
            elif rule_anomaly:
                method = "rule"
            elif ml_anomaly:
                method = "ml"
            else:
                method = "none"

            results.append(
                DetectionResult(
                    user_arn=uf.user_arn,
                    is_anomaly=is_anomaly,
                    detection_method=method,
                    triggered_rules=triggered_rules,
                    ml_anomaly_score=ml_score,
                    details={
                        "total_events": uf.total_events,
                        "high_risk_events": uf.high_risk_event_count,
                        "failed_events": uf.failed_event_count,
                        "off_hours_events": uf.off_hours_event_count,
                        "unique_ips": uf.unique_ips,
                        "mfa_missing_high_risk": uf.mfa_missing_high_risk,
                    },
                )
            )

        return results
