"""
탐지 엔진 (최소 버전)
- Feature 추출 (사용자별 집계)
- IsolationForest 이상탐지
- Rule 기반 Risk Score
- 최종 결과 반환
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np


# ─────────────────────────────────────────
# 1) Feature 추출
# ─────────────────────────────────────────

@dataclass
class UserFeatures:
    user_arn:               str
    total_events:           int   = 0
    off_hours_events:       int   = 0   # 22:00~06:00 접속
    high_risk_events:       int   = 0
    mfa_missing_high_risk:  int   = 0   # 고위험인데 MFA 없음
    unique_ips:             int   = 0
    failed_events:          int   = 0
    consecutive_failures:   int   = 0
    admin_action_count:     int   = 0   # DeleteUser, AttachUserPolicy 등
    unique_regions:         int   = 0

ADMIN_EVENTS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "PutUserPolicy", "CreateRole", "AttachRolePolicy", "CreateAccessKey",
}


def extract_features(events: list[dict]) -> list[UserFeatures]:
    """이벤트 리스트 → 사용자별 UserFeatures 리스트."""
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "events": [], "ips": set(), "regions": set(),
    })

    for e in events:
        b = buckets[e["user_arn"]]
        b["events"].append(e)
        b["ips"].add(e["source_ip"])
        b["regions"].add(e["region"])

    result = []
    for arn, b in buckets.items():
        evts = b["events"]
        total = len(evts)

        # 연속 실패 최대 길이 계산
        max_consec = cur_consec = 0
        for e in evts:
            if e["error_code"]:
                cur_consec += 1
                max_consec = max(max_consec, cur_consec)
            else:
                cur_consec = 0

        uf = UserFeatures(
            user_arn=arn,
            total_events=total,
            off_hours_events=sum(
                1 for e in evts if e["event_time"].hour >= 22 or e["event_time"].hour < 6
            ),
            high_risk_events=sum(1 for e in evts if e["is_high_risk"]),
            mfa_missing_high_risk=sum(
                1 for e in evts if e["is_high_risk"] and not e["mfa_used"]
            ),
            unique_ips=len(b["ips"]),
            failed_events=sum(1 for e in evts if e["error_code"]),
            consecutive_failures=max_consec,
            admin_action_count=sum(1 for e in evts if e["event_name"] in ADMIN_EVENTS),
            unique_regions=len(b["regions"]),
        )
        result.append(uf)
    return result


def to_vector(uf: UserFeatures) -> list[float]:
    total = max(uf.total_events, 1)
    return [
        uf.total_events,
        uf.off_hours_events / total,
        uf.high_risk_events / total,
        uf.mfa_missing_high_risk,
        uf.unique_ips,
        uf.failed_events / total,
        uf.consecutive_failures,
        uf.admin_action_count,
        uf.unique_regions,
    ]


# ─────────────────────────────────────────
# 2) Rule 기반 Risk Score
# ─────────────────────────────────────────

RULES: list[tuple[str, float, callable]] = [
    ("R01_OFF_HOURS",        10.0, lambda uf: uf.off_hours_events / max(uf.total_events, 1) > 0.30),
    ("R02_HIGH_RISK_RATIO",  15.0, lambda uf: uf.high_risk_events / max(uf.total_events, 1) > 0.20),
    ("R03_NO_MFA",           20.0, lambda uf: uf.mfa_missing_high_risk >= 1),
    ("R04_MULTI_IP",         10.0, lambda uf: uf.unique_ips >= 3),
    ("R05_HIGH_FAIL_RATE",   15.0, lambda uf: uf.failed_events / max(uf.total_events, 1) > 0.40),
    ("R06_CONSEC_FAIL",      20.0, lambda uf: uf.consecutive_failures >= 5),
    ("R07_ADMIN_ABUSE",      18.0, lambda uf: uf.admin_action_count >= 5),
    ("R08_MULTI_REGION",      8.0, lambda uf: uf.unique_regions >= 2),
    ("R09_EVENT_BURST",      10.0, lambda uf: uf.total_events > 100),
]


def _risk_level(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _score(uf: UserFeatures, triggered: list[str], ml_anomaly: bool) -> tuple[float, dict]:
    breakdown: dict[str, float] = {}
    total = 0.0
    for rule_id, pts, check in RULES:
        if rule_id in triggered:
            breakdown[rule_id] = pts
            total += pts
    if ml_anomaly:
        breakdown["ML_ANOMALY"] = 15.0
        total += 15.0
    penalty = min(uf.consecutive_failures * 1.0, 10.0)
    if penalty > 0:
        breakdown["CONSEC_PENALTY"] = penalty
        total += penalty
    return min(total, 100.0), breakdown


# ─────────────────────────────────────────
# 3) IsolationForest
# ─────────────────────────────────────────

def _ml_anomalies(features_list: list[UserFeatures]) -> dict[str, bool]:
    if len(features_list) < 2:
        return {uf.user_arn: False for uf in features_list}
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return {uf.user_arn: False for uf in features_list}

    X = np.array([to_vector(uf) for uf in features_list])
    X = StandardScaler().fit_transform(X)
    preds = IsolationForest(contamination=0.1, random_state=42).fit_predict(X)
    return {features_list[i].user_arn: bool(preds[i] == -1) for i in range(len(features_list))}


# ─────────────────────────────────────────
# 4) 통합 탐지
# ─────────────────────────────────────────

def detect(events: list[dict]) -> list[dict]:
    """
    이벤트 리스트 → 사용자별 탐지 결과 반환.

    반환 형식:
    {
        user_arn, is_anomaly, risk_score, risk_level,
        detection_method, triggered_rules, score_breakdown
    }
    """
    features_list = extract_features(events)
    if not features_list:
        return []

    ml_result = _ml_anomalies(features_list)

    output = []
    for uf in features_list:
        triggered = [rid for rid, _, check in RULES if check(uf)]
        rule_hit = len(triggered) > 0
        ml_hit = ml_result.get(uf.user_arn, False)

        score, breakdown = _score(uf, triggered, ml_hit)
        level = _risk_level(score)

        if rule_hit and ml_hit:   method = "both"
        elif rule_hit:            method = "rule"
        elif ml_hit:              method = "ml"
        else:                     method = "none"

        output.append({
            "user_arn":        uf.user_arn,
            "is_anomaly":      bool(rule_hit or ml_hit),
            "risk_score":      round(score, 2),
            "risk_level":      level,
            "detection_method": method,
            "triggered_rules": triggered,
            "score_breakdown": breakdown,
            "stats": {
                "total_events":    uf.total_events,
                "high_risk":       uf.high_risk_events,
                "failed":          uf.failed_events,
                "unique_ips":      uf.unique_ips,
                "off_hours":       uf.off_hours_events,
            },
        })

    output.sort(key=lambda x: x["risk_score"], reverse=True)
    return output
