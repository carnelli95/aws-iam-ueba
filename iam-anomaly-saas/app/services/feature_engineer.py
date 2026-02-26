"""
피처 엔지니어링 모듈
- CloudTrailEvent 리스트 → 사용자별 행동 특성 벡터 추출
- 시간 기반 / IP 기반 / 빈도 기반 피처 계산
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.models.schemas import CloudTrailEvent


@dataclass
class UserFeatures:
    """단일 사용자의 행동 특성 요약."""

    user_arn: str
    total_events: int = 0
    unique_event_names: int = 0
    unique_ips: int = 0
    high_risk_event_count: int = 0
    failed_event_count: int = 0
    off_hours_event_count: int = 0     # 22:00 ~ 06:00 (UTC) 이벤트 수
    consecutive_failures: int = 0      # 연속 실패 최대 횟수
    mfa_missing_high_risk: int = 0     # 고위험 이벤트 중 MFA 미사용 수
    admin_action_count: int = 0        # 관리자 권한 관련 액션 수
    unique_regions: int = 0
    event_name_entropy: float = 0.0    # 이벤트 다양성 (높을수록 다양한 행동)
    ip_list: list[str] = field(default_factory=list)
    event_counts: dict[str, int] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


# 관리자 권한 관련 이벤트 키워드
ADMIN_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreateRole", "CreateUser", "CreateAccessKey",
    "AssumeRole", "GetSessionToken",
}


def _is_off_hours(dt: datetime) -> bool:
    """UTC 기준 22:00~06:00 사이 여부."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    hour = dt.hour
    return hour >= 22 or hour < 6


def _entropy(counts: dict[str, int]) -> float:
    """Shannon 엔트로피 계산 (이벤트 다양성 측정)."""
    import math
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def _max_consecutive_failures(events: list[CloudTrailEvent]) -> int:
    """시간순 정렬 후 연속 실패 최대값 계산."""
    sorted_events = sorted(events, key=lambda e: e.event_time)
    max_seq = current_seq = 0
    for evt in sorted_events:
        if evt.error_code:
            current_seq += 1
            max_seq = max(max_seq, current_seq)
        else:
            current_seq = 0
    return max_seq


def extract_user_features(events: list[CloudTrailEvent]) -> list[UserFeatures]:
    """
    전체 이벤트 리스트 → 사용자별 피처 추출.

    Returns
    -------
    list[UserFeatures]
        사용자 ARN별 집계된 피처 리스트
    """
    user_events: dict[str, list[CloudTrailEvent]] = defaultdict(list)
    for evt in events:
        user_events[evt.user_arn].append(evt)

    features_list: list[UserFeatures] = []

    for arn, user_evts in user_events.items():
        event_name_counter: Counter[str] = Counter(
            e.event_name for e in user_evts
        )
        ip_set = {e.source_ip for e in user_evts if e.source_ip}
        region_set = {e.aws_region for e in user_evts if e.aws_region}
        times = [e.event_time for e in user_evts]

        high_risk = sum(1 for e in user_evts if e.is_high_risk)
        failed = sum(1 for e in user_evts if e.error_code)
        off_hours = sum(1 for e in user_evts if _is_off_hours(e.event_time))
        mfa_missing_hr = sum(
            1 for e in user_evts if e.is_high_risk and not e.mfa_used
        )
        admin_count = sum(
            1 for e in user_evts if e.event_name in ADMIN_EVENTS
        )

        uf = UserFeatures(
            user_arn=arn,
            total_events=len(user_evts),
            unique_event_names=len(event_name_counter),
            unique_ips=len(ip_set),
            high_risk_event_count=high_risk,
            failed_event_count=failed,
            off_hours_event_count=off_hours,
            consecutive_failures=_max_consecutive_failures(user_evts),
            mfa_missing_high_risk=mfa_missing_hr,
            admin_action_count=admin_count,
            unique_regions=len(region_set),
            event_name_entropy=_entropy(dict(event_name_counter)),
            ip_list=list(ip_set),
            event_counts=dict(event_name_counter),
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
        )
        features_list.append(uf)

    return features_list


def features_to_vector(uf: UserFeatures) -> list[float]:
    """
    UserFeatures → ML 모델 입력용 수치 벡터 변환.

    피처 순서 (고정):
    0: total_events
    1: unique_event_names
    2: unique_ips
    3: high_risk_event_count
    4: failed_event_count
    5: off_hours_event_count
    6: consecutive_failures
    7: mfa_missing_high_risk
    8: admin_action_count
    9: unique_regions
    10: event_name_entropy
    11: high_risk_ratio  (= high_risk / total)
    12: failure_ratio    (= failed / total)
    13: off_hours_ratio  (= off_hours / total)
    """
    total = max(uf.total_events, 1)
    return [
        float(uf.total_events),
        float(uf.unique_event_names),
        float(uf.unique_ips),
        float(uf.high_risk_event_count),
        float(uf.failed_event_count),
        float(uf.off_hours_event_count),
        float(uf.consecutive_failures),
        float(uf.mfa_missing_high_risk),
        float(uf.admin_action_count),
        float(uf.unique_regions),
        uf.event_name_entropy,
        uf.high_risk_event_count / total,
        uf.failed_event_count / total,
        uf.off_hours_event_count / total,
    ]
