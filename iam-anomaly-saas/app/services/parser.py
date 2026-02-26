"""
CloudTrail 로그 파서
- CloudTrail JSON 파일에서 보안 분석에 필요한 필드 추출
- 단일 이벤트 / 배치 이벤트 모두 지원
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.models.schemas import CloudTrailEvent


# IAM 관련 고위험 이벤트명 목록
HIGH_RISK_EVENTS = {
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetSessionToken",
    "ConsoleLogin",
    "PasswordData",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "CreateVpc",
    "ModifyInstanceAttribute",
}

# 관리자급 권한 키워드
ADMIN_ACTION_KEYWORDS = {"FullAccess", "AdministratorAccess", "PowerUser", "*"}


def parse_event(raw: dict[str, Any]) -> CloudTrailEvent:
    """단일 CloudTrail 이벤트 dict → CloudTrailEvent 파싱."""
    identity = raw.get("userIdentity", {})

    # userIdentity.arn 추출 (없으면 type 기반으로 구성)
    arn = identity.get("arn") or identity.get("principalId", "unknown")

    # 이벤트 시간 파싱 (ISO 8601)
    event_time_raw = raw.get("eventTime", "")
    try:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        event_time = datetime.utcnow()

    # MFA 사용 여부 추출
    mfa_used = False
    additional_event_data = raw.get("additionalEventData", {})
    if isinstance(additional_event_data, dict):
        mfa_used = bool(
            additional_event_data.get("MFAUsed")
            or additional_event_data.get("mfaAuthenticated")
        )

    # requestParameters에서 정책명 추출 (있을 경우)
    request_params = raw.get("requestParameters") or {}
    policy_name = None
    if isinstance(request_params, dict):
        policy_name = request_params.get("policyName") or request_params.get(
            "policyArn"
        )

    is_high_risk = raw.get("eventName", "") in HIGH_RISK_EVENTS
    error_code = raw.get("errorCode")
    error_message = raw.get("errorMessage")

    return CloudTrailEvent(
        event_id=raw.get("eventID", ""),
        event_time=event_time,
        event_name=raw.get("eventName", ""),
        event_source=raw.get("eventSource", ""),
        aws_region=raw.get("awsRegion", ""),
        source_ip=raw.get("sourceIPAddress", ""),
        user_agent=raw.get("userAgent", ""),
        user_arn=arn,
        user_type=identity.get("type", ""),
        account_id=identity.get("accountId", ""),
        mfa_used=mfa_used,
        request_parameters=request_params,
        policy_name=policy_name,
        error_code=error_code,
        error_message=error_message,
        is_high_risk=is_high_risk,
    )


def parse_file(path: str | Path) -> list[CloudTrailEvent]:
    """CloudTrail JSON 파일 전체 파싱 → 이벤트 리스트 반환."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"로그 파일이 존재하지 않습니다: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # CloudTrail 표준 형식: {"Records": [...]}
    if isinstance(data, dict) and "Records" in data:
        raw_events = data["Records"]
    elif isinstance(data, list):
        raw_events = data
    else:
        raise ValueError("지원하지 않는 CloudTrail 로그 형식입니다.")

    return [parse_event(evt) for evt in raw_events]


def parse_raw_json(content: str | bytes) -> list[CloudTrailEvent]:
    """문자열/바이트 JSON 파싱 (API 업로드용)."""
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    data = json.loads(content)

    if isinstance(data, dict) and "Records" in data:
        raw_events = data["Records"]
    elif isinstance(data, list):
        raw_events = data
    else:
        raise ValueError("지원하지 않는 CloudTrail 로그 형식입니다.")

    return [parse_event(evt) for evt in raw_events]
