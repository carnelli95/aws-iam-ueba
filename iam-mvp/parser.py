"""
CloudTrail JSON 파서 (최소 버전)
- {"Records": [...]} 또는 이벤트 배열 JSON 지원
- 탐지에 필요한 필드만 추출
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

HIGH_RISK_EVENTS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "PutUserPolicy", "CreateRole", "DeleteRole", "AttachRolePolicy",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "AssumeRole",
    "ConsoleLogin", "AuthorizeSecurityGroupIngress", "CreateVpc",
}


def parse(content: str | bytes | dict) -> list[dict[str, Any]]:
    """CloudTrail JSON → 정규화된 이벤트 리스트 반환."""
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    if isinstance(content, str):
        data = json.loads(content)
    else:
        data = content

    raw_events = data.get("Records", data) if isinstance(data, dict) else data
    if not isinstance(raw_events, list):
        raise ValueError("지원하지 않는 CloudTrail 로그 형식입니다.")

    events = []
    for r in raw_events:
        identity = r.get("userIdentity", {})
        arn = identity.get("arn") or identity.get("principalId", "unknown")

        try:
            t = datetime.fromisoformat(r.get("eventTime", "").replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            t = datetime.utcnow()

        mfa = False
        extra = r.get("additionalEventData", {})
        if isinstance(extra, dict):
            mfa = bool(extra.get("MFAUsed") or extra.get("mfaAuthenticated"))

        event_name = r.get("eventName", "")
        events.append({
            "user_arn":      arn,
            "event_time":    t,
            "event_name":    event_name,
            "event_source":  r.get("eventSource", ""),
            "region":        r.get("awsRegion", ""),
            "source_ip":     r.get("sourceIPAddress", ""),
            "mfa_used":      mfa,
            "error_code":    r.get("errorCode"),
            "is_high_risk":  event_name in HIGH_RISK_EVENTS,
        })
    return events
