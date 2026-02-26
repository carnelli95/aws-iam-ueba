"""
인메모리 세션 스토어 (개발/MVP용)
- 업로드된 이벤트를 세션 ID 기반으로 임시 저장
- 운영 전환 시 Redis 캐시로 교체 권장
"""
from __future__ import annotations

from app.models.schemas import CloudTrailEvent

# session_id → list[CloudTrailEvent]
session_store: dict[str, list[CloudTrailEvent]] = {}
