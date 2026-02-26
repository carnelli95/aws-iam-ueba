"""
데이터베이스 설정 (SQLAlchemy + SQLite/PostgreSQL)
- 개발: SQLite (zero-config)
- 운영: DATABASE_URL 환경변수로 PostgreSQL 전환 가능
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./iam_anomaly.db")

# SQLite는 check_same_thread=False 필요
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


# ──────────────────────────────────────────────
# ORM 모델
# ──────────────────────────────────────────────

class AnalysisSession(Base):
    """로그 업로드 세션 (분석 단위)."""
    __tablename__ = "analysis_sessions"

    id = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    total_events = Column(Integer, default=0)
    unique_users = Column(Integer, default=0)
    status = Column(String, default="pending")   # pending / completed / error


class DetectionRecord(Base):
    """사용자별 탐지 결과 저장."""
    __tablename__ = "detection_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, index=True)
    user_arn = Column(String, index=True)
    is_anomaly = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="LOW")
    detection_method = Column(String, default="none")
    triggered_rules = Column(Text, default="[]")   # JSON 직렬화
    ml_anomaly_score = Column(Float, default=0.0)
    score_breakdown = Column(Text, default="{}")   # JSON 직렬화
    recommendations = Column(Text, default="[]")   # JSON 직렬화
    details = Column(Text, default="{}")           # JSON 직렬화
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_json(self, field: str, value) -> None:
        setattr(self, field, json.dumps(value, ensure_ascii=False))

    def get_json(self, field: str):
        return json.loads(getattr(self, field) or "null")


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI 의존성 주입용 DB 세션 생성기."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
