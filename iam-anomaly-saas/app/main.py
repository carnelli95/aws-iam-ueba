"""
FastAPI 메인 애플리케이션
IAM Anomaly Detection SaaS - MVP
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import detect, upload
from app.database.db import create_tables
from app.models.schemas import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="IAM Anomaly Detection API",
    description=(
        "AWS CloudTrail 로그를 기반으로 IAM 권한 오남용 및 이상행위를 탐지하는 B2B SaaS MVP.\n\n"
        "## 사용 흐름\n"
        "1. `POST /upload-log` — CloudTrail JSON 파일 업로드\n"
        "2. `POST /detect` — 이상탐지 수행 (규칙 기반 + ML)\n"
        "3. `GET /risk-summary` — 위험 계정 Top-N 조회\n"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(detect.router)


@app.get("/health", response_model=HealthResponse, tags=["시스템"])
def health_check():
    return HealthResponse()


@app.get("/", tags=["시스템"])
def root():
    return {
        "service": "IAM Anomaly Detection SaaS",
        "version": "0.1.0",
        "docs": "/docs",
        "status": "running",
    }
