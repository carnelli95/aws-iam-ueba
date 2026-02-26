"""
Streamlit 대시보드
- IAM 이상탐지 결과 시각화
- FastAPI 백엔드 연동 (API_BASE_URL 환경변수)
- 실행: streamlit run dashboard/streamlit_app.py
"""
from __future__ import annotations

import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(
    page_title="IAM Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
)

# ──────────────────────────────────────────────
# 사이드바
# ──────────────────────────────────────────────
st.sidebar.title("🛡️ IAM Anomaly Detection")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "메뉴",
    ["로그 업로드 & 분석", "위험 계정 대시보드", "시스템 상태"],
)

# ──────────────────────────────────────────────
# 헬퍼 함수
# ──────────────────────────────────────────────

LEVEL_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH":     "#ff7f0e",
    "MEDIUM":   "#ffdd57",
    "LOW":      "#2ca02c",
}


def level_badge(level: str) -> str:
    color = LEVEL_COLORS.get(level, "#888")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{level}</span>'


# ──────────────────────────────────────────────
# 페이지: 로그 업로드 & 분석
# ──────────────────────────────────────────────

if page == "로그 업로드 & 분석":
    st.title("📤 CloudTrail 로그 업로드 & 이상탐지")

    col1, col2 = st.columns([2, 1])

    with col1:
        uploaded_file = st.file_uploader(
            "CloudTrail JSON 파일 선택",
            type=["json"],
            help='{"Records": [...]} 형식 또는 이벤트 배열 JSON',
        )

    with col2:
        ml_enabled = st.checkbox("ML 탐지 활성화", value=True)
        contamination = st.slider(
            "이상치 비율 추정 (IsolationForest)",
            min_value=0.01,
            max_value=0.30,
            value=0.10,
            step=0.01,
            disabled=not ml_enabled,
        )

    if uploaded_file and st.button("🚀 탐지 시작", type="primary"):
        with st.spinner("로그 업로드 중..."):
            resp = requests.post(
                f"{API_BASE}/upload-log",
                files={"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")},
            )

        if resp.status_code != 200:
            st.error(f"업로드 실패: {resp.json().get('detail')}")
            st.stop()

        upload_data = resp.json()
        session_id = upload_data["session_id"]
        st.success(
            f"업로드 완료 | 이벤트 {upload_data['total_events']}건 | "
            f"사용자 {upload_data['unique_users']}명 | session_id: `{session_id}`"
        )

        with st.spinner("이상탐지 수행 중..."):
            detect_resp = requests.post(
                f"{API_BASE}/detect",
                json={
                    "session_id": session_id,
                    "ml_enabled": ml_enabled,
                    "contamination": contamination,
                },
            )

        if detect_resp.status_code != 200:
            st.error(f"탐지 실패: {detect_resp.json().get('detail')}")
            st.stop()

        detect_data = detect_resp.json()
        st.session_state["session_id"] = session_id
        st.session_state["detect_data"] = detect_data

        st.success(
            f"탐지 완료 | 분석 사용자 {detect_data['total_users_analyzed']}명 | "
            f"이상 감지 {detect_data['anomaly_count']}명"
        )

        # 결과 요약 카드
        results = detect_data["results"]
        df = pd.DataFrame([
            {
                "사용자 ARN": r["user_arn"],
                "위험 점수": r["risk_score"],
                "등급": r["risk_level"],
                "탐지 방법": r["detection_method"],
                "이상": "⚠️" if r["is_anomaly"] else "✅",
                "트리거 규칙 수": len(r["triggered_rules"]),
            }
            for r in results
        ])

        st.subheader("📊 탐지 결과 요약")
        anomaly_df = df[df["이상"] == "⚠️"].sort_values("위험 점수", ascending=False)
        st.dataframe(anomaly_df, use_container_width=True)

        # 위험 점수 분포 차트
        fig = px.histogram(
            df, x="위험 점수", color="등급",
            color_discrete_map=LEVEL_COLORS,
            title="위험 점수 분포",
            nbins=20,
        )
        st.plotly_chart(fig, use_container_width=True)


# ──────────────────────────────────────────────
# 페이지: 위험 계정 대시보드
# ──────────────────────────────────────────────

elif page == "위험 계정 대시보드":
    st.title("🚨 위험 계정 Top-10 대시보드")

    session_id = st.session_state.get("session_id") or st.text_input(
        "session_id 입력", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    )

    top_n = st.slider("상위 N명 표시", 1, 20, 10)

    if session_id and st.button("조회"):
        resp = requests.get(
            f"{API_BASE}/risk-summary",
            params={"session_id": session_id, "top_n": top_n},
        )
        if resp.status_code != 200:
            st.error(resp.json().get("detail"))
            st.stop()

        data = resp.json()

        # 등급 집계 도넛 차트
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("CRITICAL", data["critical_count"], delta=None)
        col2.metric("HIGH", data["high_count"])
        col3.metric("MEDIUM", data["medium_count"])
        col4.metric("LOW", data["low_count"])

        counts = {
            "CRITICAL": data["critical_count"],
            "HIGH": data["high_count"],
            "MEDIUM": data["medium_count"],
            "LOW": data["low_count"],
        }
        fig_donut = go.Figure(
            go.Pie(
                labels=list(counts.keys()),
                values=list(counts.values()),
                hole=0.5,
                marker_colors=[LEVEL_COLORS[k] for k in counts],
            )
        )
        fig_donut.update_layout(title="위험 등급 분포", height=300)
        st.plotly_chart(fig_donut, use_container_width=True)

        # Top-N 상세 테이블
        st.subheader(f"위험 Top-{top_n} 계정")
        for item in data["summary"]:
            with st.expander(
                f"#{item['rank']} {item['user_arn']} — 점수: {item['risk_score']:.1f} [{item['risk_level']}]"
            ):
                st.markdown(f"**위험 등급:** {level_badge(item['risk_level'])}", unsafe_allow_html=True)
                st.markdown(f"**위험 점수:** `{item['risk_score']:.1f}` / 100")
                if item["top_triggered_rules"]:
                    st.markdown("**트리거된 규칙:**")
                    for rule in item["top_triggered_rules"]:
                        st.markdown(f"- `{rule}`")
                st.info(f"**권고사항:** {item['recommendation']}")

        # 가로 막대 차트
        summary_df = pd.DataFrame(data["summary"])
        if not summary_df.empty:
            fig_bar = px.bar(
                summary_df,
                x="risk_score",
                y="user_arn",
                color="risk_level",
                color_discrete_map=LEVEL_COLORS,
                orientation="h",
                title="위험 점수 Top-N",
                labels={"risk_score": "위험 점수", "user_arn": "사용자 ARN"},
            )
            fig_bar.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_bar, use_container_width=True)


# ──────────────────────────────────────────────
# 페이지: 시스템 상태
# ──────────────────────────────────────────────

elif page == "시스템 상태":
    st.title("⚙️ 시스템 상태")
    try:
        resp = requests.get(f"{API_BASE}/health", timeout=3)
        if resp.status_code == 200:
            st.success(f"API 서버 정상 — {API_BASE}")
            st.json(resp.json())
        else:
            st.error("API 서버 응답 오류")
    except requests.exceptions.ConnectionError:
        st.error(f"API 서버에 연결할 수 없습니다: {API_BASE}")
        st.info("FastAPI 서버를 먼저 실행하세요: `uvicorn app.main:app --reload`")
