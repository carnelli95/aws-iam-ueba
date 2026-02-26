# 빠른 시작 가이드

## 1. 환경 설정

```bash
cd iam-anomaly-saas
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. FastAPI 서버 실행

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- API 문서: http://localhost:8000/docs
- 헬스체크: http://localhost:8000/health

## 3. Streamlit 대시보드 실행

```bash
streamlit run dashboard/streamlit_app.py
```

- 대시보드: http://localhost:8501

## 4. 테스트 실행

```bash
pytest tests/ -v
```

## 5. API 직접 사용 (curl)

```bash
# 로그 업로드
curl -X POST http://localhost:8000/upload-log \
  -F "file=@tests/sample_logs/sample_cloudtrail.json"

# 이상탐지 수행 (session_id는 위 응답에서 복사)
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID", "ml_enabled": true}'

# 위험 계정 Top-10 조회
curl "http://localhost:8000/risk-summary?session_id=YOUR_SESSION_ID&top_n=10"
```

## 6. AWS CloudTrail 실제 로그 연동

```bash
# AWS CLI로 CloudTrail 이벤트 다운로드
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --start-time 2024-01-01 \
  --end-time 2024-01-31 \
  --output json > real_cloudtrail.json

# 다운로드한 로그 업로드
curl -X POST http://localhost:8000/upload-log \
  -F "file=@real_cloudtrail.json"
```
