# AWS IAM UEBA — CloudTrail 기반 이상행위 탐지

AWS CloudTrail 로그를 분석해 IAM 계정의 이상행위를 탐지하는 보안 프로젝트입니다.
규칙 기반 탐지와 IsolationForest 머신러닝을 결합한 **UEBA(User & Entity Behavior Analytics)** 방식을 적용했습니다.

---

## 프로젝트 구성

```
aws-iam-ueba/
├── iam-mvp/              # 핵심 MVP — 실제 동작 검증 완료
│   ├── main.py           # FastAPI 서버 (POST /detect)
│   ├── parser.py         # CloudTrail JSON 파싱
│   ├── detector.py       # Feature 추출 + IsolationForest + Risk Score
│   ├── requirements.txt
│   └── sample_cloudtrail.json  # 테스트용 샘플 로그 (alice/bob/charlie)
│
└── iam-anomaly-saas/     # Full SaaS 구조 (확장 설계)
    ├── app/              # FastAPI + SQLAlchemy
    ├── dashboard/        # Streamlit 대시보드
    ├── tests/            # pytest 테스트
    └── docs/             # 아키텍처 문서
```

---

## 탐지 방식

### Layer 1 — 규칙 기반 탐지 (즉시 해석 가능)

| 규칙 | 설명 | 점수 |
|------|------|------|
| R01 | 야간(22~06시) 접속 비율 30% 초과 | 10 |
| R02 | 고위험 이벤트 비율 20% 초과 | 15 |
| R03 | 고위험 액션에 MFA 미사용 | 20 |
| R04 | 3개 이상 IP에서 접속 | 10 |
| R05 | 실패율 40% 초과 (권한 스캔 의심) | 15 |
| R06 | 연속 실패 5회 이상 (무차별 대입 의심) | 20 |
| R07 | 관리자 권한 액션 5회 이상 | 18 |
| R08 | 2개 이상 리전에서 동시 활동 | 8 |
| R09 | 단시간 이벤트 100건 초과 | 10 |

### Layer 2 — IsolationForest ML 탐지

사용자별 행동 벡터를 구성해 통계적 이상치를 탐지합니다.

```python
feature_vector = [
    total_events,         # 전체 이벤트 수
    off_hours_ratio,      # 야간 접속 비율
    high_risk_ratio,      # 고위험 이벤트 비율
    mfa_missing_count,    # MFA 없는 고위험 액션 수
    unique_ips,           # 접속 IP 수
    failure_ratio,        # 실패율
    consecutive_failures, # 최대 연속 실패 횟수
    admin_action_count,   # 관리자 액션 수
    unique_regions,       # 접속 리전 수
]
```

### Risk Level

| 점수 | 등급 |
|------|------|
| 80+ | CRITICAL |
| 60~79 | HIGH |
| 40~59 | MEDIUM |
| 0~39 | LOW |

---

## 실행 방법

```bash
cd iam-mvp

python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt

uvicorn main:app --reload
```

Swagger UI: `http://localhost:8000/docs`

### API 사용

```bash
curl -X POST http://localhost:8000/detect \
  -F "file=@sample_cloudtrail.json"
```

---

## 실험 결과

샘플 로그(정상 1명 / 이상 2명)로 탐지 결과:

```json
{
  "total_events": 22,
  "total_users": 3,
  "anomaly_count": 3,
  "results": [
    {
      "user_arn": "...user/charlie",
      "risk_score": 94,
      "risk_level": "CRITICAL",
      "detection_method": "rule",
      "triggered_rules": ["R01_OFF_HOURS", "R03_NO_MFA", "R06_CONSEC_FAIL", ...]
    },
    {
      "user_arn": "...user/bob",
      "risk_score": 81,
      "risk_level": "CRITICAL",
      "detection_method": "rule",
      "triggered_rules": ["R03_NO_MFA", "R04_MULTI_IP", "R07_ADMIN_ABUSE", ...]
    },
    {
      "user_arn": "...user/alice",
      "risk_score": 15,
      "risk_level": "LOW",
      "detection_method": "ml"
    }
  ]
}
```

### 발견한 한계

- IsolationForest는 **사용자 수가 20명 이상**이어야 통계적으로 의미 있음
- 소규모 데이터(3명)에서 정상 사용자(alice)가 False Positive로 분류됨
- 규칙 기반은 소규모 데이터에서도 안정적으로 동작

---

## 기술 스택

- **Backend**: FastAPI, uvicorn
- **ML**: scikit-learn IsolationForest, StandardScaler
- **파싱**: Python 표준 라이브러리 (json, datetime)
- **테스트**: pytest (iam-anomaly-saas)

---

## 로드맵

- [x] CloudTrail 로그 파서
- [x] UEBA Feature 추출 (9차원 벡터)
- [x] 규칙 기반 탐지 (R01~R09)
- [x] IsolationForest ML 탐지
- [x] FastAPI REST API
- [ ] AWS 실계정 CloudTrail 로그로 검증
- [ ] False Positive 개선 (임계값 튜닝)
- [ ] LLM 기반 리포트 자동 생성
