# 시스템 아키텍처

## 전체 데이터 흐름

```
CloudTrail JSON
      │
      ▼
[POST /upload-log]
      │  parse_raw_json()
      ▼
list[CloudTrailEvent]  ──→  AnalysisSession (DB)
      │
      ▼
[POST /detect]
      │
      ├─ extract_user_features()   → UserFeatures (사용자별 집계)
      │
      ├─ RuleEngine.evaluate()     → triggered_rules[]   (Layer 1)
      │
      ├─ IsolationForest           → ml_anomaly_score    (Layer 2)
      │
      └─ calculate_risk_score()    → RiskScore (0~100)
                                         │
                                         ▼
                                   DetectionRecord (DB)

[GET /risk-summary]
      │  DB 조회 → 정렬
      ▼
RiskSummaryResponse (Top-N)
      │
      ▼
Streamlit Dashboard
```

## 탐지 레이어 설명

### Layer 1 — 규칙 기반 (Rule Engine)
도메인 전문가 지식 기반. 즉시 해석 가능하며 포트폴리오 시연에 유리.

| 규칙 ID | 설명 | 기본 점수 |
|---------|------|-----------|
| R01 | 야간(22~06시) 접속 비율 30% 초과 | 10 |
| R02 | 고위험 이벤트 비율 20% 초과 | 15 |
| R03 | 고위험 이벤트 + MFA 미사용 | 20 |
| R04 | 3개 이상 소스 IP | 10 |
| R05 | 실패율 40% 초과 | 15 |
| R06 | 연속 실패 5회+ | 20 |
| R07 | 관리자 권한 액션 5회+ | 18 |
| R08 | 2개+ 리전 활동 | 8 |
| R09 | 이벤트 100건 초과 | 10 |

### Layer 2 — ML 기반 (IsolationForest)
비지도 학습. 14차원 피처 벡터 기반 통계적 이상치 탐지.
규칙 회피 공격에도 탐지 가능.

## 피처 벡터 구성 (14차원)

```
[0] total_events
[1] unique_event_names
[2] unique_ips
[3] high_risk_event_count
[4] failed_event_count
[5] off_hours_event_count
[6] consecutive_failures
[7] mfa_missing_high_risk
[8] admin_action_count
[9] unique_regions
[10] event_name_entropy   (Shannon 엔트로피)
[11] high_risk_ratio
[12] failure_ratio
[13] off_hours_ratio
```

## Risk Score 등급

| 점수 | 등급 | 의미 |
|------|------|------|
| 80+ | CRITICAL | 즉시 계정 비활성화 + 조사 |
| 60~79 | HIGH | 24시간 내 대응 필요 |
| 40~59 | MEDIUM | 주간 검토 권고 |
| 0~39 | LOW | 정기 모니터링 |
