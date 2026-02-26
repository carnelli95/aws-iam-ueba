"""
이상탐지 파이프라인 통합 테스트
parser → feature_engineer → anomaly_engine → risk_scoring
실행: pytest tests/test_anomaly.py -v
"""
from pathlib import Path

from app.services.anomaly_engine import AnomalyEngine
from app.services.feature_engineer import extract_user_features
from app.services.parser import parse_file
from app.services.risk_scoring import calculate_risk_score, rank_users


SAMPLE_LOG_PATH = Path(__file__).parent / "sample_logs" / "sample_cloudtrail.json"


def _run_full_pipeline():
    events = parse_file(SAMPLE_LOG_PATH)
    features = extract_user_features(events)
    engine = AnomalyEngine(ml_threshold=0.0)
    detection_results = engine.detect(features)
    features_map = {uf.user_arn: uf for uf in features}
    risk_scores = [
        calculate_risk_score(dr, features_map[dr.user_arn])
        for dr in detection_results
    ]
    return events, features, detection_results, risk_scores


def test_full_pipeline_runs():
    _, _, detection_results, risk_scores = _run_full_pipeline()
    assert len(detection_results) == 3  # alice, bob, charlie
    assert len(risk_scores) == 3


def test_alice_detected_as_anomaly():
    """alice는 야간 MFA 미사용 + 다중 IP + 관리자 액션으로 탐지 필수."""
    _, _, detection_results, _ = _run_full_pipeline()
    alice_result = next(r for r in detection_results if "alice" in r.user_arn)
    assert alice_result.is_anomaly, "alice는 이상으로 탐지되어야 함"
    assert "R03_HIGH_RISK_NO_MFA" in alice_result.triggered_rules
    assert "R01_OFF_HOURS_ACCESS" in alice_result.triggered_rules


def test_charlie_detected_consecutive_failures():
    """charlie는 5회 연속 AccessDenied — R06 탐지."""
    _, _, detection_results, _ = _run_full_pipeline()
    charlie_result = next(r for r in detection_results if "charlie" in r.user_arn)
    assert charlie_result.is_anomaly
    assert "R06_CONSECUTIVE_FAILURES" in charlie_result.triggered_rules


def test_risk_scores_in_range():
    _, _, _, risk_scores = _run_full_pipeline()
    for rs in risk_scores:
        assert 0.0 <= rs.score <= 100.0


def test_alice_has_highest_risk():
    _, _, _, risk_scores = _run_full_pipeline()
    ranked = rank_users(risk_scores)
    assert "alice" in ranked[0].user_arn


def test_recommendations_not_empty():
    _, _, _, risk_scores = _run_full_pipeline()
    for rs in risk_scores:
        if rs.level in ("CRITICAL", "HIGH"):
            assert len(rs.recommendations) > 0


def test_risk_levels_valid():
    _, _, _, risk_scores = _run_full_pipeline()
    valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for rs in risk_scores:
        assert rs.level in valid_levels
