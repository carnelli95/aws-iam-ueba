"""
parser.py 단위 테스트
실행: pytest tests/test_parser.py -v
"""
import json
from pathlib import Path

import pytest

from app.services.parser import parse_file, parse_raw_json


SAMPLE_LOG_PATH = Path(__file__).parent / "sample_logs" / "sample_cloudtrail.json"


def test_parse_file_returns_events():
    events = parse_file(SAMPLE_LOG_PATH)
    assert len(events) == 11


def test_parse_file_fields():
    events = parse_file(SAMPLE_LOG_PATH)
    alice_events = [e for e in events if "alice" in e.user_arn]
    assert len(alice_events) == 4
    for e in alice_events:
        assert e.account_id == "123456789012"
        assert not e.mfa_used  # alice는 모두 MFA 미사용


def test_high_risk_events_flagged():
    events = parse_file(SAMPLE_LOG_PATH)
    high_risk = [e for e in events if e.is_high_risk]
    high_risk_names = {e.event_name for e in high_risk}
    assert "CreateAccessKey" in high_risk_names
    assert "AttachUserPolicy" in high_risk_names
    assert "CreateUser" in high_risk_names


def test_error_code_parsed():
    events = parse_file(SAMPLE_LOG_PATH)
    error_events = [e for e in events if e.error_code]
    assert len(error_events) >= 5  # charlie의 연속 실패


def test_parse_raw_json():
    with open(SAMPLE_LOG_PATH, "rb") as f:
        content = f.read()
    events = parse_raw_json(content)
    assert len(events) == 11


def test_parse_raw_json_invalid_raises():
    with pytest.raises(ValueError):
        parse_raw_json('{"not_records": []}')


def test_parse_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_file("/nonexistent/path/log.json")
