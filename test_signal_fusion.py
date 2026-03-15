"""
Unit tests for signal fusion threat engine.

Tests verify that:
1. Threat scores are calculated correctly
2. Hard rules override threshold-based decisions
3. Request type detection works (API vs browser)
4. Signal fusion combines models equally
"""

import sys
import asyncio

# Add backend to path
sys.path.insert(0, "backend")

from src.threat_engine import (
    calculate_threat_scores,
    determine_verdict,
    ModelDetails,
    score_to_severity,
    get_threat_factors,
)
from src.multi_predict import MultiModelPredictor


def test_calculate_threat_scores_normal():
    """Test threat score for normal domain with normal traffic."""
    scores = calculate_threat_scores(
        model4_result={"classification": "normal"},
        anomaly_result={"traffic_anomaly": False, "bot_detected": False, "payload_attack": False},
        is_api_request=False
    )

    assert scores.url_threat_score == 0.0, "Normal domain should score 0.0"
    assert scores.traffic_anomaly_score == 0.1, "Normal traffic should score 0.1"
    assert scores.bot_activity_score == 0.1, "No bot should score 0.1"
    assert scores.payload_threat_score == 0.0, "Browser request (payload not applicable)"
    assert scores.overall_threat_score < 0.2, "Overall should be low for normal traffic"
    print("✓ test_calculate_threat_scores_normal PASSED")


def test_calculate_threat_scores_malware():
    """Test threat score for malware domain."""
    scores = calculate_threat_scores(
        model4_result={"classification": "malware"},
        anomaly_result={"traffic_anomaly": False, "bot_detected": False, "payload_attack": False},
        is_api_request=False
    )

    assert scores.url_threat_score == 1.0, "Malware should score 1.0"
    assert scores.overall_threat_score >= 0.25, "Overall should be high for malware"
    print("✓ test_calculate_threat_scores_malware PASSED")


def test_calculate_threat_scores_api_with_sqli():
    """Test threat score for API with SQL injection payload."""
    scores = calculate_threat_scores(
        model4_result={"classification": "normal"},
        anomaly_result={
            "traffic_anomaly": False,
            "bot_detected": False,
            "payload_attack": True
        },
        is_api_request=True
    )

    assert scores.is_api_request == True
    assert scores.payload_threat_score == 0.85, "Payload attack in API should score 0.85"
    assert scores.overall_threat_score >= 0.21, "API attack should raise overall score"
    print("✓ test_calculate_threat_scores_api_with_sqli PASSED")


def test_calculate_threat_scores_browser_ignores_payload():
    """Test that payload threat is ignored for browser requests."""
    scores = calculate_threat_scores(
        model4_result={"classification": "normal"},
        anomaly_result={
            "traffic_anomaly": False,
            "bot_detected": False,
            "payload_attack": True  # This will be ignored for browser
        },
        is_api_request=False
    )

    assert scores.is_api_request == False
    assert scores.payload_threat_score == 0.0, "Browser request should ignore payload score"
    print("✓ test_calculate_threat_scores_browser_ignores_payload PASSED")


def test_determine_verdict_malware_hard_rule():
    """Test that malware domains always get DANGEROUS verdict."""
    model_details = ModelDetails(
        model4_classification="malware",
        model4_confidence=0.99,
        traffic_anomaly_detected=False,
        bot_activity_detected=False,
        payload_attack_detected=False,
        payload_threat_type=None,
        is_api_request=False
    )

    verdict, recommendation = determine_verdict(0.1, model_details)  # Even low score

    assert verdict == "DANGEROUS", "Malware should always be DANGEROUS"
    assert "malware domain" in recommendation.lower(), "Recommendation should mention malware"
    print("✓ test_determine_verdict_malware_hard_rule PASSED")


def test_determine_verdict_bot_and_traffic_hard_rule():
    """Test that bot + traffic anomaly combo triggers DANGEROUS."""
    model_details = ModelDetails(
        model4_classification="normal",
        model4_confidence=0.5,
        traffic_anomaly_detected=True,
        bot_activity_detected=True,
        payload_attack_detected=False,
        payload_threat_type=None,
        is_api_request=False
    )

    verdict, recommendation = determine_verdict(0.4, model_details)  # Would be CAUTION alone

    assert verdict == "DANGEROUS", "Bot + traffic anomaly should be DANGEROUS"
    assert "bot activity" in recommendation.lower(), "Recommendation should mention bot"
    print("✓ test_determine_verdict_bot_and_traffic_hard_rule PASSED")


def test_determine_verdict_api_sqli_hard_rule():
    """Test that API SQLi attack triggers DANGEROUS."""
    model_details = ModelDetails(
        model4_classification="normal",
        model4_confidence=0.5,
        traffic_anomaly_detected=False,
        bot_activity_detected=False,
        payload_attack_detected=True,
        payload_threat_type="SQL Injection",
        is_api_request=True
    )

    verdict, recommendation = determine_verdict(0.2, model_details)

    assert verdict == "DANGEROUS", "SQL Injection in API should be DANGEROUS"
    assert "sql injection" in recommendation.lower(), "Should mention attack type"
    print("✓ test_determine_verdict_api_sqli_hard_rule PASSED")


def test_determine_verdict_thresholds():
    """Test threshold-based verdicts (no hard rules)."""
    model_details = ModelDetails(
        model4_classification="normal",
        model4_confidence=0.5,
        traffic_anomaly_detected=False,
        bot_activity_detected=False,
        payload_attack_detected=False,
        payload_threat_type=None,
        is_api_request=False
    )

    # Test each threshold
    verdict_safe, _ = determine_verdict(0.1, model_details)
    assert verdict_safe == "SAFE", " 0.1 score should be SAFE"

    verdict_caution, _ = determine_verdict(0.3, model_details)
    assert verdict_caution == "CAUTION", "0.3 score should be CAUTION"

    verdict_suspicious, _ = determine_verdict(0.6, model_details)
    assert verdict_suspicious == "SUSPICIOUS", "0.6 score should be SUSPICIOUS"

    verdict_dangerous, _ = determine_verdict(0.85, model_details)
    assert verdict_dangerous == "DANGEROUS", "0.85 score should be DANGEROUS"

    print("✓ test_determine_verdict_thresholds PASSED")


def test_is_api_request_post():
    """Test API request detection for POST."""
    predictor = MultiModelPredictor.__new__(MultiModelPredictor)

    req_post = "POST /api/login HTTP/1.1\nContent-Type: application/json"
    assert predictor._is_api_request(req_post) == True, "POST should be API"

    req_get = "GET /home HTTP/1.1\nUser-Agent: Chrome"
    assert predictor._is_api_request(req_get) == False, "GET should be browser"

    print("✓ test_is_api_request_post PASSED")


def test_is_api_request_content_type():
    """Test API request detection by content-type."""
    predictor = MultiModelPredictor.__new__(MultiModelPredictor)

    req_json = "GET /api HTTP/1.1\nContent-Type: application/json"
    assert predictor._is_api_request(req_json) == True, "JSON content should be API"

    req_xml = "GET /api HTTP/1.1\nContent-Type: application/xml"
    assert predictor._is_api_request(req_xml) == True, "XML content should be API"

    req_html = "GET /home HTTP/1.1\nContent-Type: text/html"
    assert predictor._is_api_request(req_html) == False, "HTML should be browser"

    print("✓ test_is_api_request_content_type PASSED")


def test_score_to_severity():
    """Test threat score to severity mapping."""
    assert score_to_severity(0.05) == "LOW", "0.05 should be LOW"
    assert score_to_severity(0.25) == "MEDIUM", "0.25 should be MEDIUM"
    assert score_to_severity(0.65) == "HIGH", "0.65 should be HIGH"
    assert score_to_severity(0.9) == "CRITICAL", "0.9 should be CRITICAL"
    print("✓ test_score_to_severity PASSED")


def test_get_threat_factors():
    """Test threat factor extraction."""
    model_details = ModelDetails(
        model4_classification="malware",
        model4_confidence=0.99,
        traffic_anomaly_detected=True,
        bot_activity_detected=True,
        payload_attack_detected=True,
        payload_threat_type="XSS Attack",
        is_api_request=True
    )

    factors = get_threat_factors(model_details)

    assert "malware domain" in factors, "Should detect malware domain"
    assert "anomalous traffic" in factors, "Should detect anomalous traffic"
    assert "bot activity" in factors, "Should detect bot activity"
    assert "xss attack" in factors.lower(), "Should detect XSS attack"

    print("✓ test_get_threat_factors PASSED")


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("Signal Fusion Threat Engine - Unit Tests")
    print("="*70 + "\n")

    tests = [
        test_calculate_threat_scores_normal,
        test_calculate_threat_scores_malware,
        test_calculate_threat_scores_api_with_sqli,
        test_calculate_threat_scores_browser_ignores_payload,
        test_determine_verdict_malware_hard_rule,
        test_determine_verdict_bot_and_traffic_hard_rule,
        test_determine_verdict_api_sqli_hard_rule,
        test_determine_verdict_thresholds,
        test_is_api_request_post,
        test_is_api_request_content_type,
        test_score_to_severity,
        test_get_threat_factors,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} ERROR: {e}")
            failed += 1

    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*70 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
