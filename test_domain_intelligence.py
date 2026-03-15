"""
Test script for Domain Intelligence Layer and Model 4 integration.

Run with: python test_domain_intelligence.py
"""

import asyncio
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from src.domain_intelligence import DomainIntelligence
from src.model4_features import (
    extract_model4_features,
    shannon_entropy,
    count_parameters
)


async def test_feature_extraction():
    """Test Model 4 feature extraction."""
    print("\n" + "="*60)
    print("TEST: Feature Extraction")
    print("="*60)

    # Test cases
    test_cases = [
        {
            "name": "Google Search URL",
            "domain": "google.com",
            "url": "https://www.google.com/search?q=what+is+gogo+paper&oq=what+is+gogo",
            "threat_flags": {"type_defacement": 0.0, "type_malware": 0.0, "type_phishing": 0.0}
        },
        {
            "name": "GitHub URL",
            "domain": "github.com",
            "url": "https://github.com/anthropics/claude-code",
            "threat_flags": {"type_defacement": 0.0, "type_malware": 0.0, "type_phishing": 0.0}
        },
        {
            "name": "Suspicious Domain",
            "domain": "fake-paypal-login-secure.xyz",
            "url": "https://fake-paypal-login-secure.xyz/confirm",
            "threat_flags": {"type_defacement": 0.0, "type_malware": 0.0, "type_phishing": 1.0}
        }
    ]

    for test in test_cases:
        print(f"\n[OK] {test['name']}")
        print(f"  Domain: {test['domain']}")
        print(f"  URL: {test['url'][:60]}...")

        # Extract features
        features = extract_model4_features(
            domain=test["domain"],
            url=test["url"],
            threat_flags=test["threat_flags"]
        )

        print(f"  Features: {features}")
        print(f"    - feature1 (entropy): {features[0]:.4f}")
        print(f"    - id (param_count): {features[1]:.1f}")
        print(f"    - type_defacement: {features[2]}")
        print(f"    - type_malware: {features[3]}")
        print(f"    - type_phishing: {features[4]}")

        # Verify feature count
        assert len(features) == 5, f"Expected 5 features, got {len(features)}"
        print(f"  [OK] Correct feature count (5)")


def test_entropy_calculation():
    """Test Shannon entropy calculation."""
    print("\n" + "="*60)
    print("TEST: Shannon Entropy")
    print("="*60)

    test_cases = [
        ("google", 2.321),  # Low entropy
        ("abcdefgh", 3.0),  # High entropy
        ("aaaa", 0.0),      # Zero entropy
    ]

    for text, expected_approx in test_cases:
        entropy = shannon_entropy(text)
        print(f"[OK] shannon_entropy('{text}') = {entropy:.3f} (expected ~{expected_approx})")
        assert entropy >= 0, "Entropy should be non-negative"


def test_parameter_counting():
    """Test query parameter counting."""
    print("\n" + "="*60)
    print("TEST: Parameter Counting")
    print("="*60)

    test_cases = [
        ("https://example.com", 0),
        ("https://example.com?a=1", 1),
        ("https://example.com?a=1&b=2", 2),
        ("https://google.com/search?q=test&oq=test&gs_lcrp=xyz", 3),
    ]

    for url, expected in test_cases:
        params = count_parameters(url)
        print(f"[OK] count_parameters('{url[:40]}...') = {params} (expected {expected})")
        assert params == expected, f"Expected {expected} parameters, got {params}"


def test_domain_operations():
    """Test domain extraction and normalization."""
    print("\n" + "="*60)
    print("TEST: Domain Operations")
    print("="*60)

    # Test extraction
    test_urls = [
        ("https://google.com/search", "google.com"),
        ("http://WWW.GITHUB.COM/repo", "www.github.com"),
        ("https://api.example.com:8080/v1?key=123", "api.example.com:8080"),
    ]

    print("\nExtraction:")
    for url, expected_domain in test_urls:
        domain = DomainIntelligence.extract_domain(url)
        print(f"[OK] extract_domain('{url[:40]}...') = {domain}")
        assert domain is not None, f"Failed to extract domain from {url}"

    # Test normalization
    print("\nNormalization:")
    norm_tests = [
        ("WWW.EXAMPLE.COM", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
        ("WWW.Example.COM.", "example.com"),
    ]

    for domain, expected in norm_tests:
        normalized = DomainIntelligence.normalize_domain(domain)
        print(f"[OK] normalize_domain('{domain}') = '{normalized}'")
        assert normalized == expected, f"Expected {expected}, got {normalized}"


def test_heuristic_checks():
    """Test heuristic domain validation."""
    print("\n" + "="*60)
    print("TEST: Heuristic Checks")
    print("="*60)

    test_cases = [
        ("google.com", False, "major domain"),
        ("github.com", False, "legitimate domain"),
        ("login-secure-paypal-update-verification.xyz", True, "too many hyphens"),
        ("fake-paypal-secure-verify.biz", True, "suspicious keywords"),
        ("very-very-very-very-very-very-long-domain-name-with-many-characters.com", True, "too long"),
    ]

    for domain, should_be_suspicious, reason in test_cases:
        is_suspicious, reason_code = DomainIntelligence.heuristic_check(domain)
        status = "[OK] SUSPICIOUS" if is_suspicious else "[OK] NORMAL"
        print(f"{status}: '{domain[:50]}...' ({reason})")
        assert is_suspicious == should_be_suspicious, \
            f"Expected suspicious={should_be_suspicious} for '{domain}', got {is_suspicious}"


def test_threat_categorization():
    """Test threat type categorization from domains."""
    print("\n" + "="*60)
    print("TEST: Threat Categorization")
    print("="*60)

    test_cases = [
        ("bet365.com", "betting"),
        ("fake-phishing-site.net", "phishing"),
        ("malware-trojan-virus.biz", "malware"),
        ("hacked-defaced-site.xyz", "defacement"),
        ("legitimate-site.com", "unknown"),
    ]

    for domain, expected_category in test_cases:
        category = DomainIntelligence._categorize_threat(domain)
        print(f"[OK] categorize('{domain}') = '{category}' (expected '{expected_category}')")
        assert category == expected_category, f"Expected {expected_category}, got {category}"


async def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("DOMAIN INTELLIGENCE LAYER — COMPREHENSIVE TESTS")
    print("="*60)

    try:
        # Synchronous tests
        test_entropy_calculation()
        test_parameter_counting()
        test_domain_operations()
        test_heuristic_checks()
        test_threat_categorization()

        # Async tests
        await test_feature_extraction()

        print("\n" + "="*60)
        print("[PASS] ALL TESTS PASSED")
        print("="*60)

    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
