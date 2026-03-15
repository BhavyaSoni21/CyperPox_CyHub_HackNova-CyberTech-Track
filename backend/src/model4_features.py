"""
CyHub — Model 4 Feature Engineering

Extracts and preprocesses the 5-feature vector required by Model 4
(URL domain classification: normal|adult|betting|malware).

Features:
  1. feature1: Shannon entropy of domain
  2. id: Number of query parameters
  3. type_defacement: Binary flag (0.0 or 1.0)
  4. type_malware: Binary flag (0.0 or 1.0)
  5. type_phishing: Binary flag (0.0 or 1.0)
"""

from __future__ import annotations

import math
import logging
from typing import List, Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    Measures randomness/disorder in the text (0-8 bits typically).
    High entropy suggests encoded/obfuscated data.

    Args:
        text: String to analyze

    Returns:
        Entropy value in bits (0 = uniform, high = random)

    Example:
        shannon_entropy("aaaa") → 0.0 (no randomness)
        shannon_entropy("abc") → 1.585 (high randomness)
    """
    if not text:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy: H = -Σ(p_i * log2(p_i))
    entropy = 0.0
    text_length = len(text)
    for count in char_counts.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def count_parameters(url: str) -> int:
    """Count query parameters in URL.

    Args:
        url: Full URL (e.g., https://example.com?a=1&b=2)

    Returns:
        Number of query parameters (count of = signs)

    Example:
        count_parameters("https://example.com?a=1&b=2") → 2
        count_parameters("https://example.com") → 0
    """
    try:
        parsed = urlparse(url)
        query_string = parsed.query
        if not query_string:
            return 0
        # Count equals signs in query string
        return query_string.count("=")
    except Exception as e:
        logger.warning(f"Error counting parameters in URL: {e}")
        return 0


def extract_model4_features(
    domain: str,
    url: str,
    threat_flags: Dict[str, float]
) -> List[float]:
    """Extract 5-feature vector for Model 4 prediction.

    This function must match the preprocessing pipeline used during
    Model 4 training (StandardScaler on features, not scaling threat flags).

    Args:
        domain: Normalized domain (e.g., github.com)
        url: Full URL with query parameters
        threat_flags: Dict with type_defacement, type_malware, type_phishing

    Returns:
        5-element list: [feature1, id, type_def, type_mal, type_phish]
        Ready to send to Model 4 API as-is (no scaling here)

    Note:
        The Model 4 training pipeline expects StandardScaler applied to
        numerical features. We apply scaling during preprocessing, before
        this function is called. This function just extracts raw values.
    """
    # feature1: Shannon entropy of domain
    feature1 = shannon_entropy(domain)

    # id: Number of query parameters in URL
    param_count = count_parameters(url)
    id_value = float(param_count)

    # Threat flags from Domain Intelligence Layer
    type_defacement = threat_flags.get("type_defacement", 0.0)
    type_malware = threat_flags.get("type_malware", 0.0)
    type_phishing = threat_flags.get("type_phishing", 0.0)

    # Return 5-feature vector
    features = [
        float(feature1),
        float(id_value),
        float(type_defacement),
        float(type_malware),
        float(type_phishing)
    ]

    logger.debug(
        f"Extracted Model 4 features for '{domain}': "
        f"entropy={feature1:.3f}, params={param_count}, "
        f"def={type_defacement}, mal={type_malware}, phish={type_phishing}"
    )

    return features


def scale_features(
    features: List[float],
    scaler=None
) -> List[float]:
    """Apply StandardScaler to numerical features (feature1 and id).

    Note: This requires the scaler to be fitted on the training data.
    For now, we'll skip scaling and let the Model 4 API handle it,
    or use the existing scaler from feature_engineering.py.

    Args:
        features: 5-element feature list [feature1, id, type_def, type_mal, type_phish]
        scaler: StandardScaler instance (optional). If None, return as-is.

    Returns:
        Features with numericals scaled (or unchanged if no scaler provided)
    """
    if scaler is None:
        logger.debug("No scaler provided, returning features as-is")
        return features

    try:
        # Only scale the first two features (feature1 and id)
        feature1_scaled = float(scaler.transform([[features[0]]])[0][0])
        id_scaled = float(scaler.transform([[features[1]]])[0][0])

        scaled_features = [
            feature1_scaled,
            id_scaled,
            features[2],  # type_defacement (unchanged)
            features[3],  # type_malware (unchanged)
            features[4]   # type_phishing (unchanged)
        ]

        return scaled_features

    except Exception as e:
        logger.warning(f"Error scaling features: {e}. Returning unscaled.")
        return features


def preprocess_for_model4(
    domain: str,
    url: str,
    threat_flags: Dict[str, float],
    scaler=None
) -> List[float]:
    """Complete preprocessing pipeline for Model 4.

    Combines feature extraction + scaling.

    Args:
        domain: Normalized domain
        url: Full URL
        threat_flags: Threat classification flags
        scaler: Optional StandardScaler for numerical features

    Returns:
        Final 5-feature vector ready for Model 4 API
    """
    # Extract raw features
    features = extract_model4_features(domain, url, threat_flags)

    # Scale numerical features if scaler provided
    if scaler:
        features = scale_features(features, scaler)

    return features
