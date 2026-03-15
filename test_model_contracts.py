import sys

import numpy as np

sys.path.insert(0, "backend")

from src.multi_predict import (
    _coerce_model2_features,
    _engineer_model3_features,
    _extract_model1_features,
    _extract_model3_base,
)


def test_model1_feature_contract():
    raw_request = (
        "GET /login?user=admin' OR 1=1-- HTTP/1.1\n"
        "Host: example.com\n"
        "User-Agent: Chrome\n"
        "Cookie: session=abc123\n"
    )

    features = _extract_model1_features(raw_request)

    assert features.shape == (1, 11)
    assert features[0, 1] >= 1
    assert features[0, 2] == 1
    assert features[0, 6] >= 1
    assert features[0, 9] == len("session=abc123")
    assert features[0, 10] == len("Chrome")



def test_model2_feature_contract():
    features = [
        120000, 5400, 25, 12, 9, 450, 120,
        3000, 200, 3, 5, 0, 400, 1200,
    ]

    coerced = _coerce_model2_features(features)

    assert coerced is not None
    assert coerced.shape == (1, 14)
    assert coerced.dtype == np.float64



def test_model3_feature_contract():
    raw_request = "POST /api/login HTTP/1.1\nContent-Type: application/json\n\n{}"
    base_features = {
        "request_length": float(len(raw_request)),
        "shannon_entropy": 3.5,
    }

    base_vec = _extract_model3_base(raw_request, base_features)
    engineered = _engineer_model3_features(base_vec)

    assert base_vec.shape == (18,)
    assert engineered.shape == (1, 35)
    assert np.isfinite(engineered).all()
