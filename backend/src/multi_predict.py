"""
CyHub — Multi-Model Prediction Pipeline

Context-aware threat detection pipeline with a model router:

  Model 1  Payload / Injection Attack (HuggingFace Space) — API requests with payload only
  Model 2  Bot / Botnet Activity      (HuggingFace Space) — only when 14 flow features provided
  Model 3  Network Traffic Anomaly    (HuggingFace Space) — only when 14 flow features provided

Models are scheduled conditionally:
  has_payload AND is_api  → Model 1 runs
  has_flow_features       → Model 2 + Model 3 run

No gatekeeper: the base IsolationForest contributes its anomaly_score as one signal — NOT
as a gatekeeper that blocks other models from running.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import joblib
import numpy as np
import httpx

warnings.filterwarnings("ignore")

# ── helpers imported from existing feature engineering ──────────────────────
from src.feature_engineering import (
    FEATURE_COLUMNS,
    compute_script_tag_score,
    compute_shannon_entropy,
    compute_sql_keyword_score,
    count_special_chars,
    extract_features,
)

# ── constants ────────────────────────────────────────────────────────────────
_MODEL1_HF_URL = os.getenv("HF_MODEL1_URL", "https://bhavyasoni21-model1.hf.space/predict")
_MODEL2_HF_URL = os.getenv("HF_MODEL2_URL", "https://bhavyasoni21-model2.hf.space/predict")
_MODEL3_HF_URL = os.getenv("HF_MODEL3_URL", "https://bhavyasoni21-model3.hf.space/predict")
_MODEL1_TIMEOUT = float(os.getenv("HF_MODEL1_TIMEOUT", "8.0"))
_MODEL2_TIMEOUT = float(os.getenv("HF_MODEL2_TIMEOUT", "8.0"))
_MODEL3_TIMEOUT = float(os.getenv("HF_MODEL3_TIMEOUT", "8.0"))

_HF_API_TOKEN = os.getenv("HF_API_TOKEN", "").strip()

# ── M1 Payload Result Cache (reduces HF calls for repeated/similar payloads) ─
# Keyed by the Model 1 feature-vector bytes; results expire after TTL seconds.
_PAYLOAD_CACHE: Dict[bytes, Tuple[Tuple[bool, Optional[float]], float]] = {}
_PAYLOAD_CACHE_TTL = 60.0       # seconds — short TTL; threats can change

# ── Shared httpx client (connection pooling) ─────────────────────────────────
_shared_client: Optional[httpx.AsyncClient] = None


async def get_shared_client() -> httpx.AsyncClient:
    """Get or create the shared async HTTP client with connection pooling."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            timeout=httpx.Timeout(10.0, connect=5.0),
        )
    return _shared_client


async def close_shared_client() -> None:
    """Close the shared client on shutdown."""
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
        _shared_client = None


# ─────────────────────────────────────────────────────────────────────────────
#  Feature extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

_MODEL1_PATH_TRAVERSAL_PATTERNS = ("../", "..\\", "%2e%2e", "..%2f", "%2f", "%5c")


def _parse_raw_request(raw_request: str) -> Dict[str, str]:
    """Split a raw HTTP request into request-line, headers, and body fields."""
    lines = [line.rstrip("\r") for line in raw_request.splitlines()]
    request_line = lines[0].strip() if lines else ""
    parts = request_line.split()

    method = parts[0] if len(parts) >= 1 else ""
    url = parts[1] if len(parts) >= 2 else ""

    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if not line.strip():
                in_body = True
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
                continue
        body_lines.append(line)

    return {
        "method": method,
        "url": url,
        "content": "\n".join(body_lines).strip(),
        "cookie": headers.get("cookie", ""),
        "user_agent": headers.get("user-agent", ""),
    }


def _safe_url_depth(url: str) -> float:
    path = urlsplit(url).path or url.split("?", 1)[0]
    return float(len([segment for segment in path.split("/") if segment]))


def _safe_parameter_count(url: str) -> float:
    query = urlsplit(url).query
    if query:
        return float(len(parse_qsl(query, keep_blank_values=True)))
    return float(url.count("="))


def _extract_model1_features(raw_request: str) -> np.ndarray:
    """Build the 11-feature vector expected by Model 1."""
    parsed = _parse_raw_request(raw_request)
    method = parsed["method"]
    url = parsed["url"]
    content = parsed["content"]
    cookie = parsed["cookie"]
    user_agent = parsed["user_agent"]

    request_length = float(len(raw_request))
    payload_text = "\n".join(filter(None, [method, url, content, cookie, user_agent, raw_request]))
    digit_ratio = (
        sum(char.isdigit() for char in payload_text) / max(1, len(payload_text))
    )
    lower_raw = raw_request.lower()
    path_traversal_score = float(any(pattern in lower_raw for pattern in _MODEL1_PATH_TRAVERSAL_PATTERNS))

    return np.array([[
        request_length,
        _safe_url_depth(url),
        _safe_parameter_count(url),
        float(count_special_chars(payload_text)),
        float(digit_ratio),
        float(compute_shannon_entropy(payload_text)),
        float(compute_sql_keyword_score(payload_text)),
        float(compute_script_tag_score(payload_text)),
        path_traversal_score,
        float(len(cookie)),
        float(len(user_agent)),
    ]])


def _heuristic_bot_score(features: List[float]) -> Tuple[bool, float, str]:
    """
    Local heuristic bot detection based on 14 flow features.
    Used as fallback when HF Model 2 is unavailable.

    Returns: (is_bot, score, bot_type)

    Features:
      0  flow_duration
      1  packet_count
      2  unique_urls
      3  request_rate
      4  url_repetition_ratio
      5  unique_user_agents
      6  iat_mean
      7  iat_std
      8  iat_min
      9  iat_max
      10 burst_ratio
      11 hour_of_day
      12 url_entropy
      13 session_depth_mean
    """
    if len(features) != 14:
        return False, 0.0, "normal"

    flow_duration = features[0]
    packet_count = features[1]
    unique_urls = features[2]
    request_rate = features[3]
    url_repetition_ratio = features[4]
    iat_mean = features[6]
    iat_std = features[7]
    iat_min = features[8]
    burst_ratio = features[10]
    url_entropy = features[12]

    score = 0.0
    signals = []

    # High request rate (> 0.5 req/sec is suspicious for sustained traffic)
    if request_rate > 0.5:
        score += min(0.30, (request_rate - 0.5) * 0.20)
        if request_rate > 1.0:
            signals.append("high_rate")

    # Robot-like regularity: very low variance in timing
    # iat_std = 0 means perfectly regular intervals (very bot-like)
    if iat_mean > 0:
        regularity = iat_std / (iat_mean + 0.001)
        if regularity < 0.1:  # Nearly perfect regularity
            score += 0.35
            signals.append("regular_timing")
        elif regularity < 0.3:  # Very regular
            score += 0.20
            signals.append("regular_timing")

    # Very short inter-arrival times combined with volume
    if iat_mean <= 2.0 and packet_count >= 5:
        score += 0.15
        signals.append("rapid_requests")

    # High URL repetition (brute-force pattern)
    if url_repetition_ratio > 0.8:
        score += 0.30
        signals.append("url_hammering")
    elif url_repetition_ratio > 0.5:
        score += 0.15

    # Low URL diversity relative to requests (hitting same few endpoints)
    if packet_count > 5 and unique_urls <= 2:
        score += 0.20
        signals.append("low_diversity")

    # High burst ratio (many requests in short time)
    if burst_ratio > 0.8:
        score += 0.15
        signals.append("burst")
    elif burst_ratio > 0.6:
        score += 0.10

    # Low URL entropy with significant traffic (predictable patterns)
    if url_entropy < 1.5 and packet_count > 4:
        score += 0.10

    # Clamp to [0, 1]
    score = min(1.0, max(0.0, score))
    is_bot = score >= 0.45  # Slightly lower threshold

    # Determine bot type based on signals
    bot_type = "normal"
    if is_bot:
        if "url_hammering" in signals and "regular_timing" in signals:
            # Check if it's a health-check (low volume) vs brute-force (high volume)
            if packet_count <= 5:
                bot_type = "health-check bot"
            else:
                bot_type = "brute-force bot"
        elif "url_hammering" in signals and packet_count <= 5:
            bot_type = "health-check bot"
        elif "url_hammering" in signals:
            bot_type = "credential stuffing bot"
        elif "high_rate" in signals and "rapid_requests" in signals and unique_urls > 5:
            bot_type = "scraper bot"
        elif "regular_timing" in signals and packet_count <= 5:
            bot_type = "health-check bot"
        elif "regular_timing" in signals and "rapid_requests" in signals:
            bot_type = "scraper bot"
        elif "burst" in signals:
            bot_type = "DDoS bot"
        else:
            bot_type = "suspicious bot"

    return is_bot, score, bot_type


def _coerce_model2_features(model2_flow_features: Optional[List[float]]) -> Optional[np.ndarray]:
    """Validate a true 14-feature network-flow vector for Model 2."""
    if model2_flow_features is None:
        return None

    arr = np.asarray(model2_flow_features, dtype=np.float64)
    if arr.shape != (14,):
        raise ValueError("Model 2 requires exactly 14 flow features")
    if not np.all(np.isfinite(arr)):
        raise ValueError("Model 2 flow features contain NaN or Inf")
    return arr.reshape(1, -1)


def _extract_model3_base(request: str, base: Dict[str, float]) -> np.ndarray:
    """
    Build the 18-feature base vector for Model 3 (traffic classifier).
    """
    req_len = base["request_length"]
    entropy = base["shannon_entropy"]

    tot_fwd_pkts = max(1.0, math.ceil(req_len / 1500.0))
    tot_bwd_pkts = 0.0
    total_fwd_len = req_len
    total_bwd_len = 0.0
    avg_pkt_size = req_len / max(1.0, tot_fwd_pkts)
    pkt_len_std = entropy * 8.0
    flow_duration = max(1.0, req_len * 0.1)
    flow_bytes_s = (req_len + 0.0) / max(1.0, flow_duration / 1000.0)
    pkts_per_s = max(1.0, tot_fwd_pkts / max(0.001, flow_duration / 1000.0))
    iat_mean = flow_duration / max(1.0, tot_fwd_pkts)
    iat_std = abs(entropy - 3.5) * 4.0
    iat_max = iat_mean * 2.0
    active_mean = flow_duration
    active_std = iat_std
    idle_mean = 0.0
    idle_std = 0.0
    idle_max = 0.0

    return np.array([
        flow_duration, flow_bytes_s, pkts_per_s,
        tot_fwd_pkts, tot_bwd_pkts,
        total_fwd_len, total_bwd_len,
        avg_pkt_size, pkt_len_std, avg_pkt_size,
        iat_mean, iat_std, iat_max,
        active_mean, active_std, idle_mean, idle_std, idle_max,
    ])


_LOG_COLS = [
    "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Idle Mean", "Idle Std", "Idle Max",
]
_BASE_COLS = [
    "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
    "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Packet Length Mean", "Packet Length Std", "Average Packet Size",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Active Mean", "Active Std", "Idle Mean", "Idle Std", "Idle Max",
]

def _engineer_model3_features(base_vec: np.ndarray) -> np.ndarray:
    """
    Apply the same feature engineering used during Model 3 training.
    Returns a 35-element vector.
    """
    d = dict(zip(_BASE_COLS, base_vec))
    eps = 1e-9

    log_vals = [math.log1p(max(0.0, d[c])) for c in _LOG_COLS]

    fwd_bwd_pkt_ratio = d["Total Fwd Packet"] / (d["Total Bwd packets"] + eps)
    fwd_bwd_len_ratio = d["Total Length of Fwd Packet"] / (d["Total Length of Bwd Packet"] + eps)
    bytes_per_pkt = (
        (d["Total Length of Fwd Packet"] + d["Total Length of Bwd Packet"])
        / (d["Total Fwd Packet"] + d["Total Bwd packets"] + eps)
    )
    iat_variability = d["Flow IAT Std"] / (d["Flow IAT Mean"] + eps)
    pkt_std_to_mean = d["Packet Length Std"] / (d["Packet Length Mean"] + eps)
    active_idle_ratio = d["Active Mean"] / (d["Idle Mean"] + eps)

    engineered = np.array(log_vals + [
        fwd_bwd_pkt_ratio, fwd_bwd_len_ratio, bytes_per_pkt,
        iat_variability, pkt_std_to_mean, active_idle_ratio,
    ])

    engineered = np.where(np.isfinite(engineered), engineered, 0.0)

    return np.concatenate([base_vec, engineered]).reshape(1, -1)


# ─────────────────────────────────────────────────────────────────────────────
#  Multi-model predictor
# ─────────────────────────────────────────────────────────────────────────────

class MultiModelPredictor:
    """
    Context-aware threat pipeline — models only run when they have valid input.

    Model routing:
      Model 1 (payload): runs when raw_request is non-empty AND it's an API request
      Model 2 (bot):     runs when 14 network flow features are provided
      Model 3 (traffic): runs when 14 network flow features are provided

    No gatekeeper: the base IsolationForest score is one input to the
    fusion engine, not a gate that blocks Models 2 & 3 from running.
    """

    def __init__(
        self,
        base_model_path: Optional[str] = None,
    ):
        """
        Initialize MultiModelPredictor.

        Base model is now OPTIONAL. Only Models 1-4 (HuggingFace) are used for predictions.
        If base_model_path is None or not found, base anomaly scoring is skipped.
        """
        self._base_remote_url = ""
        self._base_model = None
        self._base_scaler = None
        self._base_feature_columns = FEATURE_COLUMNS

        # Base model is optional — skip if not provided
        if not base_model_path:
            print("[INFO] Base model disabled (not configured)")
            return

        if base_model_path.startswith(("http://", "https://")):
            self._base_remote_url = base_model_path
            print(f"[INFO] Base model configured as remote endpoint: {self._base_remote_url}")
        else:
            env_base_url = os.getenv("HF_BASE_MODEL_URL", "").strip()
            if env_base_url:
                self._base_remote_url = env_base_url
                print(f"[INFO] Base model remote endpoint from HF_BASE_MODEL_URL: {self._base_remote_url}")

        base_pipeline = None
        if not self._base_remote_url:
            if not os.path.exists(base_model_path):
                print(f"[INFO] Base model not found at {base_model_path} — skipping base anomaly detection")
                return
            base_pipeline = joblib.load(base_model_path)

        if base_pipeline:
            self._base_model = base_pipeline["model"]
            self._base_scaler = base_pipeline["scaler"]
            self._base_feature_columns = base_pipeline["feature_columns"]
            print("[INFO] Base model loaded successfully")

    @staticmethod
    def _is_api_request(raw_request: str) -> bool:
        """Detect if this is an API call vs browser request."""
        if not raw_request:
            return False
        api_methods = ("POST", "PUT", "DELETE", "PATCH")
        is_api_method = any(raw_request.startswith(m) for m in api_methods)
        is_api_content = (
            "application/json" in raw_request or
            "application/xml" in raw_request or
            "application/x-www-form-urlencoded" in raw_request
        )
        return is_api_method or is_api_content

    @staticmethod
    def _build_hf_headers() -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if _HF_API_TOKEN:
            headers["Authorization"] = f"Bearer {_HF_API_TOKEN}"
        return headers

    @staticmethod
    def _extract_payload(data: Any) -> Any:
        if isinstance(data, list):
            return data[0] if data else {}
        return data

    @staticmethod
    def _parse_confidence(data: Any) -> Optional[float]:
        """Extract probability/confidence score from HF response.

        Returns a 0.0–1.0 float if found, or None if the response
        contained no recognisable confidence key (model unavailable /
        response shape unknown).
        """
        payload = MultiModelPredictor._extract_payload(data)
        if not isinstance(payload, dict):
            return None
        for key in (
            "confidence",
            "score",
            "probability",
            "prob",
            "confidence_score",
            "attack_probability",
        ):
            if key in payload:
                try:
                    val = float(payload[key])
                    if val > 1.0:
                        val /= 100.0
                    return round(min(1.0, max(0.0, val)), 4)
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _parse_bool_prediction(
        data: Any,
        positive_labels: set[str],
        positive_values: set[int],
    ) -> Optional[bool]:
        payload = MultiModelPredictor._extract_payload(data)

        if isinstance(payload, bool):
            return payload
        if isinstance(payload, (int, float)):
            return int(payload) in positive_values
        if not isinstance(payload, dict):
            return None

        for key in ("raw_prediction", "prediction", "label", "class", "predicted_class", "result"):
            if key not in payload:
                continue
            value = payload[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return int(value) in positive_values
            if isinstance(value, str):
                normalized = value.strip().lower().replace(" ", "_")
                return normalized in positive_labels

        return None

    @staticmethod
    async def _post_json_async(url: str, payload: Dict[str, Any], timeout: float) -> Optional[Any]:
        """Async POST using shared connection-pooled client."""
        if not url:
            return None
        try:
            client = await get_shared_client()
            response = await client.post(
                url,
                json=payload,
                headers=MultiModelPredictor._build_hf_headers(),
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[WARN] HuggingFace async request failed ({url}): {e}")
            return None

    def _predict_base_local(self, features: Dict[str, float]) -> Tuple[float, bool]:
        """Run base IsolationForest locally."""
        feature_values = np.array([[features[col] for col in self._base_feature_columns]])
        scaled = self._base_scaler.transform(feature_values)
        anomaly_score = float(self._base_model.decision_function(scaled)[0])
        return anomaly_score, anomaly_score < 0

    async def _predict_base_remote(self, features: Dict[str, float]) -> Tuple[float, bool]:
        """Run base IsolationForest via remote HF endpoint."""
        feature_values = [features[col] for col in self._base_feature_columns]
        payload = {
            "features": feature_values,
            "inputs": feature_values,
            "feature_columns": self._base_feature_columns,
        }
        data = await self._post_json_async(
            self._base_remote_url,
            payload,
            float(os.getenv("HF_BASE_MODEL_TIMEOUT", "8.0")),
        )
        if data is None:
            raise RuntimeError("Base HuggingFace model request failed")

        parsed = self._extract_payload(data)
        if not isinstance(parsed, dict):
            bool_pred = self._parse_bool_prediction(
                parsed,
                positive_labels={"suspicious", "anomaly", "attack", "anomalous", "outlier", "-1"},
                positive_values={-1, 1},
            )
            if bool_pred is None:
                raise RuntimeError("Unrecognized base model response shape")
            return (1.0 if not bool_pred else -1.0), bool_pred

        score = parsed.get("anomaly_score", parsed.get("score"))
        bool_pred = self._parse_bool_prediction(
            parsed,
            positive_labels={"suspicious", "anomaly", "attack", "anomalous", "outlier", "-1"},
            positive_values={-1},
        )

        if score is None and bool_pred is None:
            raise RuntimeError("Base model response missing score and prediction")

        if score is None:
            score = -1.0 if bool_pred else 1.0
        score = float(score)

        if bool_pred is None:
            bool_pred = score < 0

        return score, bool_pred

    # ── individual model predictions ──────────────────────────────────────

    async def _predict_traffic(self, request: str, base: Dict[str, float]) -> Tuple[bool, Optional[float]]:
        """Returns (is_anomalous, confidence) from Model 3 via HuggingFace Space."""
        base_vec = _extract_model3_base(request, base)
        X35 = _engineer_model3_features(base_vec)

        data = await self._post_json_async(
            _MODEL3_HF_URL,
            {"features": X35.flatten().tolist(), "inputs": X35.flatten().tolist()},
            _MODEL3_TIMEOUT,
        )
        if data is None:
            return False, None

        remote_result = self._parse_bool_prediction(
            data,
            positive_labels={"traffic_anomaly", "anomaly", "suspicious", "attack", "attack_detected", "-1"},
            positive_values={-1},
        )
        confidence = self._parse_confidence(data)
        if remote_result is not None:
            return remote_result, confidence
        return False, confidence

    async def _predict_bot(self, model2_flow_features: Optional[List[float]]) -> Tuple[bool, Optional[float], str]:
        """Returns (is_bot, confidence, bot_type) from Model 2 via HuggingFace Space.

        Falls back to local heuristics if HF model is unavailable.
        """
        X14 = _coerce_model2_features(model2_flow_features)
        if X14 is None:
            print("[DEBUG] Model 2: No flow features provided")
            return False, None, "normal"

        features_list = X14.flatten().tolist()
        print(f"[DEBUG] Model 2: Sending {len(features_list)} features to {_MODEL2_HF_URL}")

        data = await self._post_json_async(
            _MODEL2_HF_URL,
            {"features": features_list, "inputs": features_list},
            _MODEL2_TIMEOUT,
        )

        if data is None:
            print("[DEBUG] Model 2: HF endpoint failed, using heuristic fallback")
            is_bot, score, bot_type = _heuristic_bot_score(features_list)
            print(f"[DEBUG] Model 2 heuristic: is_bot={is_bot}, score={score:.4f}, type={bot_type}")
            return is_bot, score, bot_type

        print(f"[DEBUG] Model 2 raw response: {data}")

        result = self._parse_bool_prediction(
            data,
            positive_labels={"bot_detected", "bot", "malicious", "attack", "1"},
            positive_values={1},
        )
        confidence = self._parse_confidence(data)

        # If HF model returned but confidence is missing, use heuristics
        # (0.0% confidence is meaningless - better to use calculated score)
        if confidence is None:
            print("[DEBUG] Model 2: No confidence in HF response, using heuristic fallback")
            is_bot, score, bot_type = _heuristic_bot_score(features_list)
            print(f"[DEBUG] Model 2 heuristic: is_bot={is_bot}, score={score:.4f}, type={bot_type}")
            return is_bot, score, bot_type

        # HF model worked - derive bot_type from heuristics but use HF confidence
        _, _, bot_type = _heuristic_bot_score(features_list)
        print(f"[DEBUG] Model 2 parsed: is_bot={result}, confidence={confidence}, type={bot_type}")
        return bool(result), confidence, bot_type

    async def _predict_payload(self, request: str, base: Dict[str, float]) -> Tuple[bool, Optional[float]]:
        """Returns (is_attack, confidence) from Model 1 via HuggingFace Space.

        Results are cached by feature-vector bytes for _PAYLOAD_CACHE_TTL seconds
        to avoid redundant HF calls for repeated or structurally identical payloads.
        """
        X11 = _extract_model1_features(request)
        cache_key = X11.tobytes()
        now = time.time()

        # Cache hit
        cached = _PAYLOAD_CACHE.get(cache_key)
        if cached is not None:
            cached_result, cached_ts = cached
            if now - cached_ts < _PAYLOAD_CACHE_TTL:
                return cached_result

        data = await self._post_json_async(
            _MODEL1_HF_URL,
            {"features": X11.flatten().tolist(), "inputs": X11.flatten().tolist()},
            _MODEL1_TIMEOUT,
        )
        if data is None:
            return False, None

        result = self._parse_bool_prediction(
            data,
            positive_labels={"attack_detected", "attack", "malicious", "suspicious", "anomaly", "-1"},
            positive_values={-1},
        )
        confidence = self._parse_confidence(data)
        outcome: Tuple[bool, Optional[float]] = (bool(result), confidence)

        # Store result and lazily evict stale entries
        _PAYLOAD_CACHE[cache_key] = (outcome, now)
        if len(_PAYLOAD_CACHE) > 500:
            stale = [k for k, (_, ts) in _PAYLOAD_CACHE.items() if now - ts >= _PAYLOAD_CACHE_TTL]
            for k in stale:
                del _PAYLOAD_CACHE[k]

        return outcome

    # ── main interface ────────────────────────────────────────────────────

    async def predict(self, raw_request: str, model2_flow_features: Optional[List[float]] = None) -> Dict:
        """
        Score a single HTTP request using only the models applicable to the input.

        Model routing:
          Model 1 (payload): runs when raw_request is present AND is an API-style request
          Model 2 (bot):     runs when 14 flow features are provided
          Model 3 (traffic): runs when 14 flow features are provided

        Returns dict including model_ran flags so the fusion engine can renormalize weights.
        """
        # 1. Extract base HTTP features
        features = extract_features(raw_request)

        # 2. Compute base anomaly score (optional — skip if no base model)
        anomaly_score = 0.0  # Default neutral score if base model not configured
        if self._base_model is not None and self._base_scaler is not None:
            anomaly_score, _ = self._predict_base_local(features)
        elif self._base_remote_url:
            anomaly_score, _ = await self._predict_base_remote(features)
        else:
            print("[DEBUG] Base model not configured — skipping base anomaly scoring")

        # 3. Detect request type + routing flags
        is_api = self._is_api_request(raw_request)
        has_payload = bool(raw_request and raw_request.strip())
        has_flow_features = (
            model2_flow_features is not None
            and len(model2_flow_features) == 14
        )

        print("----- MODEL ROUTER -----")
        print(f"Payload present: {has_payload}")
        print(f"Flow features present: {has_flow_features}")
        print(f"API request: {is_api}")

        # 4. Conditional task router — only schedule models with valid input
        tasks: List = []
        task_names: List[str] = []

        if has_payload and is_api:
            tasks.append(self._predict_payload(raw_request, features))
            task_names.append("model1")

        if has_flow_features:
            # Model 2 (bot) no longer runs in /analyze — it has its own /bot-analysis endpoint
            tasks.append(self._predict_traffic(raw_request, features))
            task_names.append("model3")

        print(f"Models scheduled: {task_names}")

        model_outputs: Dict[str, Optional[Tuple]] = {
            "model1": None,
            "model2": None,
            "model3": None,
        }

        if tasks:
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            for name, result in zip(task_names, raw_results):
                if isinstance(result, Exception):
                    print(f"[WARN] Model {name} failed: {result}")
                else:
                    model_outputs[name] = result

        # Unpack results — None means the model did not run (no valid input)
        payload_attack, payload_conf = (
            model_outputs["model1"] if model_outputs["model1"] is not None else (False, None)
        )
        bot_detected, bot_conf = (
            model_outputs["model2"] if model_outputs["model2"] is not None else (False, None)
        )
        traffic_anomaly, traffic_conf = (
            model_outputs["model3"] if model_outputs["model3"] is not None else (False, None)
        )

        # 5. Determine threat type
        threat_type = "Normal"

        sql_attack = features["sql_keyword_score"] > 0
        xss_attack = features["script_tag_score"] > 0
        traversal = (
            "../" in raw_request
            or "%2e%2e" in raw_request.lower()
            or "..%2f" in raw_request.lower()
        )

        if traffic_anomaly:
            threat_type = "Traffic Anomaly"
        elif bot_detected:
            threat_type = "Bot Activity"
        elif payload_attack:
            threat_type = "Injection Attack"
        elif sql_attack:
            threat_type = "SQL Injection"
            payload_attack = True   # heuristic-detected injection — propagate to fusion
        elif xss_attack:
            threat_type = "XSS Attack"
            payload_attack = True   # heuristic-detected injection — propagate to fusion
        elif traversal:
            threat_type = "Path Traversal"
            payload_attack = True   # heuristic-detected injection — propagate to fusion

        prediction = "Normal" if threat_type == "Normal" else "Suspicious"

        return {
            "raw_request": raw_request,
            "anomaly_score": anomaly_score,
            "prediction": prediction,
            "threat_type": threat_type,
            "traffic_anomaly": traffic_anomaly,
            "traffic_confidence": traffic_conf,
            "bot_detected": bot_detected,
            "bot_confidence": bot_conf,
            "payload_attack": payload_attack,
            "payload_confidence": payload_conf,
            "is_api_request": is_api,
            "bot_flow_features_supplied": model2_flow_features is not None,
            "model1_ran": "model1" in task_names,
            "model2_ran": "model2" in task_names,
            "model3_ran": "model3" in task_names,
            "features": features,
        }

    async def predict_bot_flows(
        self, features_batch: List[List[float]]
    ) -> List[Dict]:
        """Run Model 2 (bot detection) on a batch of 14-feature flow vectors.

        Called exclusively from /bot-analysis — never from /analyze.
        """
        print(f"[DEBUG] predict_bot_flows: Processing {len(features_batch)} sessions")
        results = []
        for i, features in enumerate(features_batch):
            print(f"[DEBUG] Session {i} features: {features[:5]}... (first 5 of 14)")
            is_bot, confidence, bot_type = await self._predict_bot(features)
            results.append({
                "prediction": int(is_bot),
                "probability": round(float(confidence) if confidence is not None else float(is_bot), 4),
                "bot_type": bot_type,
            })
        return results

    async def predict_batch(self, requests: list, model2_flow_features_batch: Optional[List[Optional[List[float]]]] = None) -> list:
        """Score a batch of HTTP requests in parallel."""
        if model2_flow_features_batch is None:
            model2_flow_features_batch = [None] * len(requests)
        if len(model2_flow_features_batch) != len(requests):
            raise ValueError("Batch flow feature count must match request count")
        return await asyncio.gather(*[
            self.predict(req, flow_features)
            for req, flow_features in zip(requests, model2_flow_features_batch)
        ])

    # ── Threshold-based batch detection ─────────────────────────────────────
    # IsolationForest score below this = one anomaly signal (not the sole gate)
    ANOMALY_THRESHOLD = -0.10
    # Requests with score >= this value are classified as Normal
    UNKNOWN_ATTACK_THRESHOLD = 0.08

    @staticmethod
    def _detect_sqli(request: str) -> bool:
        """Detect SQL injection patterns using high-confidence indicators
        and multi-keyword correlation to reduce false positives."""
        lower_req = request.lower()

        # High-confidence single patterns (rarely appear in legitimate traffic)
        strong_patterns = [
            "' or '1'='1", "' or 1=1--", "' or ''='", "admin'--",
            "union select", "drop table", "insert into",
            "1=1", "1'='1", ";--", "exec(", "execute(",
            "' or ", "' and ",
        ]
        if any(p in lower_req for p in strong_patterns):
            return True

        # Weak patterns: only flag when 2+ co-occur (e.g. "select ... from")
        weak_keywords = ["select ", " from ", " where ", "@@", "char(", "--", "/*", "*/"]
        matches = sum(1 for p in weak_keywords if p in lower_req)
        return matches >= 2

    @staticmethod
    def _detect_xss(request: str) -> bool:
        """Detect XSS patterns. Bare HTML tags like <img> or <svg> alone
        are not sufficient — they must pair with event handlers or script context."""
        lower_req = request.lower()

        # High-confidence: always malicious in HTTP request context
        strong_patterns = [
            "<script", "</script", "javascript:", "document.cookie",
            "document.location", "expression(",
        ]
        if any(p in lower_req for p in strong_patterns):
            return True

        # Event handlers are strong signals on their own
        event_handlers = [
            "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
        ]
        if any(p in lower_req for p in event_handlers):
            return True

        # HTML tags only count when combined with event handlers or JS calls
        html_tags = ["<img", "<iframe", "<svg"]
        js_calls = ["alert(", "eval(", "prompt(", "confirm("]
        has_html_tag = any(t in lower_req for t in html_tags)
        has_js_call = any(j in lower_req for j in js_calls)
        return has_html_tag and has_js_call

    @staticmethod
    def _detect_path_traversal(request: str) -> bool:
        """Detect path traversal patterns. A single '../' is common in
        legitimate relative paths, so require repeated sequences or
        sensitive target files."""
        lower_req = request.lower()

        # High-confidence: encoded traversal or sensitive file targets
        strong_patterns = [
            "%2e%2e", "..%2f", "%2f..", "....//", "..%5c", "%252e",
            "/etc/passwd", "/etc/shadow", "c:\\windows", "c:/windows",
        ]
        if any(p in lower_req for p in strong_patterns):
            return True

        # Plain '../' or '..\' require 2+ occurrences to flag
        plain_count = lower_req.count("../") + lower_req.count("..\\")
        return plain_count >= 2

    def _detect_threat_type(self, request: str, is_anomaly: bool, anomaly_score: float = 0.0) -> str:
        """
        Detect attack type based on pattern matching and anomaly score.
        
        Unknown attacks with anomaly_score >= UNKNOWN_ATTACK_THRESHOLD 
        (closer to normal) are reclassified as Normal to reduce false positives.
        """
        if not is_anomaly:
            return "Normal"

        if self._detect_sqli(request):
            return "SQL Injection"
        if self._detect_xss(request):
            return "XSS Attack"
        if self._detect_path_traversal(request):
            return "Path Traversal"

        # Unknown attack pattern detected, but check score confidence
        # If score is high (close to normal), treat it as normal to filter low-confidence unknowns
        if anomaly_score >= self.UNKNOWN_ATTACK_THRESHOLD:
            return "Normal"

        return "Unknown Attack"

    async def predict_batch_with_threshold(self, requests: List[str]) -> Dict:
        """
        Batch analysis using Model 1 (payload) predictions with confidence scores.

        Pipeline:
          1. Call Model 1 (payload detection) for each request in parallel
          2. Get confidence scores from Model 1
          3. Run rule detection for threat classification
          4. Calculate contamination rate
          5. Return batch summary

        Returns:
            {
                "total_requests": int,
                "normal": int,
                "sql_injection": int,
                "xss": int,
                "path_traversal": int,
                "unknown_attack": int,
                "contamination_rate": float,
                "results": [...]  # Each with "anomaly_score" (confidence %)
            }
        """
        print(f"[BATCH] Processing {len(requests)} requests with Model 1")

        # Call Model 1 (payload detection) for all requests in parallel
        tasks = []
        for req in requests:
            features = extract_features(req)
            tasks.append(self._predict_payload(req, features))

        # Gather all predictions
        predictions = await asyncio.gather(*tasks, return_exceptions=True)
        print(f"[BATCH] Received {len(predictions)} predictions from Model 1")

        # Process results
        results = []
        counts = {
            "normal": 0,
            "sql_injection": 0,
            "xss": 0,
            "path_traversal": 0,
            "unknown_attack": 0,
        }

        for i, req in enumerate(requests):
            pred = predictions[i]

            # Handle prediction errors
            if isinstance(pred, Exception):
                print(f"[WARN] Request {i} prediction failed: {pred}")
                is_attack = False
                confidence = 0.0
            else:
                is_attack, confidence = pred
                # Convert confidence to percentage (0-100 scale for display)
                if confidence is not None:
                    confidence = confidence * 100.0  # Convert 0.0-1.0 to 0-100
                else:
                    confidence = 0.0

            # Rule-based detection (overrides Model 1 if pattern found)
            rule_type: Optional[str] = None
            if self._detect_sqli(req):
                rule_type = "SQL Injection"
                is_attack = True
                confidence = max(confidence, 95.0)  # High confidence for rule match
            elif self._detect_xss(req):
                rule_type = "XSS Attack"
                is_attack = True
                confidence = max(confidence, 95.0)
            elif self._detect_path_traversal(req):
                rule_type = "Path Traversal"
                is_attack = True
                confidence = max(confidence, 95.0)

            # Determine final threat type
            if rule_type:
                threat_type = rule_type
                is_anomaly = True
            elif is_attack:
                threat_type = "Injection Attack"
                is_anomaly = True
            else:
                threat_type = "Normal"
                is_anomaly = False

            # Count by threat type
            if threat_type == "Normal":
                counts["normal"] += 1
            elif threat_type == "SQL Injection":
                counts["sql_injection"] += 1
            elif threat_type == "XSS Attack":
                counts["xss"] += 1
            elif threat_type == "Path Traversal":
                counts["path_traversal"] += 1
            else:
                counts["unknown_attack"] += 1

            results.append({
                "raw_request": req,
                "anomaly_score": round(confidence, 2),  # Confidence % (0-100)
                "is_anomaly": is_anomaly,
                "threat_type": threat_type,
            })

        # Calculate contamination rate
        total = len(requests)
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        contamination_rate = (anomaly_count / total * 100) if total > 0 else 0.0

        print(f"[BATCH] Contamination rate: {contamination_rate:.2f}% ({anomaly_count}/{total} anomalies)")

        return {
            "total_requests": total,
            "normal": counts["normal"],
            "sql_injection": counts["sql_injection"],
            "xss": counts["xss"],
            "path_traversal": counts["path_traversal"],
            "unknown_attack": counts["unknown_attack"],
            "contamination_rate": round(contamination_rate, 2),
            "results": results,
        }

    async def _batch_predict_model1(self, features_batch: List[List[float]]) -> List[float]:
        """
        Send batch of features to base model (IsolationForest) via local or HuggingFace endpoint.
        If base model is not configured, returns neutral scores (0.1 = normal).

        Note: Despite the name, this is the BASE model batch predictor, NOT Model 1 (payload).
        Returns list of anomaly scores.
        """
        # If using local model
        if self._base_model is not None and self._base_scaler is not None:
            scores = []
            for feature_values in features_batch:
                X = np.array([feature_values])
                scaled = self._base_scaler.transform(X)
                score = float(self._base_model.decision_function(scaled)[0])
                scores.append(score)
            return scores

        # If using remote HuggingFace endpoint
        if self._base_remote_url:
            # Chunk batch into 500-request chunks (HuggingFace Spaces limit)
            CHUNK_SIZE = 500
            all_scores = []

            for chunk_idx in range(0, len(features_batch), CHUNK_SIZE):
                chunk = features_batch[chunk_idx:chunk_idx + CHUNK_SIZE]
                chunk_num = (chunk_idx // CHUNK_SIZE) + 1
                total_chunks = (len(features_batch) + CHUNK_SIZE - 1) // CHUNK_SIZE

                print(f"[BATCH] Processing chunk {chunk_num}/{total_chunks} ({len(chunk)} requests)")

                payload = {
                    "inputs": chunk,
                    "features_batch": chunk,
                    "feature_columns": self._base_feature_columns,
                }
                data = await self._post_json_async(
                    self._base_remote_url,
                    payload,
                    float(os.getenv("HF_BASE_MODEL_TIMEOUT", "15.0")),  # longer timeout for batch
                )

                if data is None:
                    print(f"[WARN] Chunk {chunk_num} HuggingFace request failed, falling back to sequential")
                    # Fallback: call individually for this chunk
                    chunk_scores = []
                    for features in chunk:
                        single_payload = {
                            "features": features,
                            "inputs": features,
                            "feature_columns": self._base_feature_columns,
                        }
                        single_data = await self._post_json_async(
                            self._base_remote_url,
                            single_payload,
                            float(os.getenv("HF_BASE_MODEL_TIMEOUT", "8.0")),
                        )
                        if single_data is None:
                            chunk_scores.append(0.1)  # Default to "normal" on failure
                        else:
                            parsed = self._extract_payload(single_data)
                            score = parsed.get("anomaly_score", parsed.get("score", 0.1))
                            chunk_scores.append(float(score))
                    all_scores.extend(chunk_scores)
                    continue

                # Parse chunk response
                chunk_scores = []
                if isinstance(data, list):
                    # Response is list of scores or list of dicts
                    for item in data:
                        if isinstance(item, (int, float)):
                            chunk_scores.append(float(item))
                        elif isinstance(item, dict):
                            score = item.get("anomaly_score", item.get("score", 0.1))
                            chunk_scores.append(float(score))
                        else:
                            chunk_scores.append(0.1)
                elif isinstance(data, dict):
                    # Response might have a "scores" or "results" key
                    if "scores" in data:
                        chunk_scores = [float(s) for s in data["scores"]]
                    elif "results" in data:
                        chunk_scores = [float(r.get("anomaly_score", r.get("score", 0.1))) for r in data["results"]]
                    else:
                        # Single result? Shouldn't happen for batch but handle it
                        score = data.get("anomaly_score", data.get("score", 0.1))
                        chunk_scores = [float(score)] * len(chunk)
                else:
                    print(f"[WARN] Unexpected chunk response format: {type(data)}")
                    chunk_scores = [0.1] * len(chunk)

                # Guard: pad/trim chunk_scores to exactly len(chunk)
                if len(chunk_scores) < len(chunk):
                    print(f"[WARN] Chunk {chunk_num}: expected {len(chunk)} scores, got {len(chunk_scores)}. Padding with 0.1")
                    chunk_scores.extend([0.1] * (len(chunk) - len(chunk_scores)))
                elif len(chunk_scores) > len(chunk):
                    chunk_scores = chunk_scores[:len(chunk)]

                all_scores.extend(chunk_scores)
                print(f"[BATCH] Chunk {chunk_num} completed: {len(chunk_scores)} scores received")

            return all_scores

        # No base model configured — return neutral scores (relies on rule detection)
        print("[INFO] Base model not configured — returning neutral scores for batch")
        return [0.1] * len(features_batch)  # 0.1 = neutral/normal score
