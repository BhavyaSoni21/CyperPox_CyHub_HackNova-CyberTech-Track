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
        base_model_path: str = "models/isolation_forest.pkl",
    ):
        self._base_remote_url = ""
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
                raise FileNotFoundError(
                    f"Base model not found at {base_model_path}. "
                    "Set MODEL_PATH to a local file or HuggingFace endpoint URL, "
                    "or set HF_BASE_MODEL_URL."
                )
            base_pipeline = joblib.load(base_model_path)

        self._base_model = base_pipeline["model"] if base_pipeline else None
        self._base_scaler = base_pipeline["scaler"] if base_pipeline else None
        self._base_feature_columns = base_pipeline["feature_columns"] if base_pipeline else FEATURE_COLUMNS

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

    async def _predict_bot(self, model2_flow_features: Optional[List[float]]) -> Tuple[bool, Optional[float]]:
        """Returns (is_bot, confidence) from Model 2 via HuggingFace Space."""
        X14 = _coerce_model2_features(model2_flow_features)
        if X14 is None:
            return False, None

        data = await self._post_json_async(
            _MODEL2_HF_URL,
            {"features": X14.flatten().tolist(), "inputs": X14.flatten().tolist()},
            _MODEL2_TIMEOUT,
        )
        if data is None:
            return False, None

        result = self._parse_bool_prediction(
            data,
            positive_labels={"bot_detected", "bot", "malicious", "attack", "1"},
            positive_values={1},
        )
        confidence = self._parse_confidence(data)
        return bool(result), confidence

    async def _predict_payload(self, request: str, base: Dict[str, float]) -> Tuple[bool, Optional[float]]:
        """Returns (is_attack, confidence) from Model 1 via HuggingFace Space."""
        X11 = _extract_model1_features(request)
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
        return bool(result), confidence

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

        # 2. Compute base anomaly score (one signal, not a gate)
        if self._base_model is not None and self._base_scaler is not None:
            anomaly_score, _ = self._predict_base_local(features)
        elif self._base_remote_url:
            anomaly_score, _ = await self._predict_base_remote(features)
        else:
            raise RuntimeError("No base model configured (local or HuggingFace remote)")

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
            tasks.append(self._predict_bot(model2_flow_features))
            task_names.append("model2")
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
