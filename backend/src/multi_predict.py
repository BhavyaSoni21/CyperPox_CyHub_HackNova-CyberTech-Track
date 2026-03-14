"""
CyHub — Multi-Model Prediction Pipeline

Three-stage threat detection pipeline:

  Stage 1  Model 3  traffic_model.pkl      Network Traffic Anomaly
  Stage 2  Model 2  bot_detection_model   Bot / Botnet Activity
  Stage 3  Model 1  web_security_model     Payload / Injection Attack

Each model was trained on network-flow features (CIC-IDS style).  Since the
API only receives raw HTTP request strings we derive proxy feature vectors by
mapping the structural properties of the request onto the expected input space
of each model.  The mappings are intentional approximations — they give the
models a meaningful signal while keeping the entire pipeline self-contained.
"""

from __future__ import annotations

import math
import os
import warnings
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import httpx

warnings.filterwarnings("ignore")

# ── helpers imported from existing feature engineering ──────────────────────
from src.feature_engineering import FEATURE_COLUMNS, extract_features

# ── constants ────────────────────────────────────────────────────────────────
# Models 1, 2 & 3 are served remotely via HuggingFace Spaces.
# URLs can be overridden through environment variables.
_MODEL1_HF_URL = os.getenv("HF_MODEL1_URL", "https://bhavyasoni21-model1.hf.space/predict")
_MODEL2_HF_URL = os.getenv("HF_MODEL2_URL", "https://bhavyasoni21-model2.hf.space/predict")
_MODEL3_HF_URL = os.getenv("HF_MODEL3_URL", "https://bhavyasoni21-model3.hf.space/predict")
_MODEL1_TIMEOUT = float(os.getenv("HF_MODEL1_TIMEOUT", "8.0"))
_MODEL2_TIMEOUT = float(os.getenv("HF_MODEL2_TIMEOUT", "8.0"))
_MODEL3_TIMEOUT = float(os.getenv("HF_MODEL3_TIMEOUT", "8.0"))

_HF_API_TOKEN = os.getenv("HF_API_TOKEN", "").strip()


# ─────────────────────────────────────────────────────────────────────────────
#  Feature extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_model2_features(request: str, base: Dict[str, float]) -> np.ndarray:
    """
    Map HTTP request features onto Model 2's 14 network-flow features.

    Feature order must match training exactly:
      Flow Duration, Flow Byts/s, Flow Pkts/s, Tot Fwd Pkts, Tot Bwd Pkts,
      Pkt Len Mean, Pkt Len Std, Flow IAT Mean, Flow IAT Std,
      SYN Flag Cnt, ACK Flag Cnt, RST Flag Cnt, Active Mean, Idle Mean
    """
    req_len = base["request_length"]
    entropy = base["shannon_entropy"]
    special = base["special_char_count"]
    sql = base["sql_keyword_score"]
    script = base["script_tag_score"]
    params = base["param_count"]

    # Heuristic proxies derived from HTTP structure
    # Bots tend to have unnaturally short/long requests and repetitive structure
    flow_duration = max(1.0, req_len * 0.1 + params * 5.0)
    flow_bytes_s = req_len * 8.0            # rough throughput estimate
    flow_pkts_s = max(1.0, req_len / 1500.0)    # MTU-based packet estimate
    tot_fwd_pkts = max(1.0, math.ceil(req_len / 1500.0))
    tot_bwd_pkts = 0.0                      # no response info available
    pkt_len_mean = req_len / max(1.0, tot_fwd_pkts)
    # Bots often have very uniform packet sizes → low std; humans vary more
    pkt_len_std = entropy * 10.0
    flow_iat_mean = flow_duration / max(1.0, tot_fwd_pkts)
    flow_iat_std = abs(entropy - 3.5) * 5.0  # regularized deviation from typical entropy
    syn_flag = 1.0                           # every new HTTP request implies SYN
    ack_flag = 0.0
    rst_flag = 1.0 if (sql > 0 or script > 0 or special > 15) else 0.0
    active_mean = flow_duration
    idle_mean = 0.0

    return np.array([[
        flow_duration, flow_bytes_s, flow_pkts_s,
        tot_fwd_pkts, tot_bwd_pkts,
        pkt_len_mean, pkt_len_std,
        flow_iat_mean, flow_iat_std,
        syn_flag, ack_flag, rst_flag,
        active_mean, idle_mean,
    ]])


def _extract_model3_base(request: str, base: Dict[str, float]) -> np.ndarray:
    """
    Build the 18-feature base vector for Model 3 (traffic classifier).

    Feature order:
      Flow Duration, Flow Bytes/s, Flow Packets/s,
      Total Fwd Packet, Total Bwd packets,
      Total Length of Fwd Packet, Total Length of Bwd Packet,
      Packet Length Mean, Packet Length Std, Average Packet Size,
      Flow IAT Mean, Flow IAT Std, Flow IAT Max,
      Active Mean, Active Std, Idle Mean, Idle Std, Idle Max
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
    Mirrors engineer_features() from ml-models/Model_3/train_model.py.
    Returns a 35-element vector.
    """
    d = dict(zip(_BASE_COLS, base_vec))
    eps = 1e-9

    # log transforms
    log_vals = [math.log1p(max(0.0, d[c])) for c in _LOG_COLS]

    # ratio features
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

    # replace inf/nan with 0
    engineered = np.where(np.isfinite(engineered), engineered, 0.0)

    return np.concatenate([base_vec, engineered]).reshape(1, -1)


# ─────────────────────────────────────────────────────────────────────────────
#  Multi-model predictor
# ─────────────────────────────────────────────────────────────────────────────

class MultiModelPredictor:
    """
    Three-stage threat pipeline:
      Stage 1 — Model 3: Network Traffic Anomaly  (HuggingFace Space)
      Stage 2 — Model 2: Bot Detection            (HuggingFace Space)
      Stage 3 — Model 1: Payload/Web Security     (HuggingFace Space)

    Falls back gracefully if any remote model is unreachable.
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
    def _post_json(url: str, payload: Dict[str, Any], timeout: float) -> Optional[Any]:
        if not url:
            return None

        try:
            response = httpx.post(
                url,
                json=payload,
                headers=MultiModelPredictor._build_hf_headers(),
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[WARN] HuggingFace request failed ({url}): {e}")
            return None

    def _predict_base_remote(self, features: Dict[str, float]) -> Tuple[float, bool]:
        feature_values = [features[col] for col in self._base_feature_columns]
        payload = {
            "features": feature_values,
            "inputs": feature_values,
            "feature_columns": self._base_feature_columns,
        }
        data = self._post_json(
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

    def _predict_traffic(self, request: str, base: Dict[str, float]) -> bool:
        """Returns True if traffic is anomalous (Model 3 via HuggingFace Space)."""
        base_vec = _extract_model3_base(request, base)
        X35 = _engineer_model3_features(base_vec)

        data = self._post_json(
            _MODEL3_HF_URL,
            {"features": X35.flatten().tolist(), "inputs": X35.flatten().tolist()},
            _MODEL3_TIMEOUT,
        )
        remote_result = self._parse_bool_prediction(
            data,
            positive_labels={"traffic_anomaly", "anomaly", "suspicious", "1"},
            positive_values={1},
        )
        if remote_result is not None:
            return remote_result

        return False

    def _predict_bot(self, request: str, base: Dict[str, float]) -> bool:
        """Returns True if traffic looks like bot activity (Model 2 via HuggingFace Space)."""
        X14 = _extract_model2_features(request, base)
        data = self._post_json(
            _MODEL2_HF_URL,
            {"features": X14.flatten().tolist(), "inputs": X14.flatten().tolist()},
            _MODEL2_TIMEOUT,
        )
        result = self._parse_bool_prediction(
            data,
            positive_labels={"bot_detected", "bot", "malicious", "attack", "1"},
            positive_values={1},
        )
        return bool(result)

    def _predict_payload(self, request: str, base: Dict[str, float]) -> bool:
        """Returns True if Model 1 (HuggingFace Space) confirms a payload attack.

        The base IsolationForest vote is intentionally excluded here — this method
        is only called when the base model has already flagged the request as
        suspicious, so re-checking it would always return True.
        """
        base_vec = _extract_model3_base(request, base)
        X35 = _engineer_model3_features(base_vec)
        data = self._post_json(
            _MODEL1_HF_URL,
            {"features": X35.flatten().tolist(), "inputs": X35.flatten().tolist()},
            _MODEL1_TIMEOUT,
        )
        result = self._parse_bool_prediction(
            data,
            positive_labels={"attack_detected", "attack", "malicious", "suspicious", "-1", "1"},
            positive_values={-1, 1},
        )
        return bool(result)

    # ── main interface ────────────────────────────────────────────────────

    def predict(self, raw_request: str) -> Dict:
        """
        Score a single HTTP request through all three stages.

        Returns:
            {
                "raw_request": str,
                "anomaly_score": float,   # from base isolation forest
                "prediction": "Normal" | "Suspicious",
                "threat_type": "Normal" | "Traffic Anomaly" | "Bot Activity"
                               | "SQL Injection" | "XSS Attack"
                               | "Path Traversal" | "Injection Attack",
                "features": { ... }       # 7-feature base vector
            }
        """
        # 1. Extract base HTTP features (used for anomaly_score + model inputs)
        features = extract_features(raw_request)
        if self._base_model is not None and self._base_scaler is not None:
            feature_values = np.array([[features[col] for col in self._base_feature_columns]])
            scaled = self._base_scaler.transform(feature_values)
            anomaly_score = float(self._base_model.decision_function(scaled)[0])
            base_is_suspicious = anomaly_score < 0
        elif self._base_remote_url:
            anomaly_score, base_is_suspicious = self._predict_base_remote(features)
        else:
            raise RuntimeError("No base model configured (local or HuggingFace remote)")

        if not base_is_suspicious:
            threat_type = "Normal"
        else:
            # 3. Feature-based attack type detection using already-computed features
            sql_attack  = features["sql_keyword_score"] > 0
            xss_attack  = features["script_tag_score"] > 0
            traversal   = (
                "../" in raw_request
                or "%2e%2e" in raw_request.lower()
                or "..%2f" in raw_request.lower()
            )

            # 4. Run secondary models for their specific threat categories
            traffic_anomaly = self._predict_traffic(raw_request, features)
            bot_detected    = self._predict_bot(raw_request, features)
            payload_attack  = self._predict_payload(raw_request, features)

            if traffic_anomaly:
                threat_type = "Traffic Anomaly"
            elif bot_detected:
                threat_type = "Bot Activity"
            elif sql_attack:
                threat_type = "SQL Injection"
            elif xss_attack:
                threat_type = "XSS Attack"
            elif traversal:
                threat_type = "Path Traversal"
            elif payload_attack:
                threat_type = "Injection Attack"
            else:
                threat_type = "Injection Attack"  # base flagged it; type unknown

        prediction = "Normal" if threat_type == "Normal" else "Suspicious"

        return {
            "raw_request": raw_request,
            "anomaly_score": anomaly_score,
            "prediction": prediction,
            "threat_type": threat_type,
            "features": features,
        }

    def predict_batch(self, requests: list) -> list:
        """Score a batch of HTTP requests."""
        return [self.predict(req) for req in requests]
