"""
CyHub Threat Engine — Signal Fusion Decision Logic

Combines independent model signals into a comprehensive threat assessment.
Uses parallel architecture where each model + domain intelligence contributes
to the final threat score with context-adaptive weights.

Architecture (5 signals):
  Model 4 (URL)              → url_threat_score
  Model 3 (Traffic)          → traffic_anomaly_score
  Model 2 (Bot)              → bot_activity_score
  Model 1 (Payload, API)     → payload_threat_score
  Domain Intelligence        → domain_intel_score

Weights adapt dynamically based on request context (entropy, flow state, domain
suspicion level) and renormalize when models didn't run.

4-tier verdict system:
  SAFE       (< 0.2)  — Allow request
  CAUTION    (0.2-0.5) — Allow but monitor
  SUSPICIOUS (0.5-0.8) — Flag for review
  DANGEROUS  (>= 0.8) — Block immediately
"""

from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel
from src.decision_controller import get_dynamic_weights, build_explanation


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Response Models
# ─────────────────────────────────────────────────────────────────────────────

class ThreatScores(BaseModel):
    """Individual threat component scores (0.0-1.0)"""
    url_threat_score: float
    traffic_anomaly_score: float
    bot_activity_score: float
    payload_threat_score: float
    domain_intel_score: float
    is_api_request: bool
    overall_threat_score: float


class ModelDetails(BaseModel):
    """Per-model signal contribution and details"""
    model4_classification: str
    model4_confidence: float
    traffic_anomaly_detected: bool
    bot_activity_detected: bool
    payload_attack_detected: bool
    payload_threat_type: Optional[str] = None
    is_api_request: bool
    domain_heuristic_flags: List[str] = []


class ComprehensiveThreatReport(BaseModel):
    """Final unified threat assessment"""
    url: str
    domain: Optional[str] = None
    threat_scores: ThreatScores
    model_details: ModelDetails
    overall_verdict: str       # "Safe" | "Caution" | "Suspicious" | "Dangerous" | "Blocked"
    recommendation: str
    passes_domain_filter: bool
    blocked_reason: Optional[str] = None
    from_cache: bool
    request_type: str          # "Browser" | "API"
    explanation: List[str] = []   # Human-readable list of detected threat signals


# ─────────────────────────────────────────────────────────────────────────────
# Domain Intelligence Score Calculation
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_domain_intel_score(domain_check: Optional[Dict]) -> float:
    """Calculate a 0.0-1.0 threat score from domain intelligence data.

    Factors: heuristic flags, blocklist proximity, DNS age, etc.
    """
    if not domain_check:
        return 0.3  # uncertain = slightly elevated

    # Whitelisted domains are safe
    classification = domain_check.get("classification", "unknown")
    if classification == "normal":
        return 0.0

    # Blocked / failed DNS
    if not domain_check.get("passes_domain_filter", True):
        return 1.0

    # Heuristic suspicion
    threat_flags = domain_check.get("threat_flags", {})
    flag_score = 0.0
    if threat_flags.get("type_malware", 0.0) > 0:
        flag_score = max(flag_score, 0.9)
    if threat_flags.get("type_phishing", 0.0) > 0:
        flag_score = max(flag_score, 0.85)
    if threat_flags.get("type_defacement", 0.0) > 0:
        flag_score = max(flag_score, 0.7)
    if flag_score > 0:
        return flag_score

    blocked_reason = domain_check.get("blocked_reason")
    if blocked_reason:
        return 0.7

    if classification == "suspicious":
        return 0.5

    if classification == "unknown":
        return 0.3

    return 0.1


# ─────────────────────────────────────────────────────────────────────────────
# Signal Fusion Logic
# ─────────────────────────────────────────────────────────────────────────────

def calculate_threat_scores(
    model4_result: Optional[Dict],
    anomaly_result: Optional[Dict],
    domain_check: Optional[Dict],
    is_api_request: bool,
    weights: Optional[Dict[str, float]] = None,
) -> ThreatScores:
    """
    Signal fusion: Combine 5 independent signals into threat scores.

    Args:
        model4_result: {"classification": str, "confidence": float}
        anomaly_result: {"traffic_anomaly": bool, "bot_detected": bool, "payload_attack": bool}
        domain_check: Domain intelligence pre-filter result
        is_api_request: Whether this is an API request or browser request
        weights: Optional pre-computed weights dict from get_dynamic_weights().
                 If None, falls back to static context-based weights.

    Returns:
        ThreatScores with per-signal and overall scores
    """
    if model4_result is None:
        model4_result = {}
    if anomaly_result is None:
        anomaly_result = {}

    # ── 1. Model 4 Score ── URL Reputation ──
    # Base threat level per category × actual model confidence
    url_score_map = {
        "normal": 0.0,
        "adult": 0.9,
        "betting": 0.9,
        "malware": 1.0,
        "phishing": 0.95,
        "unknown": 0.5,
        "blocked": 1.0,
    }
    classification = model4_result.get("classification", "unknown")
    base_url_score = url_score_map.get(classification, 0.5)
    m4_conf = model4_result.get("confidence")
    url_threat = (base_url_score * m4_conf) if m4_conf is not None else base_url_score

    # ── 2. Model 3 Score ── Traffic Anomaly ──
    # M3 returns `attack_probability` — the probability of the attack class (-1).
    # This is always a direct threat score: 0.0 = safe, 1.0 = dangerous.
    # Do NOT invert when the model says "normal" — that flips a low-threat reading
    # (e.g. 0.1) into a high-threat score (0.9), which is incorrect.
    traffic_anomaly = anomaly_result.get("traffic_anomaly", False)
    traffic_conf = anomaly_result.get("traffic_confidence")
    traffic_score = traffic_conf if traffic_conf is not None else float(traffic_anomaly)

    # ── 3. Model 2 Score ── Bot Activity ──
    # M2 confidence represents probability of the malicious class (1).
    # Use directly as the threat score for the same reason as M3.
    bot_detected = anomaly_result.get("bot_detected", False)
    bot_conf = anomaly_result.get("bot_confidence")
    bot_score = bot_conf if bot_conf is not None else float(bot_detected)

    # ── 4. Model 1 Score ── Payload Attack ──
    # M1 confidence represents probability of the anomaly class (-1).
    # Use directly as the threat score.
    # NOTE: payload_attack is also set by heuristics (sql_keyword_score, script_tag_score,
    # path traversal) so it is non-zero for GET requests with injection payloads too.
    payload_attack = anomaly_result.get("payload_attack", False)
    payload_conf = anomaly_result.get("payload_confidence")
    payload_score = payload_conf if payload_conf is not None else float(payload_attack)

    # ── 5. Domain Intelligence Score ──
    di_score = _calculate_domain_intel_score(domain_check)

    # ── Context-adaptive weighted fusion ──
    # Use pre-computed dynamic weights if provided; otherwise fall back to
    # static context-based weights (backwards-compatible).
    model1_ran = anomaly_result.get("model1_ran", True)
    model3_ran = anomaly_result.get("model3_ran", True)

    if weights is not None:
        w_url     = weights.get("w_url",     0.25)
        w_traffic = weights.get("w_traffic", 0.25)
        w_payload = weights.get("w_payload", 0.25)
        w_di      = weights.get("w_di",      0.25)
        # If Model 1 didn't run but heuristics detected a payload threat,
        # restore the payload weight so the score is not silently zeroed.
        if w_payload == 0.0 and payload_score > 0:
            w_payload = 0.25
        total_w = w_url + w_traffic + w_payload + w_di
        scale = 1.0 / total_w if total_w > 0 else 1.0
    else:
        # Static fallback weights
        if is_api_request:
            w_url, w_traffic, w_payload, w_di = 0.25, 0.25, 0.35, 0.15
        else:
            w_url, w_traffic, w_payload, w_di = 0.30, 0.30, 0.25, 0.15

        if not model3_ran:
            w_traffic = 0.0
        # Only zero payload weight if Model 1 didn't run AND no heuristic detected a threat
        if not model1_ran and payload_score == 0:
            w_payload = 0.0

        total_w = w_url + w_traffic + w_payload + w_di
        scale = 1.0 / total_w if total_w > 0 else 1.0

    overall_score = (
        url_threat    * w_url     * scale +
        traffic_score * w_traffic * scale +
        payload_score * w_payload * scale +
        di_score      * w_di      * scale
    )

    return ThreatScores(
        url_threat_score=round(url_threat, 4),
        traffic_anomaly_score=round(traffic_score, 4),
        bot_activity_score=round(bot_score, 4),
        payload_threat_score=round(payload_score, 4),
        domain_intel_score=round(di_score, 4),
        is_api_request=is_api_request,
        overall_threat_score=round(overall_score, 4),
    )


def determine_verdict(
    overall_score: float,
    model_details: ModelDetails,
) -> Tuple[str, str]:
    """
    Convert threat score + model signals into a 4-tier verdict + recommendation.

    Hard rules (override threshold):
      1. M4 == "blocked"                     → Blocked
      2. M4 == "malware"                     → Dangerous
      3. M4 == "adult"                       → Blocked (policy)
      4. M4 == "betting"                     → Blocked (policy)
      5. traffic anomaly + bot detected      → Dangerous
      6. API + payload attack                → Dangerous

    Soft rules (4-tier thresholds):
      [0.0, 0.2)  → Safe
      [0.2, 0.5)  → Caution
      [0.5, 0.8)  → Suspicious
      [0.8, 1.0]  → Dangerous
    """

    # ── Hard Rule 0: Blocked domains ──
    if model_details.model4_classification == "blocked":
        return "Blocked", "Domain is blocklisted or failed pre-filter checks."

    # ── Hard Rule 1: Malware → Dangerous ──
    if model_details.model4_classification == "malware":
        return "Dangerous", "Malware domain detected — block immediately."

    # ── Hard Rule 2: Adult / Betting → Blocked ──
    if model_details.model4_classification == "adult":
        return "Blocked", "Adult content domain — blocked by policy."
    if model_details.model4_classification == "betting":
        return "Blocked", "Betting/gambling domain — blocked by policy."

    # ── Hard Rule 3: Traffic anomaly + bot → Dangerous ──
    if model_details.traffic_anomaly_detected and model_details.bot_activity_detected:
        return "Dangerous", "Anomalous traffic with bot activity detected — block immediately."

    # ── Hard Rule 4: Payload attack (any request type) → Dangerous ──
    # Covers both API body injections and GET query-string injections (SQL, XSS, traversal).
    if model_details.payload_attack_detected:
        threat_type = model_details.payload_threat_type or "payload attack"
        return "Dangerous", f"Attack detected ({threat_type}) — block immediately."

    # ── 4-tier threshold-based verdict ──
    if overall_score >= 0.8:
        return "Dangerous", "High threat score — block immediately."
    elif overall_score >= 0.5:
        return "Suspicious", "Elevated threat — flag for review."
    elif overall_score >= 0.2:
        return "Caution", "Minor signals detected — allow but monitor."
    else:
        return "Safe", "No significant threats detected."


async def generate_report(
    url: str,
    domain_check: Dict,
    model4_result: Optional[Dict],
    anomaly_result: Optional[Dict],
    is_api_request: bool,
    payload_findings: Optional[List[str]] = None,
) -> ComprehensiveThreatReport:
    """
    Generate comprehensive threat report using 5-signal fusion.

    Args:
        url: Original URL being analyzed
        domain_check: Domain Intelligence pre-filter result
        model4_result: Model 4 URL classification result
        anomaly_result: Models 1-3 anomaly detection result
        is_api_request: Whether this is an API request
        payload_findings: Pre-gate payload scan results (SQL/XSS/traversal findings)
    """
    if anomaly_result is None:
        anomaly_result = {}

    # 1. Compute context-adaptive weights using the decision controller
    features = anomaly_result.get("features", {}) if isinstance(anomaly_result, dict) else {}
    shannon_entropy = float(features.get("shannon_entropy", 0.0)) if features else 0.0
    has_flow_anomaly = bool(anomaly_result.get("traffic_anomaly", False))
    domain_classification = (model4_result or {}).get("classification", "unknown")
    domain_suspicious = domain_classification in ("suspicious", "unknown", "phishing", "malware")
    model1_ran = anomaly_result.get("model1_ran", True)
    model3_ran = anomaly_result.get("model3_ran", True)

    weights = get_dynamic_weights(
        is_api_request=is_api_request,
        shannon_entropy=shannon_entropy,
        has_flow_anomaly=has_flow_anomaly,
        domain_suspicious=domain_suspicious,
        model1_ran=model1_ran,
        model3_ran=model3_ran,
    )

    # 2. Calculate threat scores (5 signals with adaptive weights)
    threat_scores = calculate_threat_scores(
        model4_result, anomaly_result, domain_check, is_api_request, weights=weights
    )

    # 3. Extract heuristic flags for model details
    heuristic_flags: List[str] = []
    if domain_check:
        threat_flags = domain_check.get("threat_flags", {})
        for flag_name, flag_val in threat_flags.items():
            if flag_val > 0:
                heuristic_flags.append(flag_name)
        blocked_reason = domain_check.get("blocked_reason")
        if blocked_reason:
            heuristic_flags.append(f"blocked:{blocked_reason}")

    # 4. Build model details
    model_details = ModelDetails(
        model4_classification=(
            model4_result.get("classification", "unknown") if model4_result else "unknown"
        ),
        model4_confidence=(
            model4_result.get("confidence", 0.0) if model4_result else 0.0
        ),
        traffic_anomaly_detected=(
            anomaly_result.get("traffic_anomaly", False) if anomaly_result else False
        ),
        bot_activity_detected=(
            anomaly_result.get("bot_detected", False) if anomaly_result else False
        ),
        payload_attack_detected=(
            anomaly_result.get("payload_attack", False) if anomaly_result else False
        ),
        payload_threat_type=(
            anomaly_result.get("threat_type") if anomaly_result else None
        ),
        is_api_request=is_api_request,
        domain_heuristic_flags=heuristic_flags,
    )

    # 5. Determine verdict using hard rules + 4-tier thresholds
    verdict, recommendation = determine_verdict(
        threat_scores.overall_threat_score, model_details
    )

    # 6. Build human-readable explanation
    explanation = build_explanation(
        model4_classification=model_details.model4_classification,
        traffic_anomaly=model_details.traffic_anomaly_detected,
        bot_detected=model_details.bot_activity_detected,
        payload_attack=model_details.payload_attack_detected,
        payload_threat_type=model_details.payload_threat_type,
        domain_flags=heuristic_flags,
        payload_findings=payload_findings,
        threat_score=threat_scores.overall_threat_score,
        bot_confidence=threat_scores.bot_activity_score,
    )

    # 7. Assemble final report
    return ComprehensiveThreatReport(
        url=url,
        domain=domain_check.get("domain") if domain_check else None,
        threat_scores=threat_scores,
        model_details=model_details,
        overall_verdict=verdict,
        recommendation=recommendation,
        passes_domain_filter=(
            domain_check.get("passes_domain_filter", True) if domain_check else True
        ),
        blocked_reason=domain_check.get("blocked_reason") if domain_check else None,
        from_cache=domain_check.get("from_cache", False) if domain_check else False,
        request_type="API" if is_api_request else "Browser",
        explanation=explanation,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def score_to_severity(score: float) -> str:
    """Convert threat score to human-readable severity level."""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.2:
        return "MEDIUM"
    else:
        return "LOW"


def get_threat_factors(model_details: ModelDetails) -> list[str]:
    """Extract list of detected threat factors from model details."""
    factors = []

    if model_details.model4_classification == "malware":
        factors.append("malware domain")
    elif model_details.model4_classification == "phishing":
        factors.append("phishing domain")

    if model_details.traffic_anomaly_detected:
        factors.append("anomalous traffic")

    if model_details.bot_activity_detected:
        factors.append("bot activity")

    if model_details.payload_attack_detected:
        threat_type = model_details.payload_threat_type or "payload attack"
        factors.append(threat_type)

    for flag in model_details.domain_heuristic_flags:
        if flag not in factors:
            factors.append(flag)

    return factors if factors else ["none"]
