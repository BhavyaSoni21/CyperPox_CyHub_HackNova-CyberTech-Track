"""
CyHub — Decision Controller Layer

Centralizes all control flow logic: early exits, model activation,
signal eligibility, override priority, multi-factor bot confidence,
dynamic weighting, and explainability.

Instead of scattered `if payload_attack: verdict = Dangerous` conditions
scattered across the pipeline, all decisions are encoded as ordered priority
rules evaluated by a single deterministic controller.

Fixes addressed:
  #1  Fragile control logic → priority-rule system
  #2  Pre-gate payload scan → prevents trusted-domain bypass
  #4  Naive bot OR-logic → multi-factor weighted confidence
  #5  Static fusion weights → contextual dynamic weighting
  #8  No explainability → build_explanation()
  #10 No risk memory → RiskMemory class
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Pre-Gate Payload Scanner
# ─────────────────────────────────────────────────────────────────────────────

_SQL_RE = re.compile(
    r"(\bUNION\b.{0,20}\bSELECT\b"
    r"|\bDROP\b\s+\bTABLE\b"
    r"|\bINSERT\b\s+\bINTO\b"
    r"|'\s*OR\s*'"
    r"|\bOR\b\s+1\s*=\s*1"
    r"|'\s*OR\b\s+\d"
    r"|'--"
    r"|;--"
    r"|\bEXEC\s*\("
    r"|\bEXECUTE\s*\()",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(<script[\s>]"
    r"|</script>"
    r"|javascript:"
    r"|on(?:error|load|click|mouseover|focus)\s*="
    r"|<iframe[\s>]"
    r"|document\.(?:cookie|location)"
    r"|eval\s*\("
    r"|<(?:img|svg)[\s>][^>]*on\w+\s*=)",
    re.IGNORECASE,
)
_TRAVERSAL_RE = re.compile(
    r"((?:\.\./|\.\.\\){2,}"
    r"|%2e%2e|%252e%252e"
    r"|\.\.%2f|%2f\.\."
    r"|\.\.%5c"
    r"|/etc/passwd|/etc/shadow"
    r"|c:\\\\windows|c:/windows)",
    re.IGNORECASE,
)


def scan_payload(raw_request: str) -> Tuple[bool, List[str]]:
    """Quick payload scan to detect malicious content before early exits.

    Called BEFORE domain-based early exits so a 'safe' domain carrying
    a malicious payload is never silently allowed through.

    Returns:
        (is_dangerous, list_of_findings)
    """
    findings: List[str] = []
    if _SQL_RE.search(raw_request):
        findings.append("SQL injection keywords detected")
    if _XSS_RE.search(raw_request):
        findings.append("Script/XSS patterns detected")
    if _TRAVERSAL_RE.search(raw_request):
        findings.append("Path traversal patterns detected")
    return bool(findings), findings


# ─────────────────────────────────────────────────────────────────────────────
# Priority Rule Evaluator
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_priority_rules(
    payload_attack: bool,
    malware_domain: bool,
    bot_detected: bool,
    traffic_anomaly: bool,
    payload_findings: Optional[List[str]] = None,
) -> Optional[Tuple[str, str]]:
    """Evaluate ordered hard rules — first match wins.

    Priority rules replace implicit scattered conditions with an explicit,
    deterministic list.  Rules are evaluated in descending severity order.

    Returns:
        (verdict, reason) if a hard rule fires, else None.
    """
    findings_str = ", ".join(payload_findings) if payload_findings else "malicious payload"

    priority_rules: List[Tuple[bool, str, str]] = [
        (
            malware_domain and bool(payload_findings),
            "Dangerous",
            f"Malware domain carrying {findings_str} — immediate block.",
        ),
        (
            malware_domain,
            "Dangerous",
            "Malware domain detected — block immediately.",
        ),
        (
            bool(payload_findings),
            "Dangerous",
            f"{findings_str.capitalize()} — block immediately.",
        ),
        (
            traffic_anomaly and bot_detected,
            "Dangerous",
            "Anomalous traffic with bot activity — block immediately.",
        ),
        (
            payload_attack,
            "Dangerous",
            "Attack payload detected — block immediately.",
        ),
    ]

    for condition, verdict, reason in priority_rules:
        if condition:
            return verdict, reason

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Multi-factor Bot Confidence  (#4)
# ─────────────────────────────────────────────────────────────────────────────

def compute_bot_confidence(
    m2_score: float,
    behavior_score: float,
    m2_weight: float = 0.6,
    behavior_weight: float = 0.4,
) -> float:
    """Weighted combination of Model 2 and behavioral bot scores.

    Replaces naive OR logic that caused high false positives for fast
    users or services making legitimate repeated API calls.

    Args:
        m2_score:       Model 2 (HuggingFace) bot confidence 0.0–1.0
        behavior_score: Behavioral heuristic bot probability 0.0–1.0
        m2_weight:      Weight for ML model score (default 0.6)
        behavior_weight: Weight for behavioral heuristic (default 0.4)

    Returns:
        Combined confidence in [0.0, 1.0]
    """
    return round(min(1.0, m2_weight * m2_score + behavior_weight * behavior_score), 4)


# ─────────────────────────────────────────────────────────────────────────────
# Contextual Dynamic Weights  (#5)
# ─────────────────────────────────────────────────────────────────────────────

def get_dynamic_weights(
    is_api_request: bool,
    shannon_entropy: float = 0.0,
    has_flow_anomaly: bool = False,
    domain_suspicious: bool = False,
    model1_ran: bool = True,
    model3_ran: bool = True,
) -> Dict[str, float]:
    """Compute context-adaptive fusion weights.

    Base weights are boosted by signal conditions:
      high entropy   (≥ 4.5) → boost M1 (payload likely obfuscated/encoded)
      abnormal flow          → boost M3 (traffic pattern more relevant)
      suspicious domain      → boost M4 (URL reputation more critical)

    Weights for models that did not run are zeroed then renormalized
    so active signals always sum to 1.0.

    Returns:
        Dict with keys: w_url, w_traffic, w_payload, w_di
    """
    if is_api_request:
        w_url, w_traffic, w_payload, w_di = 0.25, 0.25, 0.35, 0.15
    else:
        w_url, w_traffic, w_payload, w_di = 0.30, 0.30, 0.25, 0.15

    # Context-based boosts
    if shannon_entropy >= 4.5:
        w_payload += 0.10   # High entropy → payload likely obfuscated/encoded

    if has_flow_anomaly:
        w_traffic += 0.10   # Abnormal flow → traffic signal more informative

    if domain_suspicious:
        w_url += 0.10       # Suspicious/unknown domain → URL reputation critical

    # Zero weights for models that didn't run
    if not model3_ran:
        w_traffic = 0.0
    if not model1_ran:
        w_payload = 0.0

    total = w_url + w_traffic + w_payload + w_di
    if total <= 0:
        return {"w_url": 0.25, "w_traffic": 0.25, "w_payload": 0.25, "w_di": 0.25}

    scale = 1.0 / total
    return {
        "w_url":     round(w_url     * scale, 4),
        "w_traffic": round(w_traffic * scale, 4),
        "w_payload": round(w_payload * scale, 4),
        "w_di":      round(w_di      * scale, 4),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Explainability Builder  (#8)
# ─────────────────────────────────────────────────────────────────────────────

def build_explanation(
    model4_classification: str,
    traffic_anomaly: bool,
    bot_detected: bool,
    payload_attack: bool,
    payload_threat_type: Optional[str],
    domain_flags: List[str],
    payload_findings: Optional[List[str]] = None,
    threat_score: float = 0.0,
    bot_confidence: float = 0.0,
) -> List[str]:
    """Build a human-readable explanation list for the threat verdict.

    Returns a list of specific, actionable reasons so the user doesn't
    have to trust a black-box score.
    """
    reasons: List[str] = []

    # Domain / Model 4 signals
    if model4_classification == "malware":
        reasons.append("Domain classified as malware host")
    elif model4_classification == "phishing":
        reasons.append("Domain classified as phishing site")
    elif model4_classification in ("adult", "betting"):
        reasons.append(f"Domain blocked by policy ({model4_classification} content)")
    elif model4_classification == "blocked":
        reasons.append("Domain is on blocklist")

    for flag in domain_flags:
        if flag.startswith("type_"):
            label = flag.replace("type_", "").replace("_", " ")
            reasons.append(f"Domain flagged as: {label}")

    # Pre-gate payload findings
    if payload_findings:
        reasons.extend(payload_findings)

    # Model 1 / heuristic attack signals
    if payload_attack and payload_threat_type:
        reasons.append(f"Attack type identified: {payload_threat_type}")
    elif payload_attack:
        reasons.append("Malicious payload content detected")

    # Model 3 traffic signal
    if traffic_anomaly:
        reasons.append("Abnormal network traffic pattern detected")

    # Model 2 / behavioral bot signal
    if bot_detected:
        pct = round(bot_confidence * 100)
        reasons.append(f"Bot/automated traffic detected (confidence: {pct}%)")

    # Overall score commentary
    if threat_score >= 0.8:
        reasons.append("Overall threat score critically high (≥ 0.8)")
    elif threat_score >= 0.5:
        reasons.append("Multiple threat signals elevated (≥ 0.5)")

    return reasons if reasons else ["No specific threats identified"]


# ─────────────────────────────────────────────────────────────────────────────
# Risk Memory Layer  (#10)
# ─────────────────────────────────────────────────────────────────────────────

class RiskMemory:
    """Lightweight in-memory reputation tracker for IPs and domains.

    Every request verdict updates the IP's rolling threat score and the
    domain's last-known verdict.  Over time the system becomes smarter
    about repeat offenders without any model retraining.

    IP scores decay on clean requests so legitimate IPs are not
    permanently penalized for past suspicious activity.
    """

    IP_DECAY = 0.95          # score factor per clean request
    DOMAIN_TTL = 3600.0      # seconds before a domain verdict expires (1 hour)
    ATTACK_WEIGHT = 0.25     # threat score added per confirmed attack
    HIGH_RISK_THRESHOLD = 0.6

    def __init__(self) -> None:
        self._ip_scores: Dict[str, float] = {}
        self._ip_attack_counts: Dict[str, int] = defaultdict(int)
        self._domain_history: Dict[str, Tuple[str, float]] = {}   # domain → (verdict, ts)
        self._pattern_counts: Dict[str, int] = defaultdict(int)   # pattern → occurrences

    # ── write methods ─────────────────────────────────────────────────────

    def record_verdict(self, ip: str, domain: Optional[str], verdict: str) -> None:
        """Update IP reputation and domain history after each request decision."""
        is_threat = verdict in ("Dangerous", "Suspicious", "Blocked")
        current = self._ip_scores.get(ip, 0.0)

        if is_threat:
            self._ip_scores[ip] = min(1.0, current + self.ATTACK_WEIGHT)
            self._ip_attack_counts[ip] += 1
        else:
            self._ip_scores[ip] = max(0.0, current * self.IP_DECAY)

        if domain:
            self._domain_history[domain] = (verdict, time.monotonic())

    def record_attack_pattern(self, pattern: str) -> None:
        """Increment occurrence counter for a detected attack pattern."""
        self._pattern_counts[pattern] += 1

    # ── read methods ──────────────────────────────────────────────────────

    def get_ip_reputation(self, ip: str) -> float:
        """Return rolling threat score for IP (0.0 = clean, 1.0 = highly suspicious)."""
        return self._ip_scores.get(ip, 0.0)

    def is_high_risk_ip(self, ip: str) -> bool:
        return self.get_ip_reputation(ip) >= self.HIGH_RISK_THRESHOLD

    def ip_attack_count(self, ip: str) -> int:
        return self._ip_attack_counts[ip]

    def get_domain_verdict(self, domain: str) -> Optional[str]:
        """Return last known verdict if still within TTL, else None."""
        entry = self._domain_history.get(domain)
        if entry is None:
            return None
        verdict, ts = entry
        if time.monotonic() - ts > self.DOMAIN_TTL:
            del self._domain_history[domain]
            return None
        return verdict

    def get_attack_pattern_stats(self) -> Dict[str, int]:
        return dict(self._pattern_counts)
