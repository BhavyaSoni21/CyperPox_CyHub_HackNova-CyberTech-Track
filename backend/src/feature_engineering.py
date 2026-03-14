"""
CyHub — Feature Engineering Module

Converts raw HTTP request strings into numerical feature vectors
for the Isolation Forest anomaly detection model.

Features:
  - request_length     : Total character length of the request
  - url_depth          : Number of '/' separators in the URL path
  - param_count        : Number of query parameters (count of '=')
  - special_char_count : Count of injection-related special characters
  - shannon_entropy    : Shannon entropy of the full request string
  - sql_keyword_score  : Presence score of SQL injection keywords
  - script_tag_score   : Presence score of XSS/script injection patterns
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List

import numpy as np
import pandas as pd

SPECIAL_CHARS = set("'\";<>=%(")

SQL_KEYWORDS = ["SELECT", "DROP", "UNION", "INSERT", "DELETE", "UPDATE", "OR", "AND", "EXEC", "EXECUTE"]

SCRIPT_PATTERNS = [
    r"<script",
    r"</script",
    r"onerror",
    r"onload",
    r"javascript:",
    r"eval\(",
    r"alert\(",
    r"document\.",
    r"window\.",
]


# Matches standard UUID/GUID: 8-4-4-4-12 hex chars (case-insensitive)
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _strip_uuids(s: str) -> str:
    """Remove UUID/GUID segments from a string before entropy scoring.

    UUIDs are random hex and produce artificially high Shannon entropy
    (~3.7 bits/char), identical to obfuscated payloads.  Stripping them
    prevents legitimate UUID-based routes from being flagged as suspicious.
    """
    return _UUID_RE.sub("", s)



def compute_shannon_entropy(s: str) -> float:
    """Compute the Shannon entropy of a string.
    
    Higher entropy → more randomness / unpredictability,
    which may indicate obfuscated or encoded payloads.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def count_special_chars(s: str) -> int:
    """Count injection-related special characters in a string."""
    return sum(1 for c in s if c in SPECIAL_CHARS)


def compute_sql_keyword_score(s: str) -> int:
    """Score the presence of SQL keywords in the request string.
    
    Each distinct SQL keyword found adds 1 to the score.
    Case-insensitive matching.
    """
    upper = s.upper()
    score = 0
    for keyword in SQL_KEYWORDS:
        if re.search(r'\b' + keyword + r'\b', upper):
            score += 1
    return score


def compute_script_tag_score(s: str) -> int:
    """Score the presence of XSS / script injection patterns.
    
    Each distinct pattern found adds 1 to the score.
    Case-insensitive matching.
    """
    lower = s.lower()
    score = 0
    for pattern in SCRIPT_PATTERNS:
        if re.search(pattern, lower):
            score += 1
    return score


def extract_features(request: str) -> Dict[str, float]:
    """Extract the full feature vector from a single raw HTTP request string.
    
    Returns a dict with keys:
        request_length, url_depth, param_count, special_char_count,
        shannon_entropy, sql_keyword_score, script_tag_score
    """
    return {
        "request_length": float(len(request)),
        "url_depth": float(request.count("/")),
        "param_count": float(request.count("=")),
        "special_char_count": float(count_special_chars(request)),
        "shannon_entropy": compute_shannon_entropy(_strip_uuids(request)),
        "sql_keyword_score": float(compute_sql_keyword_score(request)),
        "script_tag_score": float(compute_script_tag_score(request)),
    }


def extract_features_batch(requests: List[str]) -> pd.DataFrame:
    """Extract features from a batch of request strings.
    
    Returns a DataFrame where each row is a feature vector.
    """
    rows = [extract_features(r) for r in requests]
    return pd.DataFrame(rows)

FEATURE_COLUMNS = [
    "request_length",
    "url_depth",
    "param_count",
    "special_char_count",
    "shannon_entropy",
    "sql_keyword_score",
    "script_tag_score",
]
