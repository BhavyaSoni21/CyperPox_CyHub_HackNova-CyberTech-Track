"""
bot_feature_builder.py — Convert simple CSV logs into 14-feature flow vectors for Model 2.

Input CSV columns: timestamp, ip, url
Output: (ip_labels, np.ndarray of shape (n_sessions, 14))

The 14 features match the training schema of Model 2 (bot/botnet detection):
  0  flow_duration          seconds between first and last request
  1  packet_count           total requests in session
  2  unique_urls            distinct URL paths requested
  3  request_rate           packets / flow_duration
  4  url_repetition_ratio   most-repeated URL count / packet_count
  5  unique_user_agents     distinct User-Agent strings (0 if col absent)
  6  iat_mean               mean inter-arrival time (seconds)
  7  iat_std                std dev of inter-arrival times
  8  iat_min                min inter-arrival time
  9  iat_max                max inter-arrival time
 10  burst_ratio            requests in top-10% busiest second / total
 11  hour_of_day            hour (0-23) of first request
 12  url_entropy            Shannon entropy of URL distribution
 13  session_depth_mean     mean URL path depth (number of "/" segments)
"""

from __future__ import annotations

import math
from typing import List, Tuple

import numpy as np
import pandas as pd

BOT_FEATURE_COUNT = 14


def _shannon_entropy(values: pd.Series) -> float:
    counts = values.value_counts(normalize=True)
    return float(-sum(p * math.log2(p) for p in counts if p > 0))


def _url_depth(url: str) -> int:
    path = url.split("?")[0]
    return len([s for s in path.split("/") if s])


def generate_flow_features(df: pd.DataFrame) -> Tuple[List[str], np.ndarray]:
    """
    Group the DataFrame by IP, engineer 14 flow features per session.

    Args:
        df: DataFrame with columns [timestamp, ip, url]
            timestamp can be any pandas-parseable format.

    Returns:
        (ip_labels, feature_matrix)
        ip_labels — list of IP strings (one per row of feature_matrix)
        feature_matrix — np.ndarray of shape (n_sessions, 14), dtype float64
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
    df = df.sort_values("timestamp")

    has_ua = "user_agent" in df.columns

    ip_labels: List[str] = []
    rows: List[List[float]] = []

    for ip, session in df.groupby("ip", sort=False):
        session = session.sort_values("timestamp")
        ts = session["timestamp"]
        urls = session["url"]

        # 0 — flow duration in seconds
        duration = float((ts.max() - ts.min()).total_seconds())

        # 1 — packet count
        n = len(session)

        # 2 — unique URLs
        unique_urls = float(urls.nunique())

        # 3 — request rate (requests/second; avoid div-by-zero)
        rate = n / max(duration, 1.0)

        # 4 — URL repetition ratio (most common URL / total)
        top_url_count = int(urls.value_counts().iloc[0])
        repetition_ratio = top_url_count / n

        # 5 — unique user-agents (0 if column not present)
        unique_uas = float(session["user_agent"].nunique()) if has_ua else 0.0

        # 6-9 — inter-arrival times
        ts_sec = ts.astype(np.int64) / 1e9
        iats = np.diff(ts_sec.values)
        if len(iats) > 0:
            iat_mean = float(np.mean(iats))
            iat_std  = float(np.std(iats))
            iat_min  = float(np.min(iats))
            iat_max  = float(np.max(iats))
        else:
            iat_mean = iat_std = iat_min = iat_max = 0.0

        # 10 — burst ratio (fraction of requests occurring in the busiest 10% of seconds)
        if duration > 0:
            ts_floored = ts.dt.floor("s")
            counts_per_sec = ts_floored.value_counts()
            top_n = max(1, int(len(counts_per_sec) * 0.10))
            burst_count = int(counts_per_sec.nlargest(top_n).sum())
            burst_ratio = burst_count / n
        else:
            burst_ratio = 1.0

        # 11 — hour of first request
        hour = float(ts.iloc[0].hour)

        # 12 — URL entropy
        url_entropy = _shannon_entropy(urls)

        # 13 — mean URL path depth
        depth_mean = float(urls.apply(_url_depth).mean())

        rows.append([
            duration, float(n), unique_urls, rate,
            repetition_ratio, unique_uas,
            iat_mean, iat_std, iat_min, iat_max,
            burst_ratio, hour,
            url_entropy, depth_mean,
        ])
        ip_labels.append(str(ip))
        print(f"[DEBUG] IP {ip}: duration={duration:.1f}s, packets={n}, rate={rate:.2f}/s, "
              f"repetition={repetition_ratio:.2f}, iat_mean={iat_mean:.2f}, iat_std={iat_std:.2f}")

    feature_matrix = np.array(rows, dtype=np.float64)
    # Replace any NaN/Inf that crept in with 0
    feature_matrix = np.where(np.isfinite(feature_matrix), feature_matrix, 0.0)
    return ip_labels, feature_matrix
