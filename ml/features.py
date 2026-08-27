"""
features.py
Converts raw artifact dicts into numeric feature vectors suitable for
IsolationForest. Keeping this separate from the model code means the
feature set can evolve independently of the scoring logic.
"""

import numpy as np


SUSPICIOUS_KEYWORDS = [
    "failed login", "failed password", "unauthorized", "powershell -enc",
    "disable firewall", "privilege escalation", "reverse shell",
    "connection to", "invalid user", "authentication failure",
]


def keyword_hit_count(text: str) -> int:
    text_lower = (text or "").lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)


def extract_features(artifacts: list[dict]) -> np.ndarray:
    """
    Returns an (n_samples, n_features) array. Feature columns, in order:
    0: size_bytes (log-scaled to reduce skew)
    1: hour_of_day modified (0-23) — odd-hour activity is a common signal
    2: is_suspicious_extension (0/1)
    3: keyword_hit_count in content_snippet
    4: filename_length (very long/short names can be anomalous)
    """
    rows = []
    for a in artifacts:
        size_log = np.log1p(a.get("size_bytes", 0))
        hour = a["modified_time"].hour if a.get("modified_time") else 12
        is_susp_ext = 1 if a.get("is_suspicious_extension") else 0
        kw_hits = keyword_hit_count(a.get("content_snippet", ""))
        fname_len = len(a.get("filename", ""))

        rows.append([size_log, hour, is_susp_ext, kw_hits, fname_len])

    return np.array(rows, dtype=float)


FEATURE_NAMES = ["size_log", "hour_of_day", "is_suspicious_extension", "keyword_hit_count", "filename_length"]
