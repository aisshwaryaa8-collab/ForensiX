"""
features.py
Converts raw artifact dicts into numeric feature vectors suitable for
IsolationForest. Keeping this separate from the model code means the
feature set can evolve independently of the scoring logic.
"""

from datetime import datetime

import numpy as np


SUSPICIOUS_KEYWORDS = [
    "failed login", "failed password", "unauthorized", "powershell -enc",
    "disable firewall", "privilege escalation", "reverse shell",
    "connection to", "invalid user", "authentication failure",
]


def keyword_hit_count(text) -> int:
    """Accepts None/non-string gracefully — real parser data may have
    missing or unexpected types for a given field."""
    if not isinstance(text, str):
        return 0
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text.lower())


def safe_hour(modified_time) -> int:
    """
    Extracts hour-of-day from modified_time, tolerating:
    - a real datetime object (what mock_data.py produces)
    - an ISO-format string (common if data passed through JSON, e.g. from
      an API boundary with Person 1's backend)
    - None / missing / unparseable values -> falls back to a neutral hour
      (12) rather than crashing, since one bad timestamp shouldn't take
      down scoring for the whole case.
    """
    if isinstance(modified_time, datetime):
        return modified_time.hour
    if isinstance(modified_time, str):
        try:
            return datetime.fromisoformat(modified_time).hour
        except ValueError:
            return 12
    return 12


def safe_size(size_bytes) -> float:
    """Coerces size to a non-negative number, defaulting to 0 for
    missing/invalid values instead of raising."""
    try:
        return max(float(size_bytes), 0.0)
    except (TypeError, ValueError):
        return 0.0


def extract_features(artifacts: list[dict]) -> np.ndarray:
    """
    Returns an (n_samples, n_features) array. Feature columns, in order:
    0: size_bytes (log-scaled to reduce skew)
    1: hour_of_day modified (0-23) — odd-hour activity is a common signal
    2: is_suspicious_extension (0/1)
    3: keyword_hit_count in content_snippet
    4: filename_length (very long/short names can be anomalous)

    Tolerant of missing/malformed fields in each artifact dict — real
    parser output won't always match the mock data shape exactly, and a
    single bad record shouldn't crash scoring for the whole evidence set.
    """
    rows = []
    for a in artifacts:
        size_log = np.log1p(safe_size(a.get("size_bytes")))
        hour = safe_hour(a.get("modified_time"))
        is_susp_ext = 1 if a.get("is_suspicious_extension") else 0
        kw_hits = keyword_hit_count(a.get("content_snippet"))
        fname_len = len(a.get("filename") or "")

        rows.append([size_log, hour, is_susp_ext, kw_hits, fname_len])

    return np.array(rows, dtype=float)


FEATURE_NAMES = ["size_log", "hour_of_day", "is_suspicious_extension", "keyword_hit_count", "filename_length"]
