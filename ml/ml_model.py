"""
ml_model.py
Wraps scikit-learn's IsolationForest for per-case anomaly detection.
Self-contained per case, as scoped in the task doc — the model is
trained fresh on each case's own artifacts rather than a pre-trained
global model, since "normal" varies a lot between systems/cases.
"""

import numpy as np
from sklearn.ensemble import IsolationForest


def compute_anomaly_scores(feature_matrix: np.ndarray, contamination: float = 0.15, seed: int = 42) -> np.ndarray:
    """
    Fits IsolationForest on the case's own artifacts and returns a
    normalized anomaly score per artifact, scaled 0-100 (100 = most anomalous).

    contamination: rough expected proportion of anomalous artifacts in
    the case. 0.15 is a reasonable default for a demo; tune per case
    if you have ground truth to check against.
    """
    if len(feature_matrix) < 2:
        # Not enough data to fit meaningfully — return neutral scores
        return np.zeros(len(feature_matrix))

    model = IsolationForest(contamination=contamination, random_state=seed)
    model.fit(feature_matrix)

    # decision_function: higher = more normal, lower/negative = more anomalous.
    # We flip and normalize to a 0-100 "anomaly score" so higher = more suspicious,
    # matching the convention used elsewhere in the pipeline (rule-based scorer, etc.)
    raw_scores = model.decision_function(feature_matrix)

    min_score, max_score = raw_scores.min(), raw_scores.max()
    if max_score == min_score:
        return np.zeros(len(feature_matrix))

    normalized = (max_score - raw_scores) / (max_score - min_score)  # flip: anomalous -> higher
    return normalized * 100
