"""
suspicion_scorer.py
THIS IS THE MAIN ENTRY POINT Person 1 imports from.

Combines rule-based checks + ML anomaly detection into one suspicion
score per artifact, and produces a ranked recommendation list for the
investigator. Everything else in this module (mock_data, features,
ml_model, rule_checks) is internal plumbing this file wires together.

Agreed output schema for a "scored artifact" (per the coordination note
in the task doc — confirm this matches what Person 1/3 expect):
{
    "artifact_id": str,
    "path": str,
    "rule_score": int (0-100),
    "ml_score": int (0-100),
    "suspicion_score": int (0-100),
    "findings": [str, ...],
    "recommended": bool
}
"""

from features import extract_features
from ml_model import compute_anomaly_scores
from rule_checks import apply_rule_checks


# How much weight the ML anomaly score gets vs rule-based score in the
# final blended suspicion score. Tune this once you have real cases to
# validate against — 50/50 is a reasonable, easy-to-explain starting point.
ML_WEIGHT = 0.5
RULE_WEIGHT = 0.5

# Suspicion score threshold above which an artifact is flagged as
# "recommended for investigator review first"
RECOMMENDATION_THRESHOLD = 50


def score_artifacts(artifacts: list[dict]) -> list[dict]:
    """
    Main function. Takes a list of artifact dicts (matching the schema
    documented in mock_data.py — swap in Person 1's real parser output
    once available, as long as field names match) and returns a list of
    scored artifact dicts, sorted by suspicion_score descending.
    """
    if not artifacts:
        return []

    feature_matrix = extract_features(artifacts)
    ml_scores = compute_anomaly_scores(feature_matrix)

    scored = []
    for i, (artifact, ml_score) in enumerate(zip(artifacts, ml_scores)):
        rule_result = apply_rule_checks(artifact)
        rule_score = rule_result["rule_score"]

        suspicion_score = round(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score)

        # .get() with fallbacks: real parser output may not always include
        # these fields under the exact names we expect on day one of
        # integration — falling back to an index-based id beats crashing
        # the whole batch over one malformed record.
        scored.append({
            "artifact_id": artifact.get("artifact_id", f"unknown-{i}"),
            "path": artifact.get("path", "unknown path"),
            "rule_score": rule_score,
            "ml_score": round(ml_score),
            "suspicion_score": suspicion_score,
            "findings": rule_result["rule_findings"],
            "recommended": suspicion_score >= RECOMMENDATION_THRESHOLD,
        })

    scored.sort(key=lambda x: x["suspicion_score"], reverse=True)
    return scored


def get_recommendations(scored_artifacts: list[dict], top_n: int = 10) -> list[dict]:
    """
    Returns the top N artifacts an investigator should look at first.
    Assumes scored_artifacts is already sorted (score_artifacts does this),
    but re-sorts defensively in case it's called on unsorted data.
    """
    sorted_artifacts = sorted(scored_artifacts, key=lambda x: x["suspicion_score"], reverse=True)
    return sorted_artifacts[:top_n]
