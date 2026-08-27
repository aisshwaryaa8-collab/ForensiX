"""
rule_checks.py
Deterministic, explainable checks — the counterpart to the ML anomaly
score. Keeping these separate matters for a forensics tool: investigators
need to know which flags are "the model thinks this is weird" vs
"this literally matches a known-bad pattern."
"""

from features import safe_hour

SUSPICIOUS_KEYWORDS = [
    "failed login", "failed password", "unauthorized", "powershell -enc",
    "disable firewall", "privilege escalation", "reverse shell",
    "connection to", "invalid user", "authentication failure",
]

RULE_WEIGHTS = {
    "suspicious_extension": 20,
    "keyword_match": 15,   # per keyword matched, capped below
    "odd_hour_activity": 10,
}

ODD_HOURS = set(range(0, 5))  # midnight-5am


def apply_rule_checks(artifact: dict) -> dict:
    """
    Returns {"rule_score": int (0-100), "rule_findings": [str, ...]}
    Tolerant of missing/malformed fields — a real artifact record won't
    always have every field the mock data guarantees.
    """
    findings = []
    score = 0

    if artifact.get("is_suspicious_extension"):
        findings.append(f"Suspicious file extension ({artifact.get('extension', 'unknown')})")
        score += RULE_WEIGHTS["suspicious_extension"]

    content_raw = artifact.get("content_snippet")
    content = content_raw.lower() if isinstance(content_raw, str) else ""
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in content]
    if matched_keywords:
        findings.append(f"Suspicious content: {', '.join(matched_keywords)}")
        score += min(RULE_WEIGHTS["keyword_match"] * len(matched_keywords), 45)

    hour = safe_hour(artifact.get("modified_time"))
    if hour in ODD_HOURS:
        findings.append(f"Activity at unusual hour ({hour}:00)")
        score += RULE_WEIGHTS["odd_hour_activity"]

    return {"rule_score": min(score, 100), "rule_findings": findings}
