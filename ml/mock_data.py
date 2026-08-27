"""
mock_data.py
Generates fake forensic artifacts shaped like what Person 1's parser will
eventually output. Use this to develop and test the ML scoring module
independently, before the real backend pipeline exists.

Swap this out for Person 1's real output once it's ready — as long as
the field names match (see the schema note below), nothing else needs
to change.
"""

import random
from datetime import datetime, timedelta


EXTENSIONS = [".txt", ".log", ".pdf", ".docx", ".exe", ".bat", ".dll", ".jpg", ".ps1", ".zip"]
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".dll", ".ps1"}

SAMPLE_LOG_SNIPPETS_NORMAL = [
    "user login successful",
    "scheduled backup completed",
    "system update installed",
    "file saved successfully",
]

SAMPLE_LOG_SNIPPETS_SUSPICIOUS = [
    "failed login attempt from 203.0.113.45",
    "powershell -enc JABzAD0ATgBlAHc=",
    "disable firewall command executed",
    "unauthorized access attempt detected",
    "connection to 45.33.32.156 established",
]


def generate_mock_artifacts(n: int = 50, suspicious_ratio: float = 0.15, seed: int = 42) -> list[dict]:
    """
    Returns a list of artifact dicts with this schema:
    {
        "artifact_id": str,
        "path": str,
        "filename": str,
        "extension": str,
        "size_bytes": int,
        "modified_time": datetime,
        "created_time": datetime,
        "sha256": str,
        "content_snippet": str,   # empty string if not a text/log file
        "is_suspicious_extension": bool,
    }
    """
    random.seed(seed)
    artifacts = []
    base_time = datetime(2026, 8, 1, 9, 0, 0)

    n_suspicious = max(1, int(n * suspicious_ratio))

    for i in range(n):
        is_suspicious = i < n_suspicious

        if is_suspicious:
            # Mix of suspicious executable-type files AND suspicious log entries,
            # so both rule paths (extension check, keyword check) get exercised
            ext = random.choice([".exe", ".bat", ".ps1", ".dll", ".log"])
        else:
            ext = random.choice(EXTENSIONS)

        modified_time = base_time + timedelta(
            hours=random.randint(0, 72),
            minutes=random.randint(0, 59),
        )
        # Suspicious activity clustered at odd hours, a common real-world signal
        if is_suspicious:
            modified_time = modified_time.replace(hour=random.choice([1, 2, 3, 4]))

        size_bytes = random.randint(500, 50_000) if not is_suspicious else random.randint(50_000, 5_000_000)

        content_snippet = ""
        if ext in (".log", ".txt"):
            content_snippet = random.choice(
                SAMPLE_LOG_SNIPPETS_SUSPICIOUS if is_suspicious else SAMPLE_LOG_SNIPPETS_NORMAL
            )

        artifacts.append({
            "artifact_id": f"artifact-{i:03d}",
            "path": f"case_files/folder_{i % 5}/file_{i}{ext}",
            "filename": f"file_{i}{ext}",
            "extension": ext,
            "size_bytes": size_bytes,
            "modified_time": modified_time,
            "created_time": modified_time - timedelta(minutes=random.randint(0, 30)),
            "sha256": f"mockhash{i:03d}" + "0" * 55,
            "content_snippet": content_snippet,
            "is_suspicious_extension": ext in SUSPICIOUS_EXTENSIONS,
        })

    random.shuffle(artifacts)
    return artifacts


if __name__ == "__main__":
    sample = generate_mock_artifacts(10)
    for a in sample:
        print(a["artifact_id"], a["extension"], a["size_bytes"], a["modified_time"], a["content_snippet"])
