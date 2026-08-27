import csv
import re
import os
from datetime import datetime

# --- Known "bad" indicators for this prototype (hardcoded for demo purposes) ---
SUSPICIOUS_IPS = {"45.227.253.109", "185.220.101.7"}
SUSPICIOUS_PORTS = {"4444", "8080"}

def parse_auth_log(filepath):
    """Parses an auth.log style file, returns list of artifact dicts."""
    artifacts = []
    with open(filepath, "r") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            iocs = []
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            src_ip = ip_match.group(1) if ip_match else None

            if src_ip in SUSPICIOUS_IPS:
                iocs.append(f"Suspicious source IP: {src_ip}")
            if "Failed password" in line:
                iocs.append("Failed login attempt")
            if "curl" in line and "bash" in line:
                iocs.append("Remote script execution via curl|bash")

            artifacts.append({
                "id": f"auth-{i}",
                "source_file": os.path.basename(filepath),
                "type": "auth_log",
                "raw": line,
                "src_ip": src_ip,
                "iocs": iocs
            })
    return artifacts


def parse_network_csv(filepath):
    """Parses network_connections.csv, returns list of artifact dicts."""
    artifacts = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            iocs = []
            if row["dst_ip"] in SUSPICIOUS_IPS:
                iocs.append(f"Connection to known suspicious IP: {row['dst_ip']}")
            if row["dst_port"] in SUSPICIOUS_PORTS:
                iocs.append(f"Connection to high-risk port: {row['dst_port']}")

            artifacts.append({
                "id": f"net-{i}",
                "source_file": os.path.basename(filepath),
                "type": "network_connection",
                "raw": row,
                "iocs": iocs
            })
    return artifacts


def parse_file_inventory(filepath):
    """Parses file_inventory.txt (csv-style), returns list of artifact dicts."""
    artifacts = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            iocs = []
            filename = os.path.basename(row["filepath"])

            # crude lookalike-filename check (e.g. svch0st.exe instead of svchost.exe)
            if re.search(r"[0-9]", filename) and filename.lower().replace("0", "o").endswith(".exe"):
                iocs.append(f"Possible lookalike/masquerading filename: {filename}")
            if "password" in filename.lower():
                iocs.append(f"Sensitive-looking filename: {filename}")

            artifacts.append({
                "id": f"file-{i}",
                "source_file": os.path.basename(filepath),
                "type": "file_record",
                "raw": row,
                "iocs": iocs
            })
    return artifacts


def parse_all(sample_data_dir="sample_data"):
    """Runs all parsers over the sample_data folder and returns one combined list."""
    all_artifacts = []

    auth_path = os.path.join(sample_data_dir, "auth.log")
    net_path = os.path.join(sample_data_dir, "network_connections.csv")
    file_path = os.path.join(sample_data_dir, "file_inventory.txt")

    if os.path.exists(auth_path):
        all_artifacts.extend(parse_auth_log(auth_path))
    if os.path.exists(net_path):
        all_artifacts.extend(parse_network_csv(net_path))
    if os.path.exists(file_path):
        all_artifacts.extend(parse_file_inventory(file_path))

    return all_artifacts


# Quick manual test — lets you run this file directly to check it works
if __name__ == "__main__":
    results = parse_all()
    print(f"Parsed {len(results)} artifacts total.\n")
    for artifact in results:
        if artifact["iocs"]:
            print(artifact)