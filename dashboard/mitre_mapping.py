# mitre_mapping.py

from typing import List

# Mapping of CICIDS 2017 attacks to MITRE ATT&CK techniques
MITRE_MAPPING = {
    "DDoS": ["T1499"],  # Endpoint Denial of Service
    "DoS Hulk": ["T1499"],
    "DoS GoldenEye": ["T1499"],
    "DoS slowloris": ["T1499"],
    "DoS Slowhttptest": ["T1499"],
    "PortScan": ["T1046"],  # Network Service Discovery
    "Bot": ["T1090", "T1071"],  # Remote Access & Exfiltration
    "Infiltration": ["T1071", "T1059"],  # Command & Scripting
    "Web Attack – Brute Force": ["T1110"],  # Brute Force
    "Web Attack – XSS": ["T1059.007"],  # Scripting: Browser
    "Web Attack – Sql Injection": ["T1059.006"],  # SQL Injection
}

def map_to_mitre(label: str) -> List[str]:
    """
    Returns a list of MITRE ATT&CK IDs for a given attack label.
    If not mapped, returns an empty list.
    """
    return MITRE_MAPPING.get(label, [])
