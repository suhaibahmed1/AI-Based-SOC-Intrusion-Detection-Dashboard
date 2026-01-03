# mitre_mapping.py

from typing import List

MITRE_MAPPING = {
    "DDoS": ["T1499"],
    "DoS Hulk": ["T1499"],
    "DoS GoldenEye": ["T1499"],
    "DoS slowloris": ["T1499"],
    "DoS Slowhttptest": ["T1499"],
    "PortScan": ["T1046"],
    "Bot": ["T1090", "T1071"],
    "Infiltration": ["T1071", "T1059"],
    "Web Attack - Brute Force": ["T1110"],
    "Web Attack - XSS": ["T1059.007"],
    "Web Attack - Sql Injection": ["T1059.006"],
}

def map_to_mitre(label: str) -> List[str]:
    return MITRE_MAPPING.get(label, [])
