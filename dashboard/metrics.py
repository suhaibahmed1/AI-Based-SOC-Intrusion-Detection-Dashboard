def compute_metrics(df):
    total_records = len(df)

    attack_count = (df["Label"] != "BENIGN").sum()
    benign_count = (df["Label"] == "BENIGN").sum()

    attack_ratio = round((attack_count / total_records) * 100, 2)

    return {
        "total_records": total_records,
        "attack_count": attack_count,
        "benign_count": benign_count,
        "attack_ratio": attack_ratio,
    }


def add_severity(df):
    severity_map = {
        "DoS Hulk": "Critical",
        "DDoS": "Critical",
        "DoS GoldenEye": "High",
        "DoS slowloris": "High",
        "DoS Slowhttptest": "High",
        "PortScan": "Medium",
        "Bot": "Medium",
        "Infiltration": "Medium",
        "Web Attack – Brute Force": "Low",
        "Web Attack – XSS": "Low",
        "Web Attack – Sql Injection": "Low",
    }

    df["Severity"] = df["Label"].map(severity_map).fillna("Low")
    return df
