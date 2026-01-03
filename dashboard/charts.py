# charts.py
import plotly.express as px
import pandas as pd

def plot_attack_distribution(df: pd.DataFrame):
    return px.histogram(
        df,
        x="Label",
        color="Label",
        title="Attack Distribution",
        template="plotly_dark",
    )

def plot_severity_distribution(df: pd.DataFrame):
    if "Severity" not in df.columns:
        raise ValueError("Severity column not found in dataframe")
    counts = df["Severity"].value_counts().reset_index()
    counts.columns = ["Severity", "Count"]

    color_map = {
        "Critical": "#ff4d4d",
        "High": "#ffa500",
        "Medium": "#f1c40f",
        "Low": "#2ecc71",
    }

    return px.bar(
        counts,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map=color_map,
        title="Severity Distribution",
        template="plotly_dark",
    )

def plot_attack_trend(df: pd.DataFrame):
    temp = df.copy()
    temp["batch"] = temp.index // 50000

    trend = (
        temp[temp["Label"] != "BENIGN"]
        .groupby("batch")
        .size()
        .reset_index(name="Attacks")
    )

    return px.line(
        trend,
        x="batch",
        y="Attacks",
        markers=True,
        title="Attack Trend Over Time (Simulated)",
        template="plotly_dark",
    )

def plot_detection_overview(df: pd.DataFrame):
    benign = (df["Label"] == "BENIGN").sum()
    attack = (df["Label"] != "BENIGN").sum()

    data = pd.DataFrame(
        {"Type": ["Benign", "Attack"], "Count": [benign, attack]}
    )

    return px.bar(
        data,
        x="Type",
        y="Count",
        color="Type",
        title="Detection Overview",
        template="plotly_dark",
    )
