import streamlit as st
import pandas as pd
import plotly.express as px

from data_loader import load_data
from metrics import compute_metrics, add_severity
from charts import (
    plot_attack_distribution,
    plot_attack_trend,
    plot_severity_distribution,
    plot_detection_overview,
)
from mitre_mapping import map_to_mitre

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="AI-Based Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
)

# ---------------- CUSTOM STYLE ----------------
st.markdown(
    """
    <style>
    h1, h2, h3 { color: #4fc3f7 !important; }

    [data-testid="metric-container"] {
        background-color: #161b22;
        border-radius: 10px;
        padding: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------- TITLE ----------------
st.title("🛡️ AI-Based Intrusion Detection & Risk Dashboard")
st.caption("SOC-style dashboard using CICIDS 2017 dataset")

# ---------------- LOAD DATA ----------------
@st.cache_data
def get_data():
    return load_data("../data/cleaned_cicids2017.csv")

df = get_data()
df = add_severity(df)

# Map attacks to MITRE techniques
df["MITRE"] = df["Label"].apply(map_to_mitre)

# ---------------- METRICS ----------------
metrics = compute_metrics(df)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", f"{metrics['total_records']:,}")
c2.metric("Critical Alerts", f"{metrics['attack_count']:,}")
c3.metric("Benign Traffic", f"{metrics['benign_count']:,}")
c4.metric("Attack Ratio", f"{metrics['attack_ratio']}%")

st.divider()

# ---------------- FILTER SIDEBAR ----------------
st.sidebar.header("🎛 Filters")

severity_filter = st.sidebar.selectbox(
    "Severity Level",
    ["All", "Critical", "High", "Medium", "Low"]
)

attack_types = ["All"] + sorted(df["Label"].unique())
attack_filter = st.sidebar.selectbox("Attack Type", attack_types)

filtered_df = df.copy()

if severity_filter != "All":
    filtered_df = filtered_df[filtered_df["Severity"] == severity_filter]

if attack_filter != "All":
    filtered_df = filtered_df[filtered_df["Label"] == attack_filter]

# ---------------- CHARTS ----------------
st.subheader("📊 Attack Distribution")
st.plotly_chart(plot_attack_distribution(filtered_df), use_container_width=True)

st.subheader("🚦 Severity Distribution")
st.plotly_chart(plot_severity_distribution(filtered_df), use_container_width=True)

st.subheader("📈 Attack Trend Over Time")
st.plotly_chart(plot_attack_trend(filtered_df), use_container_width=True)

with st.expander("🧠 Detection Overview"):
    st.plotly_chart(plot_detection_overview(filtered_df), use_container_width=True)

# ---------------- MITRE ATT&CK MAPPING ----------------
st.subheader("🗺️ MITRE ATT&CK Mapping")

mitre_counts = {}
for tactics in filtered_df["MITRE"]:
    for t in tactics:
        mitre_counts[t] = mitre_counts.get(t, 0) + 1

if mitre_counts:
    mitre_df = pd.DataFrame({
        "MITRE Technique": list(mitre_counts.keys()),
        "Count": list(mitre_counts.values())
    })

    colors = px.colors.qualitative.Plotly
    color_map = {mitre: colors[i % len(colors)] for i, mitre in enumerate(mitre_df["MITRE Technique"])}

    fig = px.bar(
        mitre_df,
        x="MITRE Technique",
        y="Count",
        title="MITRE ATT&CK Mapping of Detected Attacks",
        template="plotly_dark",
        color="MITRE Technique",
        color_discrete_map=color_map
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No attacks mapped to MITRE techniques in the selected filters.")

# ---------------- SOC ALERT TABLE ----------------
st.subheader("🚨 SOC Alerts")

severity_colors = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

alerts = filtered_df.copy()
alerts["Severity"] = alerts["Severity"].map(
    lambda x: f"{severity_colors.get(x, '')} {x}"
)

cols = ["Label", "Severity"]
existing_cols = [c for c in cols if c in alerts.columns]

st.dataframe(
    alerts[existing_cols].head(50).reset_index(drop=True),
    use_container_width=True,
)

# ---------------- FOOTER ----------------
st.markdown(
    """
---
**AI-Based Intrusion Detection System (IDS)**  
Built with **Python, Streamlit & CICIDS 2017**  
Designed for SOC monitoring, alert triage & security analytics  
"""
)
