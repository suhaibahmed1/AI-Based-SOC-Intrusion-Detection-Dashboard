# data_loader.py
import pandas as pd

def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(
    csv_path,
    sep=",",
    engine="python",
    on_bad_lines="skip",
    encoding="utf-8",
)

    df.columns = df.columns.str.strip()

    # Ensure timestamp exists and is datetime
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        # Drop rows with invalid timestamps
        df = df.dropna(subset=["timestamp"])

    return df
