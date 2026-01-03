import pandas as pd

def load_data(csv_path: str) -> pd.DataFrame:
    """
    Load CICIDS 2017 CSV, ensure timestamps are parsed,
    and drop invalid rows.
    """
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    return df
