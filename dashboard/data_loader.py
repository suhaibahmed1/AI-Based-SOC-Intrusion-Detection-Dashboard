# data_loader.py
import pandas as pd

def load_data(csv_path: str) -> pd.DataFrame:
    """
    Load CICIDS 2017 CSV, clean column names and labels.
    """
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    
    # Clean Label column
    df["Label"] = df["Label"].str.strip()                    # remove spaces
    df["Label"] = df["Label"].str.replace("–", "-", regex=False)  # replace en-dash with hyphen
    
    return df
