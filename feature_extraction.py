"""
feature_extraction.py — Stage 2: Feature Extraction
=====================================================
Aligns any traffic DataFrame to the exact feature columns
the AI models were trained on (CICIDS2017 format).
"""

import numpy as np
import pandas as pd

META_COLS = {
    "Flow ID","Source IP","Source Port","Destination IP",
    "Destination Port","Protocol","Timestamp","Label",
    "Fwd Header Length.1","category",
}


def extract(df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    """
    Align df columns to the trained model's feature_cols.
    Missing columns are zero-filled. Non-feature columns are dropped.
    Returns a clean numeric DataFrame ready for the AI models.
    """
    X = pd.DataFrame(index=df.index)
    for col in feature_cols:
        if col in df.columns:
            X[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            X[col] = 0.0
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0.0, inplace=True)
    return X
