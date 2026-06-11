"""
feature_extract.py — Stage 2: Feature Extraction
=================================================
Aligns any traffic DataFrame to the exact feature columns
the AI models were trained on.
"""

import numpy as np
import pandas as pd

DROP_META = {
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Destination Port", "Protocol", "Timestamp", "Label",
    "Fwd Header Length.1", "category",
    # internal metadata columns added by capture.py
    "src_ip", "dst_ip", "src_port", "dst_port", "proto",
}


def extract_features(df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    """
    Align df to exactly the feature_cols the model was trained on.
    Missing columns are zero-filled. Extra columns are dropped.
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
