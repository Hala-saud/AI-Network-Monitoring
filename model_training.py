"""
model_training.py — Stage 0: Train AI Models on CICIDS2017
===========================================================
Trains:
  • Isolation Forest  — unsupervised anomaly detection
  • Random Forest     — supervised multi-class attack classification

Usage:
  python model_training.py --data ./datasets/
  python model_training.py --data ./datasets/ --sample 200000
"""

import os, sys, pickle, argparse, warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
warnings.filterwarnings("ignore")

MODEL_DIR = "models"

# CICIDS2017 label → our category
LABEL_MAP = {
    "BENIGN":                              "Normal",
    "DoS Hulk":                            "DoS",
    "DoS GoldenEye":                       "DoS",
    "DoS slowloris":                       "DoS",
    "DoS Slowhttptest":                    "DoS",
    "Heartbleed":                          "DoS",
    "DDoS":                                "DDoS",
    "PortScan":                            "PortScan",
    "FTP-Patator":                         "BruteForce",
    "SSH-Patator":                         "BruteForce",
    "Web Attack \u2013 Brute Force":       "BruteForce",
    "Web Attack \x96 Brute Force":         "BruteForce",
    "Web Attack - Brute Force":            "BruteForce",
    "Web Attack \u2013 XSS":              "WebAttack",
    "Web Attack \x96 XSS":               "WebAttack",
    "Web Attack - XSS":                   "WebAttack",
    "Web Attack \u2013 Sql Injection":    "WebAttack",
    "Web Attack \x96 Sql Injection":      "WebAttack",
    "Web Attack - Sql Injection":         "WebAttack",
    "Infiltration":                        "Infiltration",
    "Bot":                                 "Botnet",
}

CLASSES = ["Normal", "DoS", "DDoS", "PortScan",
           "BruteForce", "WebAttack", "Botnet", "Infiltration"]

DROP_COLS = {
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Destination Port", "Protocol", "Timestamp", "Label",
    "Fwd Header Length.1",
}


def load_cicids2017(path: str):
    print(f"\n[Stage 0] Loading CICIDS2017 from: {path}")
    if os.path.isdir(path):
        files = sorted([os.path.join(path, f)
                        for f in os.listdir(path) if f.lower().endswith(".csv")])
        if not files:
            sys.exit(f"[!] No CSV files found in {path}")
        print(f"  Found {len(files)} CSV files:")
        parts = []
        for fp in files:
            mb = os.path.getsize(fp) / 1e6
            print(f"    {os.path.basename(fp)}  ({mb:.0f} MB)")
            df = pd.read_csv(fp, low_memory=False, encoding="utf-8",
                             encoding_errors="replace")
            df.columns = df.columns.str.strip()
            parts.append(df)
        data = pd.concat(parts, ignore_index=True)
    else:
        data = pd.read_csv(path, low_memory=False, encoding="utf-8",
                           encoding_errors="replace")
        data.columns = data.columns.str.strip()

    print(f"\n  Total rows : {len(data):,}  |  Columns: {len(data.columns)}")

    if "Label" not in data.columns:
        sys.exit(f"[!] 'Label' column not found.")

    data["Label"]    = data["Label"].astype(str).str.strip()
    data["category"] = data["Label"].map(LABEL_MAP).fillna("Normal")

    print(f"\n  Label distribution:")
    for cat in CLASSES:
        n = (data["category"] == cat).sum()
        if n > 0:
            bar = "█" * min(int(n / len(data) * 40), 40)
            print(f"    {cat:<15} {n:>9,}  {n/len(data)*100:>5.1f}%  {bar}")

    feature_cols = [c for c in data.columns
                    if c not in DROP_COLS and c != "category"]
    X = data[feature_cols].apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(X.median(numeric_only=True), inplace=True)
    return X, data["category"], feature_cols


def train(data_path: str, sample_size: int = 300000):
    os.makedirs(MODEL_DIR, exist_ok=True)
    X, y_raw, feature_cols = load_cicids2017(data_path)

    class_to_idx = {c: i for i, c in enumerate(CLASSES)}
    y = y_raw.map(class_to_idx).fillna(0).astype(int)

    if len(X) > sample_size:
        print(f"\n  Sampling {sample_size:,} rows from {len(X):,} ...")
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), sample_size, replace=False)
        X   = X.iloc[idx].reset_index(drop=True)
        y   = y.iloc[idx].reset_index(drop=True)

    print("\n  Scaling features ...")
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y, test_size=0.20, random_state=42, stratify=y)

    print("\n  Training Isolation Forest (anomaly detection) ...")
    X_normal = X_scaled[y.values == 0]
    iso = IsolationForest(n_estimators=200, contamination=0.10,
                          random_state=42, n_jobs=-1)
    iso.fit(X_normal)
    print(f"    → Trained on {len(X_normal):,} BENIGN samples")

    print("\n  Training Random Forest (attack classifier) ...")
    rf = RandomForestClassifier(n_estimators=300, max_depth=25,
                                class_weight="balanced",
                                random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)

    y_pred = rf.predict(X_te)
    acc    = accuracy_score(y_te, y_pred)
    active = sorted(y_te.unique())
    names  = [CLASSES[i] for i in active]

    print(f"\n{'═'*58}")
    print(f"  Random Forest Accuracy : {acc*100:.2f}%")
    print(f"{'═'*58}")
    print(classification_report(y_te, y_pred, labels=active,
          target_names=names, zero_division=0))

    def _save(obj, name):
        with open(os.path.join(MODEL_DIR, name), "wb") as f:
            pickle.dump(obj, f)

    _save(iso,          "isolation_forest.pkl")
    _save(rf,           "random_forest.pkl")
    _save(scaler,       "scaler.pkl")
    _save(CLASSES,      "classes.pkl")
    _save(feature_cols, "feature_cols.pkl")
    print(f"\n[+] Models saved to ./{MODEL_DIR}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",   required=True)
    parser.add_argument("--sample", type=int, default=300000)
    args = parser.parse_args()
    train(args.data, args.sample)
