"""
train.py — Stage 0: Train AI Models on CICIDS2017
==================================================
Trains two models:
  • Isolation Forest  (unsupervised anomaly detection)
  • Random Forest     (supervised attack classification)

USAGE (standalone):
  python train.py --data ./datasets/
  python train.py --data ./datasets/ --sample 200000

OR called from main.py:
  python main.py --train --data ./datasets/
"""

import os, sys, pickle, argparse, warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
warnings.filterwarnings("ignore")

MODEL_DIR = "models"

# ── CICIDS2017 label → system category ────────────────────────────────────
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
        files = sorted([
            os.path.join(path, f)
            for f in os.listdir(path) if f.lower().endswith(".csv")
        ])
        if not files:
            sys.exit(f"[!] No CSV files found in {path}")
        print(f"  Found {len(files)} CSV files:")
        parts = []
        for fp in files:
            mb = os.path.getsize(fp) / 1e6
            print(f"    {os.path.basename(fp)}  ({mb:.0f} MB)")
            df = pd.read_csv(fp, low_memory=False,
                             encoding="utf-8", encoding_errors="replace")
            df.columns = df.columns.str.strip()
            parts.append(df)
        data = pd.concat(parts, ignore_index=True)
    else:
        data = pd.read_csv(path, low_memory=False,
                           encoding="utf-8", encoding_errors="replace")
        data.columns = data.columns.str.strip()

    print(f"\n  Total rows loaded : {len(data):,}")
    print(f"  Columns           : {len(data.columns)}")

    if "Label" not in data.columns:
        sys.exit(f"[!] 'Label' column not found. Available: {list(data.columns)}")

    data["Label"]    = data["Label"].astype(str).str.strip()
    data["category"] = data["Label"].map(LABEL_MAP).fillna("Normal")

    unknown = data[~data["Label"].isin(LABEL_MAP)]["Label"].unique()
    if len(unknown):
        print(f"  [!] Unknown labels (mapped to Normal): {list(unknown)}")

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


def train_pipeline(data_path: str, sample_size: int = 300000):
    os.makedirs(MODEL_DIR, exist_ok=True)
    X, y_raw, feature_cols = load_cicids2017(data_path)

    class_to_idx = {c: i for i, c in enumerate(CLASSES)}
    y = y_raw.map(class_to_idx).fillna(0).astype(int)

    # Sample
    if len(X) > sample_size:
        print(f"\n  Sampling {sample_size:,} rows from {len(X):,} ...")
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), sample_size, replace=False)
        X   = X.iloc[idx].reset_index(drop=True)
        y   = y.iloc[idx].reset_index(drop=True)
        y_raw = y_raw.iloc[idx].reset_index(drop=True)

    # Scale
    print("\n  Scaling features ...")
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y, test_size=0.20, random_state=42, stratify=y)

    # ── Isolation Forest ──────────────────────────────────────────────────
    print("\n  Training Isolation Forest (anomaly detection) ...")
    X_normal = X_scaled[y.values == 0]
    iso = IsolationForest(
        n_estimators=200, contamination=0.10,
        max_samples="auto", random_state=42, n_jobs=-1)
    iso.fit(X_normal)
    print(f"    → Trained on {len(X_normal):,} BENIGN samples")

    # ── Random Forest ─────────────────────────────────────────────────────
    print("\n  Training Random Forest (attack classifier) ...")
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=25, min_samples_split=5,
        class_weight="balanced", random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)

    y_pred = rf.predict(X_te)
    acc    = accuracy_score(y_te, y_pred)
    active_idx   = sorted(y_te.unique())
    active_names = [CLASSES[i] for i in active_idx]

    print(f"\n{'═'*60}")
    print(f"  Random Forest Accuracy : {acc*100:.2f}%")
    print(f"{'═'*60}")
    print(classification_report(y_te, y_pred,
          labels=active_idx, target_names=active_names, zero_division=0))

    # ── Save models ───────────────────────────────────────────────────────
    def _save(obj, name):
        with open(os.path.join(MODEL_DIR, name), "wb") as f:
            pickle.dump(obj, f)

    _save(iso,          "isolation_forest.pkl")
    _save(rf,           "random_forest.pkl")
    _save(scaler,       "scaler.pkl")
    _save(CLASSES,      "classes.pkl")
    _save(feature_cols, "feature_cols.pkl")

    print(f"[+] Models saved to ./{MODEL_DIR}/")
    print(f"    isolation_forest.pkl  |  random_forest.pkl")
    print(f"    scaler.pkl  |  classes.pkl  |  feature_cols.pkl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI models on CICIDS2017")
    parser.add_argument("--data",   required=True,
                        help="Path to CICIDS2017 CSV folder or single CSV")
    parser.add_argument("--sample", type=int, default=300000,
                        help="Max training rows (default 300000)")
    args = parser.parse_args()
    train_pipeline(args.data, args.sample)
