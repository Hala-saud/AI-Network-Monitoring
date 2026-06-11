"""
scoring.py — Stage 4: Threat Scoring
======================================
Combines AI outputs + heuristics → composite score [0–1] → Low/Medium/High
"""

import numpy as np
import pandas as pd

ATTACK_SEVERITY = {
    "Normal":      "NORMAL",
    "DoS":         "HIGH",
    "DDoS":        "HIGH",
    "PortScan":    "MEDIUM",
    "BruteForce":  "HIGH",
    "WebAttack":   "HIGH",
    "Botnet":      "HIGH",
    "Infiltration":"HIGH",
}

ATTACK_RISK = {
    "Normal":      0.00, "DoS":    0.85, "DDoS":         0.90,
    "PortScan":    0.60, "BruteForce": 0.80, "WebAttack": 0.75,
    "Botnet":      0.85, "Infiltration": 0.80,
}

W_ANOM = 0.35
W_CONF = 0.45
W_HEUR = 0.20


def _heuristic(row: pd.Series) -> float:
    score = 0.0
    pps = float(row.get("Flow Packets/s", 0) or 0)
    syn = float(row.get("SYN Flag Count", 0) or 0)
    rst = float(row.get("RST Flag Count", 0) or 0)
    pm  = float(row.get("Packet Length Mean", 0) or 0)
    bwd = float(row.get("Total Backward Packets", 0) or 0)
    fwd = float(row.get("Total Fwd Packets", 1) or 1)
    if pps > 10000: score += 0.40
    elif pps > 2000: score += 0.20
    elif pps > 500:  score += 0.10
    if syn > 100 and bwd < fwd * 0.1: score += 0.30
    if rst > 50: score += 0.15
    if pm < 60 and pps > 100: score += 0.20
    return min(1.0, score)


def score_flows(df_raw: pd.DataFrame, predictions: pd.DataFrame) -> pd.DataFrame:
    """
    Merge raw metadata + AI predictions → fully scored flow DataFrame.
    Each row gets: src_ip, dst_ip, attack, severity, composite_score, etc.
    """
    rows = []
    for idx in df_raw.index:
        raw  = df_raw.loc[idx]
        pred = predictions.loc[idx]

        attack = pred["attack"]
        conf   = float(pred["confidence"])
        anom   = float(pred["anomaly_score"])
        is_a   = bool(pred["is_anomaly"])
        risk   = ATTACK_RISK.get(attack, 0.0)
        heur   = _heuristic(raw)

        if is_a:
            comp = W_ANOM*anom + W_CONF*conf*risk + W_HEUR*heur
        else:
            comp = W_ANOM*anom*0.3 + W_CONF*conf*risk + W_HEUR*heur
        comp = float(np.clip(comp, 0.0, 1.0))

        base = ATTACK_SEVERITY.get(attack, "NORMAL")
        if attack == "Normal" and comp < 0.15:   sev = "NORMAL"
        elif attack == "Normal":                  sev = "LOW"
        elif base == "HIGH"   and comp >= 0.65:   sev = "HIGH"
        elif comp >= 0.35:                         sev = "MEDIUM"
        elif comp >= 0.15:                         sev = "LOW"
        else:                                      sev = "NORMAL"

        rows.append({
            "src_ip":          str(raw.get("Source IP",          raw.get("src_ip",  "?"))),
            "dst_ip":          str(raw.get("Destination IP",     raw.get("dst_ip",  "?"))),
            "src_port":        str(raw.get("Source Port",        raw.get("src_port","?"))),
            "dst_port":        str(raw.get("Destination Port",   raw.get("dst_port","?"))),
            "protocol":        str(raw.get("Protocol",           raw.get("proto",   "?"))),
            "attack":          attack,
            "confidence":      round(conf, 4),
            "is_anomaly":      is_a,
            "anomaly_score":   round(anom, 4),
            "composite_score": round(comp, 4),
            "severity":        sev,
            "rf_probas":       str(pred["rf_probas"]),
        })
    return pd.DataFrame(rows)
