"""
detection.py — Stage 3: AI-Based Detection
===========================================
Dual-layer detection using trained CICIDS2017 models:
  Layer 1 : Isolation Forest  — unsupervised anomaly detection
  Layer 2 : Random Forest     — supervised attack classification
"""

import os, sys, pickle
import numpy as np
import pandas as pd

MODEL_DIR = "models"


class Detector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def load(self) -> bool:
        if self._loaded:
            return True
        files = ["isolation_forest.pkl","random_forest.pkl",
                 "scaler.pkl","classes.pkl","feature_cols.pkl"]
        missing = [f for f in files
                   if not os.path.exists(os.path.join(MODEL_DIR, f))]
        if missing:
            return False
        def _p(n):
            with open(os.path.join(MODEL_DIR, n), "rb") as f:
                return pickle.load(f)
        self.iso          = _p("isolation_forest.pkl")
        self.rf           = _p("random_forest.pkl")
        self.scaler       = _p("scaler.pkl")
        self.classes      = _p("classes.pkl")
        self.feature_cols = _p("feature_cols.pkl")
        self._loaded      = True
        return True

    @property
    def ready(self) -> bool:
        return self._loaded

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        X : aligned feature DataFrame (output of feature_extraction.extract)
        Returns DataFrame with columns:
          attack, confidence, is_anomaly, anomaly_score, rf_probas
        """
        X_sc        = self.scaler.transform(X)
        raw_scores  = self.iso.score_samples(X_sc)
        anom_score  = np.clip(-raw_scores, 0.0, 1.0)
        is_anomaly  = self.iso.predict(X_sc) == -1
        rf_pred     = self.rf.predict(X_sc)
        rf_proba    = self.rf.predict_proba(X_sc)
        attacks     = [self.classes[i] for i in rf_pred]
        confidences = rf_proba[np.arange(len(rf_pred)), rf_pred]
        probas      = [
            {self.classes[i]: round(float(p), 4) for i, p in enumerate(row)}
            for row in rf_proba
        ]
        return pd.DataFrame({
            "attack":        attacks,
            "confidence":    np.round(confidences, 4),
            "is_anomaly":    is_anomaly,
            "anomaly_score": np.round(anom_score, 4),
            "rf_probas":     probas,
        }, index=X.index)
