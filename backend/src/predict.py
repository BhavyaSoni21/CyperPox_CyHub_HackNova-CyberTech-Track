"""
CyHub — Prediction Module

Loads the trained Isolation Forest model and scores new HTTP requests.
Provides both single-request and batch prediction capabilities.

Usage (CLI):
    python src/predict.py --input data/test_traffic.csv

Usage (Python):
    from src.predict import Predictor
    predictor = Predictor()
    result = predictor.predict("GET /api/users?id=1 HTTP/1.1")
"""

from __future__ import annotations

import os
import sys
import argparse
import joblib
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_engineering import extract_features, extract_features_batch, FEATURE_COLUMNS


class Predictor:
    """Wrapper around the trained Isolation Forest pipeline."""

    def __init__(self, model_path: str = "models/isolation_forest.pkl"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                "Run 'python src/train_model.py' first to train the model."
            )
        
        pipeline = joblib.load(model_path)
        self.model = pipeline["model"]
        self.scaler = pipeline["scaler"]
        self.feature_columns = pipeline["feature_columns"]
        self.contamination = pipeline.get("contamination", 0.05)
        self.n_training_samples = pipeline.get("n_training_samples", 0)

    def predict(self, raw_request: str) -> Dict:
        """Score a single HTTP request.
        
        Returns:
            {
                "raw_request": str,
                "anomaly_score": float,
                "prediction": "Normal" | "Suspicious",
                "features": { ... }
            }
        """
        features = extract_features(raw_request)
        feature_values = np.array([[features[col] for col in self.feature_columns]])
        
        scaled = self.scaler.transform(feature_values)
        score = float(self.model.decision_function(scaled)[0])
        label = int(self.model.predict(scaled)[0])
        
        return {
            "raw_request": raw_request,
            "anomaly_score": score,
            "prediction": "Normal" if label == 1 else "Suspicious",
            "features": features,
        }

    def predict_batch(self, requests: List[str]) -> List[Dict]:
        """Score a batch of HTTP requests.
        
        Returns a list of prediction dicts (same format as predict()).
        """
        if not requests:
            return []
        
        features_df = extract_features_batch(requests)
        X = features_df[self.feature_columns].values
        
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        labels = self.model.predict(X_scaled)
        
        results = []
        for i, req in enumerate(requests):
            features = {col: float(features_df.iloc[i][col]) for col in self.feature_columns}
            results.append({
                "raw_request": req,
                "anomaly_score": float(scores[i]),
                "prediction": "Normal" if labels[i] == 1 else "Suspicious",
                "features": features,
            })
        
        return results


def main():
    parser = argparse.ArgumentParser(description="CyHub — Predict anomalies in HTTP requests")
    parser.add_argument("--input", type=str, default="data/test_traffic.csv",
                        help="Path to CSV file with 'request' column")
    parser.add_argument("--model", type=str, default="models/isolation_forest.pkl",
                        help="Path to trained model file")
    args = parser.parse_args()

    predictor = Predictor(args.model)
    
    if not os.path.exists(args.input):
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)
    
    df = pd.read_csv(args.input)
    if "request" not in df.columns:
        print("[ERROR] CSV must have a 'request' column.")
        sys.exit(1)
    
    requests = df["request"].tolist()
    print(f"[INFO] Scoring {len(requests)} requests...")
    
    results = predictor.predict_batch(requests)
    
    print(f"\n{'='*80}")
    print(f"{'Request':<50} {'Score':>10} {'Label':>12}")
    print(f"{'='*80}")
    for r in results:
        req_display = r["raw_request"][:47] + "..." if len(r["raw_request"]) > 50 else r["raw_request"]
        print(f"{req_display:<50} {r['anomaly_score']:>10.4f} {r['prediction']:>12}")
    
    n_suspicious = sum(1 for r in results if r["prediction"] == "Suspicious")
    print(f"\n[SUMMARY] {n_suspicious}/{len(results)} requests flagged as suspicious "
          f"({n_suspicious/len(results)*100:.1f}%)")


if __name__ == "__main__":
    main()
