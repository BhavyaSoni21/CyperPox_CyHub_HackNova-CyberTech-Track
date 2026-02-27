"""
CyHub — Model Training Script

Trains an Isolation Forest model on normal (benign) HTTP request data.
The model learns baseline traffic patterns and can then detect anomalous
requests as statistical outliers.

Usage:
    python src/train_model.py

Outputs:
    models/isolation_forest.pkl — serialized model + scaler pipeline
"""

from __future__ import annotations

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_engineering import extract_features_batch, FEATURE_COLUMNS


def load_training_data(path: str = "data/normal_traffic.csv") -> pd.DataFrame:
    """Load benign HTTP request samples from CSV.
    
    Expected CSV format: single column 'request' containing raw HTTP request strings.
    """
    if not os.path.exists(path):
        print(f"[ERROR] Training data not found at: {path}")
        print("        Please create data/normal_traffic.csv with benign request samples.")
        sys.exit(1)
    
    df = pd.read_csv(path)
    if "request" not in df.columns:
        print("[ERROR] CSV must have a 'request' column containing raw HTTP request strings.")
        sys.exit(1)
    
    print(f"[INFO] Loaded {len(df)} training samples from {path}")
    return df


def train_model(
    data_path: str = "data/normal_traffic.csv",
    model_path: str = "models/isolation_forest.pkl",
    contamination: float = 0.05,
    random_state: int = 42,
) -> None:
    """Train the Isolation Forest model and save to disk.
    
    Pipeline:
        1. Load normal traffic CSV
        2. Extract feature vectors
        3. Scale features with StandardScaler
        4. Fit Isolation Forest on scaled features
        5. Serialize model + scaler to .pkl
    """
    df = load_training_data(data_path)
    requests = df["request"].tolist()
    
    print("[INFO] Extracting features...")
    features_df = extract_features_batch(requests)
    X = features_df[FEATURE_COLUMNS].values
    print(f"[INFO] Feature matrix shape: {X.shape}")
    
    print("[INFO] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"[INFO] Training Isolation Forest (contamination={contamination})...")
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        max_samples="auto",
        n_jobs=-1,
    )
    model.fit(X_scaled)
    
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    pipeline = {
        "model": model,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "contamination": contamination,
        "n_training_samples": len(requests),
    }
    joblib.dump(pipeline, model_path)
    print(f"[SUCCESS] Model saved to {model_path}")
    
    scores = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)
    n_anomalies = (predictions == -1).sum()
    print(f"[STATS] Training anomalies detected: {n_anomalies}/{len(requests)} ({n_anomalies/len(requests)*100:.1f}%)")
    print(f"[STATS] Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"[STATS] Score mean: {scores.mean():.4f}, std: {scores.std():.4f}")


if __name__ == "__main__":
    train_model()
