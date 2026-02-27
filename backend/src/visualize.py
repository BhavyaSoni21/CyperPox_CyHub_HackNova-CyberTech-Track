"""
CyHub — Visualization Module

Renders anomaly score distributions and visual comparisons between
normal and suspicious requests.

Usage:
    python src/visualize.py
"""

from __future__ import annotations

import os
import sys
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_engineering import extract_features_batch, FEATURE_COLUMNS
from src.predict import Predictor


def plot_score_distribution(results: list, save_path: str = "plots/score_distribution.png"):
    """Plot the anomaly score distribution with normal vs suspicious coloring."""
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    scores_normal = [r["anomaly_score"] for r in results if r["prediction"] == "Normal"]
    scores_suspicious = [r["anomaly_score"] for r in results if r["prediction"] == "Suspicious"]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    if scores_normal:
        ax.hist(scores_normal, bins=30, alpha=0.6, color="#22c55e", label=f"Normal ({len(scores_normal)})", edgecolor="white")
    if scores_suspicious:
        ax.hist(scores_suspicious, bins=30, alpha=0.6, color="#ef4444", label=f"Suspicious ({len(scores_suspicious)})", edgecolor="white")
    
    ax.set_xlabel("Anomaly Score", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("CyHub — Anomaly Score Distribution", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"[INFO] Score distribution plot saved to {save_path}")


def plot_feature_heatmap(results: list, save_path: str = "plots/feature_heatmap.png"):
    """Plot a heatmap of feature values, grouped by prediction label."""
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    rows = []
    for r in results:
        row = dict(r["features"])
        row["prediction"] = r["prediction"]
        rows.append(row)
    
    df = pd.DataFrame(rows)
    
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    for idx, (label, color) in enumerate([("Normal", "Greens"), ("Suspicious", "Reds")]):
        subset = df[df["prediction"] == label][FEATURE_COLUMNS]
        if subset.empty:
            axes[idx].text(0.5, 0.5, f"No {label} requests", ha="center", va="center", fontsize=12)
            axes[idx].set_title(f"{label} Requests")
            continue
        
        normalized = (subset - subset.min()) / (subset.max() - subset.min() + 1e-10)
        
        sns.heatmap(
            normalized.head(20).T,
            ax=axes[idx],
            cmap=color,
            xticklabels=False,
            yticklabels=[col.replace("_", " ").title() for col in FEATURE_COLUMNS],
            cbar_kws={"shrink": 0.8},
        )
        axes[idx].set_title(f"{label} Requests (top 20)", fontsize=12, fontweight="bold")
    
    plt.suptitle("CyHub — Feature Heatmap", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"[INFO] Feature heatmap saved to {save_path}")


def plot_scatter_entropy_vs_score(results: list, save_path: str = "plots/entropy_vs_score.png"):
    """Scatter plot of Shannon entropy vs anomaly score."""
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    for label, color, marker in [("Normal", "#22c55e", "o"), ("Suspicious", "#ef4444", "x")]:
        subset = [r for r in results if r["prediction"] == label]
        if not subset:
            continue
        entropies = [r["features"]["shannon_entropy"] for r in subset]
        scores = [r["anomaly_score"] for r in subset]
        ax.scatter(entropies, scores, c=color, label=label, alpha=0.6, marker=marker, s=50)
    
    ax.set_xlabel("Shannon Entropy", fontsize=12)
    ax.set_ylabel("Anomaly Score", fontsize=12)
    ax.set_title("CyHub — Entropy vs Anomaly Score", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"[INFO] Entropy vs score plot saved to {save_path}")


def main():
    """Generate all visualizations from the test traffic data."""
    predictor = Predictor()
    
    test_path = "data/test_traffic.csv"
    if not os.path.exists(test_path):
        print(f"[ERROR] Test data not found at: {test_path}")
        sys.exit(1)
    
    df = pd.read_csv(test_path)
    requests = df["request"].tolist()
    
    print(f"[INFO] Scoring {len(requests)} test requests...")
    results = predictor.predict_batch(requests)
    
    plot_score_distribution(results)
    plot_feature_heatmap(results)
    plot_scatter_entropy_vs_score(results)
    
    print("\n[DONE] All plots generated in plots/ directory.")


if __name__ == "__main__":
    main()
