"""
CyHub — FastAPI Application

High-performance async REST API for the anomaly detection system.

Endpoints:
    POST /predict        — Score a single HTTP request
    POST /predict/batch  — Batch score from uploaded CSV
    GET  /logs           — Retrieve flagged request log history
    GET  /health         — API health check

Run:
    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import os
import io
import csv
from datetime import datetime, timezone
from typing import List, Optional

import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

# ── Import predictor ──
from src.predict import Predictor
from src.feature_engineering import FEATURE_COLUMNS

# ── App setup ──
app = FastAPI(
    title="CyHub API",
    description="AI-Driven Web Anomaly Detection — powered by Isolation Forest",
    version="1.0.0",
)

# ── CORS ──
origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ──
predictor: Optional[Predictor] = None
request_logs: List[dict] = []  # In-memory fallback if Supabase isn't configured


# ── Supabase client (optional) ──
supabase_client = None
try:
    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_key = os.getenv("SUPABASE_KEY", "")
    if supabase_url and supabase_key and not supabase_url.startswith("https://your-"):
        from supabase import create_client
        supabase_client = create_client(supabase_url, supabase_key)
        print("[INFO] Supabase client initialized")
    else:
        print("[INFO] Supabase not configured — using in-memory log storage")
except Exception as e:
    print(f"[WARN] Supabase init failed: {e} — using in-memory log storage")


# ── Startup ──
@app.on_event("startup")
async def startup():
    global predictor
    model_path = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
    try:
        predictor = Predictor(model_path)
        print(f"[INFO] Model loaded from {model_path}")
    except FileNotFoundError:
        print(f"[WARN] Model not found at {model_path}. Train it first with: python src/train_model.py")
        print("[WARN] /predict endpoints will return 503 until model is available")


# ── Schemas ──
class PredictRequest(BaseModel):
    raw_request: str = Field(..., min_length=1, description="Raw HTTP request string to analyze")


class FeatureVector(BaseModel):
    request_length: float
    url_depth: float
    param_count: float
    special_char_count: float
    shannon_entropy: float
    sql_keyword_score: float
    script_tag_score: float


class PredictResponse(BaseModel):
    raw_request: str
    anomaly_score: float
    prediction: str
    features: FeatureVector


class LogEntry(BaseModel):
    id: str
    timestamp: str
    raw_request: str
    anomaly_score: float
    prediction: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str


# ── Helpers ──
def save_log(raw_request: str, anomaly_score: float, prediction: str):
    """Persist a scored request to Supabase or in-memory storage."""
    log_entry = {
        "id": str(len(request_logs) + 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_request": raw_request[:500],  # Truncate for storage
        "anomaly_score": anomaly_score,
        "prediction": prediction,
    }
    
    if supabase_client:
        try:
            supabase_client.table("request_logs").insert({
                "raw_request": log_entry["raw_request"],
                "anomaly_score": log_entry["anomaly_score"],
                "prediction": log_entry["prediction"],
            }).execute()
        except Exception as e:
            print(f"[WARN] Supabase insert failed: {e}")
            request_logs.append(log_entry)
    else:
        request_logs.append(log_entry)


# ── Endpoints ──
@app.post("/predict", response_model=PredictResponse)
async def predict_single(body: PredictRequest):
    """Score a single HTTP request for anomalies."""
    if predictor is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Train the model first: python src/train_model.py"
        )
    
    result = predictor.predict(body.raw_request)
    save_log(result["raw_request"], result["anomaly_score"], result["prediction"])
    
    return PredictResponse(
        raw_request=result["raw_request"],
        anomaly_score=result["anomaly_score"],
        prediction=result["prediction"],
        features=FeatureVector(**result["features"]),
    )


@app.post("/predict/batch", response_model=List[PredictResponse])
async def predict_batch(file: UploadFile = File(...)):
    """Batch score HTTP requests from an uploaded CSV file.
    
    CSV must have a 'request' column.
    """
    if predictor is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Train the model first: python src/train_model.py"
        )
    
    try:
        content = await file.read()
        text = content.decode("utf-8")
        df = pd.read_csv(io.StringIO(text))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")
    
    if "request" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must have a 'request' column")
    
    requests = df["request"].dropna().tolist()
    if not requests:
        raise HTTPException(status_code=400, detail="No valid requests found in CSV")
    
    results = predictor.predict_batch(requests)
    
    # Log all results
    for r in results:
        save_log(r["raw_request"], r["anomaly_score"], r["prediction"])
    
    return [
        PredictResponse(
            raw_request=r["raw_request"],
            anomaly_score=r["anomaly_score"],
            prediction=r["prediction"],
            features=FeatureVector(**r["features"]),
        )
        for r in results
    ]


@app.get("/logs", response_model=List[LogEntry])
async def get_logs(limit: int = 100):
    """Retrieve scored request log history."""
    if supabase_client:
        try:
            response = supabase_client.table("request_logs") \
                .select("*") \
                .order("timestamp", desc=True) \
                .limit(limit) \
                .execute()
            return [
                LogEntry(
                    id=str(row.get("id", "")),
                    timestamp=row.get("timestamp", ""),
                    raw_request=row.get("raw_request", ""),
                    anomaly_score=row.get("anomaly_score", 0.0),
                    prediction=row.get("prediction", "Unknown"),
                )
                for row in response.data
            ]
        except Exception as e:
            print(f"[WARN] Supabase query failed: {e}")
    
    # Fall back to in-memory logs
    sorted_logs = sorted(request_logs, key=lambda x: x["timestamp"], reverse=True)
    return [LogEntry(**log) for log in sorted_logs[:limit]]


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """API health check."""
    return HealthResponse(
        status="healthy",
        model_loaded=predictor is not None,
        version="1.0.0",
    )
