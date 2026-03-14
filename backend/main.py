from __future__ import annotations

import os
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, quote_plus, urlunparse

import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

from src.multi_predict import MultiModelPredictor

app = FastAPI(
    title="CyHub API",
    description="AI-Driven Web Anomaly Detection — powered by Isolation Forest",
    version="1.0.0",
)

origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

predictor: Optional[MultiModelPredictor] = None

# ── Persistent file-based fallback log storage ─────────────────────────────
LOGS_FILE = Path(os.getenv("LOGS_FILE", "data/request_logs.json"))

def _load_logs_from_disk() -> List[dict]:
    """Load existing logs from the JSON file if it exists."""
    if LOGS_FILE.exists():
        try:
            with LOGS_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Could not load logs file: {e}")
    return []

def _save_logs_to_disk(logs: List[dict]) -> None:
    """Write the full log list to disk atomically."""
    try:
        LOGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = LOGS_FILE.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
        tmp.replace(LOGS_FILE)
    except Exception as e:
        print(f"[WARN] Could not persist logs to disk: {e}")

request_logs: List[dict] = _load_logs_from_disk()

def _encode_mongo_uri(uri: str) -> str:
    """
    Re-encode username and password inside a MongoDB URI so that special
    characters (especially '@' in the password) do not break URI parsing.
    dotenv decodes %40 back to @, which causes pymongo InvalidURI errors
    because the resulting URI has two '@' separating userinfo from host.
    """
    try:
        parsed = urlparse(uri)
        if parsed.username and parsed.password:
            userinfo = f"{quote_plus(parsed.username)}:{quote_plus(parsed.password)}"
            # Rebuild netloc without re-encoding the host / port / options
            host_part = parsed.hostname
            if parsed.port:
                host_part = f"{host_part}:{parsed.port}"
            new_netloc = f"{userinfo}@{host_part}"
            rebuilt = urlunparse((
                parsed.scheme, new_netloc,
                parsed.path, parsed.params,
                parsed.query, parsed.fragment,
            ))
            return rebuilt
    except Exception:
        pass
    return uri

mongo_collection = None
mongo_client = None
try:
    raw_uri = os.getenv("MONGODB_URI", "")
    if raw_uri and not raw_uri.startswith("mongodb+srv://your-"):
        mongo_uri = _encode_mongo_uri(raw_uri)
        from motor.motor_asyncio import AsyncIOMotorClient
        mongo_client = AsyncIOMotorClient(mongo_uri)
        mongo_db = mongo_client[os.getenv("MONGODB_DB", "cyhub")]
        mongo_collection = mongo_db["request_logs"]
        print("[INFO] MongoDB client initialized")
    else:
        print("[INFO] MongoDB not configured — using in-memory log storage")
except Exception as e:
    print(f"[WARN] MongoDB init failed: {e} — using in-memory log storage")

@app.on_event("startup")
async def startup():
    global predictor, mongo_collection
    # Verify MongoDB is reachable; disable it if not so every endpoint falls
    # back to in-memory storage without raising uncaught exceptions.
    if mongo_collection is not None:
        try:
            await mongo_client.admin.command("ping")
            print("[INFO] MongoDB ping OK")
        except Exception as e:
            print(f"[WARN] MongoDB unreachable ({e}) — using in-memory storage")
            mongo_collection = None

    model_path = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
    try:
        predictor = MultiModelPredictor(base_model_path=model_path)
        print(f"[INFO] Multi-model pipeline loaded (base: {model_path})")
    except Exception as exc:
        print(f"[WARN] Model pipeline failed to load: {exc}")
        print("[WARN] /predict endpoints will return 503 until models are available")

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
    threat_type: str = "Normal"
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


class StatsResponse(BaseModel):
    total_scanned: int
    normal_count: int
    suspicious_count: int
    model_status: str


async def save_log(raw_request: str, anomaly_score: float, prediction: str):
    """Persist a scored request to MongoDB (primary) and disk JSON (fallback)."""
    log_entry = {
        "id": str(len(request_logs) + 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_request": raw_request[:500],
        "anomaly_score": anomaly_score,
        "prediction": prediction,
    }

    if mongo_collection is not None:
        try:
            await mongo_collection.insert_one({
                "timestamp": log_entry["timestamp"],
                "raw_request": log_entry["raw_request"],
                "anomaly_score": log_entry["anomaly_score"],
                "prediction": log_entry["prediction"],
            })
            # Also keep in-memory list in sync so /stats stays accurate
            request_logs.append(log_entry)
            return
        except Exception as e:
            print(f"[WARN] MongoDB insert failed: {e} — falling back to disk storage")

    # File-backed fallback — survives server restarts
    request_logs.append(log_entry)
    _save_logs_to_disk(request_logs)

@app.post("/predict", response_model=PredictResponse)
async def predict_single(body: PredictRequest):
    """Score a single HTTP request for anomalies."""
    if predictor is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Train the model first: python src/train_model.py"
        )
    
    result = predictor.predict(body.raw_request)
    await save_log(result["raw_request"], result["anomaly_score"], result["prediction"])
    
    return PredictResponse(
        raw_request=result["raw_request"],
        anomaly_score=result["anomaly_score"],
        prediction=result["prediction"],
        threat_type=result.get("threat_type", "Normal"),
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
    
    for r in results:
        await save_log(r["raw_request"], r["anomaly_score"], r["prediction"])
    
    return [
        PredictResponse(
            raw_request=r["raw_request"],
            anomaly_score=r["anomaly_score"],
            prediction=r["prediction"],
            threat_type=r.get("threat_type", "Normal"),
            features=FeatureVector(**r["features"]),
        )
        for r in results
    ]


@app.get("/logs", response_model=List[LogEntry])
async def get_logs(limit: int = 100):
    """Retrieve scored request log history."""
    if mongo_collection is not None:
        try:
            cursor = mongo_collection.find().sort("timestamp", -1).limit(limit)
            rows = await cursor.to_list(length=limit)
            return [
                LogEntry(
                    id=str(row.get("_id", "")),
                    timestamp=row.get("timestamp", ""),
                    raw_request=row.get("raw_request", ""),
                    anomaly_score=row.get("anomaly_score", 0.0),
                    prediction=row.get("prediction", "Unknown"),
                )
                for row in rows
            ]
        except Exception as e:
            print(f"[WARN] MongoDB query failed: {e}")

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


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get aggregate statistics from logs."""
    try:
        total = 0
        normal = 0
        suspicious = 0

        if mongo_collection is not None:
            try:
                total = await mongo_collection.count_documents({})
                normal = await mongo_collection.count_documents({"prediction": "Normal"})
                suspicious = total - normal
            except Exception as e:
                print(f"[WARN] MongoDB stats query failed: {e}")
                total = len(request_logs)
                normal = sum(1 for log in request_logs if log.get("prediction") == "Normal")
                suspicious = total - normal
        else:
            total = len(request_logs)
            normal = sum(1 for log in request_logs if log.get("prediction") == "Normal")
            suspicious = total - normal

        return StatsResponse(
            total_scanned=total,
            normal_count=normal,
            suspicious_count=suspicious,
            model_status="Ready" if predictor is not None else "Not Loaded",
        )
    except Exception as e:
        print(f"[ERROR] /stats failed unexpectedly: {e}")
        mem_total = len(request_logs)
        mem_normal = sum(1 for log in request_logs if log.get("prediction") == "Normal")
        return StatsResponse(
            total_scanned=mem_total,
            normal_count=mem_normal,
            suspicious_count=mem_total - mem_normal,
            model_status="Ready" if predictor is not None else "Not Loaded",
        )
