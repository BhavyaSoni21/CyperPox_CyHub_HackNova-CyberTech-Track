from __future__ import annotations

import os
import io
import json
import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, quote_plus, urlunparse

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.requests import Request

load_dotenv()

from src.multi_predict import MultiModelPredictor, close_shared_client
from src.domain_intelligence import DomainIntelligence
from src.model4_features import extract_model4_features
from src import threat_engine
from src.decision_controller import (
    scan_payload,
    compute_bot_confidence,
    RiskMemory,
)

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
domain_intelligence: Optional[DomainIntelligence] = None

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

# ── In-memory behavioral bot detection ──────────────────────────────────────
REQUEST_WINDOW = 20  # sliding window: most-recent N requests per IP
request_history: defaultdict = defaultdict(lambda: deque(maxlen=REQUEST_WINDOW))
bot_alerts: dict = {}  # ip → probability (0.0–1.0); set by background task

# ── Risk Memory (IP/domain reputation tracking) ──────────────────────────────
risk_memory = RiskMemory()

# ── Feedback Store (tracks verdict corrections for threshold tuning) ─────────
feedback_store: List[dict] = []

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


# ── Behavioral bot detection helpers ────────────────────────────────────────

def log_request(ip: str, endpoint: str, method: str, user_agent: str) -> None:
    """Append request metadata to the IP's sliding-window history."""
    request_history[ip].append({
        "timestamp": time.time(),
        "endpoint": endpoint,
        "method": method,
        "user_agent": user_agent,
    })


def _compute_bot_probability(history: deque) -> float:
    """Heuristic behavioral bot score derived from request history.

    Returns a value in [0.0, 1.0].  Requires ≥10 samples to produce a
    meaningful score; returns 0.0 for shorter histories.
    """
    if len(history) < 10:
        return 0.0

    timestamps = [r["timestamp"] for r in history]
    endpoints = [r["endpoint"] for r in history]
    intervals = np.diff(timestamps)

    duration = timestamps[-1] - timestamps[0] + 1e-9
    request_rate = len(history) / duration
    interval_variance = float(np.var(intervals)) if len(intervals) > 1 else 0.0
    unique_endpoints = len(set(endpoints))
    repetition_ratio = endpoints.count(endpoints[-1]) / len(endpoints)

    score = 0.0
    if request_rate > 2.0:           # > 2 requests/second
        score += 0.35
    if interval_variance < 0.05:     # robot-regular cadence
        score += 0.30
    if unique_endpoints == 1:        # hammering a single endpoint
        score += 0.20
    if repetition_ratio > 0.8:       # >80 % of hits on same endpoint
        score += 0.15

    return min(1.0, score)


async def analyze_bot_behavior(ip: str) -> None:
    """Background task: compute behavioral score and update bot_alerts."""
    history = request_history[ip]
    probability = _compute_bot_probability(history)

    if probability > 0.5:
        bot_alerts[ip] = probability
        print(f"[BOT] Behavioral alert — IP={ip} score={probability:.2f}")
    elif ip in bot_alerts and probability < 0.2:
        # Clear stale alert once behavior normalises
        del bot_alerts[ip]


async def _periodic_cleanup() -> None:
    """Background loop: remove stale IPs from request_history every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        cutoff = time.time() - 600  # inactive for 10+ min
        for ip in list(request_history.keys()):
            hist = request_history[ip]
            if not hist or hist[-1]["timestamp"] < cutoff:
                del request_history[ip]
                bot_alerts.pop(ip, None)


@app.on_event("startup")
async def startup():
    global predictor, mongo_collection, domain_intelligence
    # Verify MongoDB is reachable; disable it if not so every endpoint falls
    # back to in-memory storage without raising uncaught exceptions.
    if mongo_collection is not None:
        try:
            await mongo_client.admin.command("ping")
            print("[INFO] MongoDB ping OK")
        except Exception as e:
            print(f"[WARN] MongoDB unreachable ({e}) — using in-memory storage")
            mongo_collection = None

    # Initialize Multi-Model Predictor (requires base IsolationForest model)
    model_path = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
    try:
        predictor = MultiModelPredictor(base_model_path=model_path)
        print(f"[INFO] Multi-model pipeline loaded (base: {model_path})")
    except Exception as exc:
        print(f"[WARN] Model pipeline failed to load: {exc}")
        print("[WARN] /predict endpoints will return 503 until models are available")

    # Initialize Domain Intelligence Layer (works with or without MongoDB)
    try:
        di_db = None
        if mongo_client is not None:
            di_db = mongo_client[os.getenv("MONGODB_DB", "cyhub")]
        domain_intelligence = DomainIntelligence(di_db)
        print(f"[INFO] Domain Intelligence Layer initialized (MongoDB: {'yes' if di_db is not None else 'no — in-memory only'})")

        # Optionally load blocklists on startup (requires MongoDB)
        load_blocklists_on_startup = os.getenv("LOAD_BLOCKLISTS_ON_STARTUP", "false").lower() == "true"
        if load_blocklists_on_startup and di_db is not None:
            print("[INFO] Loading public blocklists on startup...")
            asyncio.create_task(domain_intelligence.load_blocklists_from_sources())
    except Exception as e:
        print(f"[WARN] Domain Intelligence Layer failed to initialize: {e}")
        # Still create a minimal instance so /analyze doesn't 503
        domain_intelligence = DomainIntelligence(None)

    # Start background cleanup for request history
    asyncio.create_task(_periodic_cleanup())
    print("[INFO] Behavioral bot detection enabled (in-memory history)")


@app.on_event("shutdown")
async def shutdown():
    """Clean up shared resources."""
    await close_shared_client()
    if mongo_client is not None:
        mongo_client.close()


@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    """Root endpoint - API information and available routes."""
    return {
        "service": "CyHub API",
        "description": "AI-Driven Web Anomaly Detection System",
        "version": "1.0.0",
        "status": "online",
        "endpoints": {
            "health": "/health",
            "stats": "/stats",
            "analyze": "/analyze (POST) - Unified threat analysis",
            "predict": "/predict (POST) - Single request prediction",
            "batch": "/predict/batch (POST) - CSV batch analysis",
            "url_analysis": "/predict-url (POST) - URL-specific analysis",
            "bot_analysis": "/bot-analysis (POST) - Bot detection from CSV",
            "feedback": "/feedback (POST) - Submit analyst feedback",
            "feedback_stats": "/feedback/stats (GET) - Feedback statistics",
            "logs": "/logs (GET) - Recent analysis logs",
            "docs": "/docs - Interactive API documentation"
        },
        "documentation": "/docs"
    }


class PredictRequest(BaseModel):
    raw_request: str = Field(..., min_length=1, description="Raw HTTP request string to analyze")
    network_flow_features: Optional[List[float]] = Field(
        default=None,
        min_length=14,
        max_length=14,
        description="Optional 14-element Model 2 network flow feature vector",
    )


class AnalyzeRequest(BaseModel):
    url: str = Field(default="", description="URL to analyze (optional if raw_request provided)")
    raw_request: str = Field(default="", description="Raw HTTP request string (optional if url provided)")


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


class BatchResultItem(BaseModel):
    """Individual result in batch analysis."""
    raw_request: str
    anomaly_score: float
    is_anomaly: bool
    threat_type: str = "Normal"


class BatchSummaryResponse(BaseModel):
    """Batch analysis summary with contamination rate."""
    total_requests: int
    normal: int
    sql_injection: int
    xss: int
    path_traversal: int
    unknown_attack: int
    contamination_rate: float  # percentage (0-100)
    results: List[BatchResultItem]


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


class PredictURLRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL to analyze")
    raw_request: str = Field(default="", description="Optional raw HTTP request for feature extraction")


class FeedbackRequest(BaseModel):
    request_id: str = Field(..., description="Log entry ID of the analyzed request")
    verdict_correct: bool = Field(..., description="Was the system verdict correct?")
    feedback_type: str = Field(
        default="correct",
        description="'correct', 'false_positive', or 'false_negative'",
    )
    notes: str = Field(default="", description="Optional analyst notes")


class DomainIntelligenceResponse(BaseModel):
    url: str
    domain: Optional[str] = None
    passes_domain_filter: bool
    classification: str
    blocked_reason: Optional[str] = None
    threat_flags: dict
    model4_features: Optional[List[float]] = None
    from_cache: bool = False


# ────────────────────────────────────────────────────────────────────────────
# Signal Fusion Report Schemas (imported from threat_engine)
# ────────────────────────────────────────────────────────────────────────────

from src.threat_engine import (
    ThreatScores,
    ModelDetails,
    ComprehensiveThreatReport,
)


class PredictURLResponse(BaseModel):
    url: str
    domain: Optional[str] = None
    domain_classification: str
    passes_domain_filter: bool
    blocked_reason: Optional[str] = None
    model4_prediction: Optional[str] = None
    from_cache: bool = False
    # If domain passes filter, also include full anomaly detection results
    anomaly_score: Optional[float] = None
    prediction: Optional[str] = None
    threat_type: Optional[str] = None
    features: Optional[FeatureVector] = None


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
    try:
        if predictor is None:
            raise HTTPException(
                status_code=503,
                detail="Model not loaded. Train the model first: python src/train_model.py"
            )

        # Note: predict() is now async (uses asyncio.gather for parallel models)
        result = await predictor.predict(body.raw_request, body.network_flow_features)
        await save_log(result["raw_request"], result["anomaly_score"], result["prediction"])

        return PredictResponse(
            raw_request=result["raw_request"],
            anomaly_score=result["anomaly_score"],
            prediction=result["prediction"],
            threat_type=result.get("threat_type", "Normal"),
            features=FeatureVector(**result["features"]),
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] /predict endpoint failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)[:200]}"
        )


@app.post("/predict/batch", response_model=BatchSummaryResponse)
async def predict_batch(file: UploadFile = File(...)):
    """Batch score HTTP requests from an uploaded CSV file.

    Pipeline:
      1. Extract features from all requests
      2. Send features to HuggingFace Model 1 (Isolation Forest) in ONE batch call
      3. Apply threshold to classify anomalies (score < -0.05 = anomaly)
      4. Run rule detection ONLY on anomalous requests
      5. Calculate contamination rate
      6. Return batch summary

    CSV must have a 'request' column.
    """
    try:
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

        # Run batch analysis with threshold-based detection
        batch_result = await predictor.predict_batch_with_threshold(requests)

        # Log results
        for item in batch_result["results"]:
            await save_log(
                item["raw_request"],
                item["anomaly_score"],
                "Suspicious" if item["is_anomaly"] else "Normal"
            )

        return BatchSummaryResponse(
            total_requests=batch_result["total_requests"],
            normal=batch_result["normal"],
            sql_injection=batch_result["sql_injection"],
            xss=batch_result["xss"],
            path_traversal=batch_result["path_traversal"],
            unknown_attack=batch_result["unknown_attack"],
            contamination_rate=batch_result["contamination_rate"],
            results=[
                BatchResultItem(
                    raw_request=r["raw_request"],
                    anomaly_score=r["anomaly_score"],
                    is_anomaly=r["is_anomaly"],
                    threat_type=r["threat_type"],
                )
                for r in batch_result["results"]
            ],
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] /predict/batch endpoint failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Batch prediction failed: {str(e)[:200]}"
        )



@app.get("/logs", response_model=List[LogEntry])
async def get_logs(limit: int = 100):
    """Retrieve scored request log history."""
    try:
        # Try MongoDB if available
        if mongo_collection is not None:
            try:
                cursor = mongo_collection.find().sort("timestamp", -1).limit(limit)
                rows = await cursor.to_list(length=limit)
                log_entries = []
                for row in rows:
                    try:
                        log_entries.append(LogEntry(
                            id=str(row.get("_id", "")),
                            timestamp=row.get("timestamp", ""),
                            raw_request=row.get("raw_request", ""),
                            anomaly_score=float(row.get("anomaly_score", 0.0)),
                            prediction=row.get("prediction", "Unknown"),
                        ))
                    except Exception as item_error:
                        print(f"[WARN] Could not parse log entry: {item_error}")
                        continue

                if log_entries:
                    print(f"[INFO] Retrieved {len(log_entries)} logs from MongoDB")
                    return log_entries
            except Exception as mongo_error:
                print(f"[WARN] MongoDB query failed (using in-memory): {mongo_error}")

        # Fallback to in-memory logs
        sorted_logs = sorted(request_logs, key=lambda x: x.get("timestamp", ""), reverse=True)
        log_entries = []
        for log in sorted_logs[:limit]:
            try:
                log_entries.append(LogEntry(**log))
            except Exception as parse_error:
                print(f"[WARN] Could not parse in-memory log: {parse_error}")
                continue
        return log_entries
    except Exception as e:
        print(f"[ERROR] /logs endpoint error: {e}")
        import traceback
        traceback.print_exc()
        return []


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
        # Default to in-memory logs
        total = len(request_logs)
        normal = sum(1 for log in request_logs if log.get("prediction") == "Normal")
        suspicious = total - normal

        # Try MongoDB if available
        if mongo_collection is not None:
            try:
                # Use find().count() as a more reliable approach
                total = await mongo_collection.count_documents({})
                normal = await mongo_collection.count_documents({"prediction": "Normal"})
                suspicious = total - normal
                print(f"[INFO] Stats from MongoDB: total={total}, normal={normal}")
            except Exception as mongo_error:
                print(f"[WARN] MongoDB stats query failed (using in-memory): {mongo_error}")
                # Fall back to in-memory logs - already computed above

        return StatsResponse(
            total_scanned=total,
            normal_count=normal,
            suspicious_count=suspicious,
            model_status="Ready" if predictor is not None else "Not Loaded",
        )
    except Exception as e:
        print(f"[ERROR] /stats endpoint error: {e}")
        import traceback
        traceback.print_exc()
        # Ultimate fallback: return zeros
        return StatsResponse(
            total_scanned=0,
            normal_count=0,
            suspicious_count=0,
            model_status="Error" if predictor is None else "Ready",
        )


@app.post("/predict-url", response_model=ComprehensiveThreatReport)
async def predict_url(body: PredictURLRequest):
    """Score a URL with all models running in parallel (signal fusion architecture).

    NEW ARCHITECTURE (Parallel/Signal Fusion):
      1. Domain Intelligence pre-filtering (whitelist/blocklist/DNS/heuristics)
      2. Extract Model 4 features
      3. RUN ALL MODELS IN PARALLEL:
         - Model 4 (URL classification) in parallel with
         - Models 1-3 (Anomaly detection - 2& 3 always parallel, 1 only for API)
      4. Signal fusion decision engine combines all signals (equal 25% weight)
      5. Generate comprehensive threat report

    Key Changes:
      - ✅ No gatekeeper logic (Models 1-3 don't wait for Model 4)
      - ✅ Model 1 only runs on API requests (not browser traffic)
      - ✅ All models return results in comprehensive report
      - ✅ Threat score = weighted avg of all signals (0.0-1.0)

    Args:
        url: URL to analyze (required)
        raw_request: Full HTTP request (optional, for anomaly detection)

    Returns:
        ComprehensiveThreatReport: Unified threat assessment with all model perspectives
    """
    try:
        if domain_intelligence is None:
            raise HTTPException(
                status_code=503,
                detail="Domain Intelligence Layer not initialized. Configure MongoDB."
            )

        # ── Step 1: Domain Intelligence Pre-filtering ──────────────────────────────
        try:
            domain_check = await domain_intelligence.check_domain(body.url, body.raw_request)
        except Exception as e:
            print(f"[ERROR] Domain check failed: {e}")
            # Continue anyway with generic domain check
            domain_check = {
                "passes_domain_filter": True,
                "domain": body.url.split("//")[-1].split("/")[0],
                "threat_flags": {}
            }

        # If domain fails pre-filter (malware, blocklisted, DNS fails), return early report
        if not domain_check.get("passes_domain_filter"):
            return await threat_engine.generate_report(
                url=body.url,
                domain_check=domain_check,
                model4_result={"classification": "blocked"},
                anomaly_result=None,
                is_api_request=False
            )

        # ── Step 2: Extract Model 4 features ───────────────────────────────────────
        domain = domain_check.get("domain")
        threat_flags = domain_check.get("threat_flags", {})

        try:
            model4_features = extract_model4_features(
                domain=domain,
                url=body.url,
                threat_flags=threat_flags
            )
        except Exception as e:
            print(f"[ERROR] Model 4 feature extraction failed: {e}")
            model4_features = {}

        # ── Step 3: RUN ALL MODELS IN PARALLEL ─────────────────────────────────────
        # Model 4 runs in parallel with anomaly detection (Models 1-3).
        # IMPORTANT: asyncio.gather requires awaitables — passing None raises
        # TypeError which leaks into the event loop callback layer (Python 3.10
        # NameError bug) and can cause subsequent requests to return 500.
        # Run gather only when both coroutines are available; otherwise run M4
        # alone and leave anomaly_result as None.
        model4_result = None
        anomaly_result = None
        try:
            if body.raw_request and predictor:
                model4_result, anomaly_result = await asyncio.gather(
                    domain_intelligence.call_model4(model4_features),
                    predictor.predict(body.raw_request),
                    return_exceptions=True,
                )
            else:
                model4_result = await domain_intelligence.call_model4(model4_features)

            # Handle exceptions returned by gather
            if isinstance(model4_result, Exception):
                print(f"[ERROR] Model 4 prediction failed: {model4_result}")
                model4_result = None
            if isinstance(anomaly_result, Exception):
                print(f"[ERROR] Anomaly prediction failed: {anomaly_result}")
                anomaly_result = None

            if model4_result is None:
                model4_result = {"classification": "unknown"}

        except Exception as e:
            print(f"[ERROR] Parallel model execution failed: {e}")
            import traceback
            traceback.print_exc()
            model4_result = {"classification": "unknown"}
            anomaly_result = None

        # ── Step 4: Detect request type for signal fusion ───────────────────────────
        is_api_request = False
        if anomaly_result and isinstance(anomaly_result, dict) and body.raw_request:
            is_api_request = anomaly_result.get("is_api_request", False)

        # ── Step 5: Generate comprehensive signal-fusion report ─────────────────────
        try:
            report = await threat_engine.generate_report(
                url=body.url,
                domain_check=domain_check,
                model4_result=model4_result,
                anomaly_result=anomaly_result,
                is_api_request=is_api_request
            )
        except Exception as e:
            print(f"[ERROR] Report generation failed: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: create minimal report
            from src.threat_engine import ComprehensiveThreatReport, ThreatScores, ModelDetails
            report = ComprehensiveThreatReport(
                url=body.url,
                domain=domain_check.get("domain"),
                threat_scores=ThreatScores(
                    url_threat_score=0.5,
                    traffic_anomaly_score=0.0,
                    bot_activity_score=0.0,
                    payload_threat_score=0.0,
                    domain_intel_score=0.3,
                    is_api_request=is_api_request,
                    overall_threat_score=0.5
                ),
                model_details=ModelDetails(
                    model4_classification="unknown",
                    model4_confidence=0.5,
                    traffic_anomaly_detected=False,
                    bot_activity_detected=False,
                    payload_attack_detected=False,
                    payload_threat_type=None,
                    is_api_request=is_api_request
                ),
                overall_verdict="Suspicious",
                recommendation="Unable to fully analyze. Check system logs.",
                passes_domain_filter=domain_check.get("passes_domain_filter", True),
                blocked_reason=None,
                from_cache=False,
                request_type="API" if is_api_request else "Browser"
            )

        # ── Step 6: Cache Model 4 result ────────────────────────────────────────────
        try:
            if model4_result and isinstance(model4_result, dict):
                await domain_intelligence.cache_classification(
                    domain,
                    model4_result.get("classification", "unknown"),
                    model4_result.get("raw_prediction_encoded", -1)
                )
        except Exception as e:
            print(f"[WARN] Model 4 cache failed: {e}")

        # ── Step 7: Log final decision ──────────────────────────────────────────────
        try:
            await save_log(
                body.raw_request or "",
                report.threat_scores.overall_threat_score,
                "Normal" if report.overall_verdict in ("Safe", "Caution") else "Suspicious",
            )
        except Exception as e:
            print(f"[WARN] Logging failed: {e}")

        return report

    except HTTPException:
        # Re-raise HTTP exceptions (like 503)
        raise
    except Exception as e:
        print(f"[ERROR] /predict-url endpoint failed unexpectedly: {e}")
        import traceback
        traceback.print_exc()
        # Return generic error response instead of 500
        raise HTTPException(
            status_code=400,
            detail=f"URL analysis failed: {str(e)[:200]}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Unified /analyze endpoint — replaces /predict + /predict-url
# ────────────────────────────────────────────────────────────────────────────

@app.post("/analyze", response_model=ComprehensiveThreatReport)
async def analyze(body: AnalyzeRequest, request: Request, background_tasks: BackgroundTasks):
    """Unified threat analysis endpoint.

    Accepts any combination of url + raw_request:
      - URL only → domain intel + Model 4 + synthetic GET for Models 2-3
      - raw_request only → extract URL from Host header, run all models
      - Both → full pipeline with all 5 signals

    Returns ComprehensiveThreatReport with per-model scores and 4-tier verdict.
    """
    try:
        if predictor is None and domain_intelligence is None:
            raise HTTPException(
                status_code=503,
                detail="Analysis pipeline not initialized. Check server logs."
            )

        url = body.url.strip()
        raw_request = body.raw_request.strip()

        # ── Log request for behavioral bot analysis ──────────────────────────
        client_ip = request.client.host if request.client else "unknown"
        log_request(
            ip=client_ip,
            endpoint=request.url.path,
            method=request.method,
            user_agent=request.headers.get("user-agent", ""),
        )
        background_tasks.add_task(analyze_bot_behavior, client_ip)

        # ── Step 1: Input normalization ─────────────────────────────────────
        if not url and not raw_request:
            raise HTTPException(
                status_code=400,
                detail="Provide at least one of 'url' or 'raw_request'."
            )

        # If only raw_request, try to extract URL from Host header
        if not url and raw_request:
            for line in raw_request.split("\n"):
                line_stripped = line.strip()
                if line_stripped.lower().startswith("host:"):
                    host = line_stripped.split(":", 1)[1].strip()
                    url = f"https://{host}"
                    break

        # If only URL, generate a synthetic GET request for Models 2-3
        if url and not raw_request:
            try:
                parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
                host = parsed.netloc or parsed.path.split("/")[0]
                path = parsed.path or "/"
                raw_request = f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: Mozilla/5.0"
            except Exception:
                raw_request = f"GET / HTTP/1.1\nHost: {url}\nUser-Agent: Mozilla/5.0"

        has_url = bool(url)
        is_api = MultiModelPredictor._is_api_request(raw_request) if raw_request else False

        # ── Pre-gate payload scan ────────────────────────────────────────────
        # Run BEFORE any early exits so a malicious payload on a 'safe' domain
        # is never silently allowed through (Fix #2).
        payload_findings: List[str] = []
        if raw_request:
            _, payload_findings = scan_payload(raw_request)
            if payload_findings:
                print(f"[PAYLOAD SCAN] Dangerous payload detected: {payload_findings}")

        # ── Step 2: Domain Intelligence (parallel with feature extraction) ──
        domain_check = None
        if has_url and domain_intelligence is not None:
            try:
                domain_check = await domain_intelligence.check_domain(url, raw_request)
            except Exception as e:
                print(f"[WARN] Domain check failed: {e}")

        # Provide a default domain_check if none
        if domain_check is None:
            domain_check = {
                "url": url,
                "domain": url.split("//")[-1].split("/")[0] if url else None,
                "passes_domain_filter": True,
                "classification": "unknown",
                "blocked_reason": None,
                "threat_flags": {},
                "from_cache": False,
            }

        # Early exit if domain is blocked
        if not domain_check.get("passes_domain_filter", True):
            return await threat_engine.generate_report(
                url=url or "unknown",
                domain_check=domain_check,
                model4_result={"classification": "blocked"},
                anomaly_result=None,
                is_api_request=is_api,
                payload_findings=payload_findings or None,
            )

        # ── Step 3: Extract Model 4 features + run all models in parallel ───
        domain = domain_check.get("domain", "")
        threat_flags = domain_check.get("threat_flags", {})

        # Model 4 features
        model4_features = None
        if has_url:
            try:
                model4_features = extract_model4_features(
                    domain=domain, url=url, threat_flags=threat_flags
                )
            except Exception as e:
                print(f"[WARN] Model 4 feature extraction failed: {e}")

        # Build parallel tasks
        async def run_model4():
            if model4_features is not None and domain_intelligence is not None:
                return await domain_intelligence.call_model4(model4_features)
            return {"classification": "unknown", "confidence": 0.0}

        async def run_anomaly():
            if raw_request and predictor is not None:
                return await predictor.predict(raw_request)
            return None

        model4_result, anomaly_result = await asyncio.gather(
            run_model4(), run_anomaly(), return_exceptions=True
        )

        if isinstance(model4_result, Exception):
            print(f"[WARN] Model 4 failed: {model4_result}")
            model4_result = {"classification": "unknown", "confidence": 0.0}
        if isinstance(anomaly_result, Exception):
            print(f"[WARN] Anomaly models failed: {anomaly_result}")
            anomaly_result = None

        # Override is_api from anomaly result if available
        if anomaly_result and isinstance(anomaly_result, dict):
            is_api = anomaly_result.get("is_api_request", is_api)

        # ── Multi-factor bot confidence (Fix #4) ─────────────────────────────
        # Replace naive OR logic with weighted combination of:
        #   - Model 2 ML score (0.6 weight)
        #   - Behavioral heuristic + IP risk reputation (0.4 weight)
        # Prevents fast-but-legitimate users from being flagged as bots.
        behavioral_score = bot_alerts.get(client_ip, 0.0)
        ip_rep = risk_memory.get_ip_reputation(client_ip)
        combined_behavior = min(1.0, behavioral_score + ip_rep * 0.3)

        m2_score = 0.0
        if anomaly_result and isinstance(anomaly_result, dict):
            m2_score = float(anomaly_result.get("bot_confidence") or 0.0)

        combined_bot_confidence = compute_bot_confidence(m2_score, combined_behavior)
        BOT_INJECT_THRESHOLD = 0.45

        if combined_bot_confidence >= BOT_INJECT_THRESHOLD:
            if anomaly_result is None:
                anomaly_result = {
                    "bot_detected": True,
                    "bot_confidence": combined_bot_confidence,
                    "traffic_anomaly": False,
                    "payload_attack": False,
                    "model1_ran": False,
                    "model2_ran": False,
                    "model3_ran": False,
                    "is_api_request": is_api,
                    "anomaly_score": 0.0,
                    "prediction": "Suspicious",
                    "threat_type": "Bot Activity",
                    "features": {},
                }
            elif isinstance(anomaly_result, dict):
                anomaly_result["bot_detected"] = True
                anomaly_result["bot_confidence"] = combined_bot_confidence
            print(
                f"[BOT] Multi-factor — IP={client_ip} "
                f"m2={m2_score:.2f} behavior={combined_behavior:.2f} "
                f"combined={combined_bot_confidence:.2f}"
            )

        # ── Step 4: Signal fusion → comprehensive report ────────────────────
        report = await threat_engine.generate_report(
            url=url or "unknown",
            domain_check=domain_check,
            model4_result=model4_result,
            anomaly_result=anomaly_result,
            is_api_request=is_api,
            payload_findings=payload_findings or None,
        )

        # ── Step 5: Update risk memory with verdict ─────────────────────────
        domain_for_memory = domain_check.get("domain") if domain_check else None
        risk_memory.record_verdict(client_ip, domain_for_memory, report.overall_verdict)
        if payload_findings:
            for finding in payload_findings:
                risk_memory.record_attack_pattern(finding)

        # ── Step 6: Cache + log (non-blocking) ─────────────────────────────
        try:
            if has_url and domain_intelligence is not None and isinstance(model4_result, dict):
                await domain_intelligence.cache_classification(
                    domain,
                    model4_result.get("classification", "unknown"),
                    model4_result.get("raw_prediction_encoded", -1),
                )
        except Exception as e:
            print(f"[WARN] Cache failed: {e}")

        try:
            await save_log(
                raw_request[:500],
                report.threat_scores.overall_threat_score,
                "Normal" if report.overall_verdict in ("Safe", "Caution") else "Suspicious",
            )
        except Exception as e:
            print(f"[WARN] Log failed: {e}")

        return report

    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] /analyze endpoint failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)[:200]}"
        )


# ────────────────────────────────────────────────────────────────────────────
# /bot-analysis — Standalone Model 2 (bot/botnet detection) endpoint
# ────────────────────────────────────────────────────────────────────────────

from src.bot_feature_builder import generate_flow_features, BOT_FEATURE_COUNT


class BotFlowResult(BaseModel):
    ip: str
    prediction: int          # 0 = normal, 1 = bot
    probability: float       # Model 2 confidence (0.0-1.0)
    bot_type: str = "normal" # Type of bot detected


class BotAnalysisResponse(BaseModel):
    flows_analyzed: int
    bot_flows: int
    results: List[BotFlowResult]


@app.post("/bot-analysis", response_model=BotAnalysisResponse)
async def bot_analysis(file: UploadFile = File(...)):
    """Standalone bot/botnet detection using Model 2.

    Upload a CSV with columns: timestamp, ip, url
    Server groups by IP, engineers 14 flow features per session, and runs Model 2.

    This endpoint is completely independent of /analyze.
    """
    if predictor is None:
        raise HTTPException(status_code=503, detail="Model pipeline not loaded.")

    try:
        content = await file.read()
        text = content.decode("utf-8")
        df = pd.read_csv(io.StringIO(text))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    required_cols = {"timestamp", "ip", "url"}
    if not required_cols.issubset(df.columns):
        raise HTTPException(
            status_code=400,
            detail=f"CSV must contain columns: {required_cols}. Got: {list(df.columns)}"
        )

    try:
        ip_labels, features_batch = generate_flow_features(df)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature engineering failed: {e}")

    if len(features_batch) == 0:
        raise HTTPException(status_code=422, detail="No sessions could be extracted from the CSV.")

    raw_results = await predictor.predict_bot_flows(features_batch.tolist())

    flow_results = [
        BotFlowResult(ip=ip, **raw)
        for ip, raw in zip(ip_labels, raw_results)
    ]
    bot_count = sum(r.prediction for r in flow_results)

    return BotAnalysisResponse(
        flows_analyzed=len(flow_results),
        bot_flows=bot_count,
        results=flow_results,
    )


# ────────────────────────────────────────────────────────────────────────────
# /feedback — Analyst feedback loop for verdict correction tracking
# ────────────────────────────────────────────────────────────────────────────

@app.post("/feedback", status_code=200)
async def submit_feedback(body: FeedbackRequest):
    """Submit analyst feedback on a system verdict.

    Tracks false positives / false negatives so thresholds can be tuned
    over time.  Results are stored in the in-memory feedback_store and
    optionally persisted to MongoDB.

    feedback_type values:
      "correct"         — verdict was right
      "false_positive"  — system said Dangerous/Suspicious but request was benign
      "false_negative"  — system said Safe/Caution but request was actually malicious
    """
    entry = {
        "request_id": body.request_id,
        "verdict_correct": body.verdict_correct,
        "feedback_type": body.feedback_type,
        "notes": body.notes,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    feedback_store.append(entry)

    # Persist to MongoDB if available
    if mongo_collection is not None:
        try:
            fb_collection = mongo_collection.database["feedback"]
            await fb_collection.insert_one(entry.copy())
        except Exception as e:
            print(f"[WARN] Feedback MongoDB insert failed: {e}")

    print(f"[FEEDBACK] id={body.request_id} type={body.feedback_type} correct={body.verdict_correct}")
    return {
        "status": "recorded",
        "feedback_type": body.feedback_type,
        "total_feedback_entries": len(feedback_store),
    }


@app.get("/feedback/stats")
async def get_feedback_stats():
    """Return aggregate feedback statistics for threshold tuning."""
    total = len(feedback_store)
    if total == 0:
        return {"total": 0, "correct": 0, "false_positives": 0, "false_negatives": 0}

    correct = sum(1 for f in feedback_store if f.get("feedback_type") == "correct")
    fp = sum(1 for f in feedback_store if f.get("feedback_type") == "false_positive")
    fn = sum(1 for f in feedback_store if f.get("feedback_type") == "false_negative")

    return {
        "total": total,
        "correct": correct,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy_rate": round(correct / total, 4) if total else 0.0,
        "attack_patterns": risk_memory.get_attack_pattern_stats(),
    }
