# CyHub Backend

FastAPI backend for the CyHub 5-signal fusion threat detection pipeline.

## Stack

- **Python 3.10+** + **FastAPI** + **uvicorn**
- **scikit-learn** — IsolationForest (M1 base), RandomForest (M3 traffic)
- **HuggingFace Spaces** — M1 payload, M2 bot, M4 URL classifier
- **httpx** — async HTTP client with connection pooling for HF calls
- **MongoDB** (optional) — domain intel persistence; falls back to in-memory cache
- **Deployed on Render**

## Development

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# Interactive docs: http://localhost:8000/docs
```

## Environment Variables

Create `backend/.env`:

```env
# HuggingFace model endpoints
HF_MODEL1_URL=https://...huggingface.co/...
HF_MODEL2_URL=https://...huggingface.co/...
HF_MODEL4_URL=https://...huggingface.co/...

# MongoDB (optional)
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/cyhub

# Load URLhaus / PhishTank / Spamhaus blocklists on startup
LOAD_BLOCKLISTS_ON_STARTUP=true
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/analyze` | **Unified** — accepts URL + raw HTTP request, returns `ComprehensiveThreatReport` |
| `POST` | `/predict` | Legacy — single raw request, returns `PredictResponse` |
| `POST` | `/predict/batch` | Legacy — CSV batch upload |
| `POST` | `/predict-url` | Legacy — URL-only analysis |
| `GET` | `/history` | Last 50 logged requests |
| `GET` | `/stats` | Aggregate detection statistics |
| `GET` | `/health` | Health check |

## Source Layout

```
backend/
├── main.py                      # FastAPI app, /analyze endpoint, startup hooks
├── requirements.txt
├── src/
│   ├── feature_engineering.py   # 7-feature vector (structural, complexity, semantic)
│   ├── multi_predict.py         # Model router — conditional M1/M2/M3, shared httpx client
│   ├── threat_engine.py         # 5-signal fusion, adaptive weights, verdict logic
│   ├── domain_intelligence.py   # M4 URL classifier, blocklist integration, MongoDB cache
│   └── model4_features.py       # M4 feature helpers
├── models/
│   └── isolation_forest.pkl     # Serialized base model
└── data/
    ├── normal_traffic.csv        # Benign training samples
    └── test_traffic.csv          # Evaluation samples
```

## Signal Fusion

Five signals are fused with context-adaptive weights:

| Signal | Source | API Weight | Browser Weight |
|---|---|---|---|
| M1 Payload | HuggingFace | 0.25 | 0.15 |
| M2 Bot | HuggingFace | 0.20 | 0.20 |
| M3 Traffic | Local RandomForest | 0.20 | 0.25 |
| M4 URL | HuggingFace | 0.20 | 0.25 |
| Domain Intel | Blocklists + MongoDB | 0.15 | 0.15 |

Weights renormalize automatically when a model doesn't run.

## Heuristic Payload Detection

These run regardless of HTTP method (GET or POST):

- `sql_keyword_score > 0` → `payload_attack=True`, `threat_type="SQL Injection"`
- `script_tag_score > 0` → `payload_attack=True`, `threat_type="XSS Attack"`
- Path traversal pattern detected → `payload_attack=True`, `threat_type="Path Traversal"`

Any `payload_attack=True` triggers a **Dangerous** hard rule override in the fusion engine.

## Deployment (Render)

1. Push to `main` — Render auto-deploys
2. Set env vars in Render dashboard: `HF_MODEL1_URL`, `HF_MODEL2_URL`, `HF_MODEL4_URL`, `MONGO_URI`, `LOAD_BLOCKLISTS_ON_STARTUP=true`
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

---

© 2024 CyHub × CyperPox — All rights reserved.
