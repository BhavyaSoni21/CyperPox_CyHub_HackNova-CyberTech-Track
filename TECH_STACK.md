# CyHub — Tech Stack

> Detailed breakdown of all technologies, libraries, and architectural decisions used in the CyHub AI-Driven Web Anomaly Detection System.

---

## Language & Runtime

| Technology | Version | Purpose |
|---|---|---|
| **Python** | 3.10+ | Primary language for all ML, data processing, and application logic |

Python 3.10+ is required for modern type hint syntax, structural pattern matching, and compatibility with all listed dependencies.

---

## Data Processing

| Library | Purpose |
|---|---|
| **Pandas** | Ingesting and manipulating tabular HTTP request data (CSV loading, DataFrame operations) |
| **NumPy** | Numerical array operations, vectorized feature computation, entropy calculations |

### Why These?
- Pandas provides a clean interface for loading `normal_traffic.csv` and `test_traffic.csv`, field access, and batch-processing request rows.
- NumPy underpins all mathematical operations including the Shannon entropy formula applied per request.

---

## Machine Learning

| Library / Component | Purpose |
|---|---|
| **scikit-learn** | Core ML framework |
| `IsolationForest` | Unsupervised anomaly detection model |
| `StandardScaler` | Feature normalization (zero mean, unit variance) |
| `joblib` (via sklearn) | Serializing and loading the trained model (`isolation_forest.pkl`) |

### Model Design Decisions

| Parameter | Value | Rationale |
|---|---|---|
| Algorithm | Isolation Forest | Trains on normal traffic only; no labeled attack data required |
| Contamination | ~0.05 | Assumes ~5% of requests in deployment may be anomalous |
| Scaler | StandardScaler | Ensures all features (e.g., `request_length` vs. `shannon_entropy`) are on comparable scales |
| Training Set | Benign traffic only | Enables detection of zero-day threats without attack signatures |

---

## Feature Engineering

Custom-built in `src/feature_engineering.py`. Converts raw HTTP request strings into a **6–7 dimensional numeric feature vector**.

| Feature | Type | Library Used |
|---|---|---|
| `request_length` | Structural | Python `len()` |
| `url_depth` | Structural | Python `str.count('/')` |
| `param_count` | Structural | Python `str.count('=')` |
| `special_char_count` | Complexity | Python `re` / string ops |
| `shannon_entropy` | Complexity | NumPy / `math.log2` |
| `sql_keyword_score` | Semantic Risk | Python regex / keyword matching |
| `script_tag_score` | Semantic Risk | Python regex / pattern matching |

---

## Visualization

| Library | Purpose |
|---|---|
| **Matplotlib** | Base plotting — anomaly score distributions, scatter plots |
| **Seaborn** | Statistical visualizations — density plots, heatmaps, styled charts |

Used in `src/visualize.py` to render anomaly score distributions and highlight flagged requests vs. normal baseline.

---

## Frontend

| Technology | Version | Purpose |
|---|---|---|
| **React** | 18+ | Component-based UI for the anomaly detection dashboard |
| **JavaScript (ES2022+)** | — | Primary language for all frontend logic |
| **HTML5 / CSS3** | — | Markup and styling |

### Key Frontend Responsibilities
- Render live anomaly score results returned from the FastAPI backend
- Display request logs, risk labels (`Normal` / `Suspicious`), and score distributions
- Provide input forms for submitting raw HTTP request strings for analysis
- Consume REST API endpoints exposed by FastAPI

---

## Backend

| Technology | Version | Purpose |
|---|---|---|
| **FastAPI** | 0.110+ | High-performance async REST API framework |
| **Uvicorn** | — | ASGI server — runs the FastAPI application |
| **Pydantic** | v2 | Request/response schema validation and serialization |
| **Python** | 3.10+ | Backend runtime |

### Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/predict` | Accepts a raw HTTP request string, returns anomaly score and label |
| `POST` | `/predict/batch` | Batch scoring from uploaded CSV |
| `GET` | `/logs` | Retrieves flagged request log history from Supabase |
| `GET` | `/health` | API health check |

### Why FastAPI?
- Native async support for handling concurrent request scoring
- Automatic OpenAPI/Swagger docs at `/docs`
- Tight Pydantic integration for clean input validation
- Minimal overhead compared to Django; more structured than Flask

---

## Database

| Technology | Purpose |
|---|---|
| **Supabase** | Managed PostgreSQL backend — stores flagged request logs, anomaly scores, and timestamps |
| **PostgreSQL** | Underlying relational database (managed by Supabase) |
| **Supabase Python Client** | `supabase-py` — used in FastAPI to insert and query records |

### Schema Overview

| Table | Columns | Purpose |
|---|---|---|
| `request_logs` | `id`, `timestamp`, `raw_request`, `anomaly_score`, `prediction` | Stores every scored request with its result |
| `flagged_requests` | `id`, `timestamp`, `raw_request`, `anomaly_score`, `alert_sent` | Subset of anomalous requests for alerting |

### Why Supabase?
- Hosted PostgreSQL with no infrastructure setup
- Built-in REST and real-time APIs
- Free tier sufficient for development and demo scale
- Row-level security for production readiness

---

## Optional UI (Legacy)

| Technology | Purpose | Status |
|---|---|---|
| **Streamlit** | Rapid-prototype dashboard used during early development | Superseded by React frontend |

Streamlit was used for early prototyping before the full React + FastAPI architecture was adopted.

---

## Persistence & Storage

| Component | Technology | Purpose |
|---|---|---|
| Trained Model | `joblib` (`.pkl`) | Serializes the fitted `IsolationForest` + `StandardScaler` pipeline to `models/isolation_forest.pkl` |
| Training Data | CSV (`data/normal_traffic.csv`) | Benign HTTP request samples used for baseline modeling |
| Test Data | CSV (`data/test_traffic.csv`) | Mixed (benign + attack) samples for evaluation |
| Request Logs | Supabase / PostgreSQL | Persists all scored requests with scores, labels, and timestamps |
| Environment Config | `.env` | Stores `SUPABASE_URL` and `SUPABASE_KEY` secrets (never committed) |

---

## Project Pipeline Architecture

```
[React Frontend]
     ↓  HTTP POST /predict
[FastAPI Backend]
     ↓
 Layer 1 — Input Parsing          Raw HTTP request string (from request body)
 Layer 2 — Feature Engineering    src/feature_engineering.py → 6–7 numeric features
 Layer 3 — Feature Scaling        StandardScaler (fit on training set)
 Layer 4 — Anomaly Detection      IsolationForest → raw anomaly score
 Layer 5 — Risk Scoring Engine    Score → Normal / Suspicious label
 Layer 6 — Persistence            Score + label + timestamp → Supabase (PostgreSQL)
 Layer 7 — API Response           JSON { anomaly_score, prediction } → React
[React Frontend]
     ↓
 Renders result in dashboard
```

---

## Dependency Summary

### Python (Backend) — `requirements.txt`

```
fastapi
uvicorn[standard]
pydantic
pandas
numpy
scikit-learn
matplotlib
seaborn
supabase
python-dotenv
```

Install via:

```bash
pip install -r requirements.txt
```

### JavaScript (Frontend) — `package.json`

```
react
react-dom
axios
```

Install via:

```bash
npm install
```

---

## Future Stack Additions

| Technology | Planned Purpose |
|---|---|
| **PyTorch / TensorFlow** | LSTM or Transformer encoder for sequence-based request modeling |
| **Apache Kafka / Redis Streams** | Real-time traffic ingestion pipeline |
| **Docker** | Containerized deployment of FastAPI + React services |
| **NGINX** | Reverse proxy and API gateway in front of FastAPI |
| **Supabase Realtime** | WebSocket-based live alert streaming to React dashboard |
| **Grafana** | Advanced metrics and anomaly trend dashboards |

---

## Design Philosophy

- **Signature-free** — no predefined attack rules; the model learns normality, making it effective against zero-day threats.
- **Unsupervised** — no labeled attack data required during training, reducing operational overhead.
- **Lightweight** — the full inference pipeline (feature extraction → scaling → prediction) runs in-process with minimal latency.
- **Extensible** — the feature vector and model can be swapped independently; the pipeline layers are decoupled by design.
