# CyHub — AI-Driven Web Anomaly Detection System

> An unsupervised machine learning system that detects injection attacks, bot activity, and zero-day threats by modeling normal web request behavior and identifying statistical deviations.

🌐 **Live Demo:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Features](#-features)
3. [Tech Stack](#tech-stack)
4. [How It Works](#how-it-works)
5. [Architecture & Pipeline](#architecture--pipeline)
6. [Multi-Model Threat Detection Pipeline](#multi-model-threat-detection-pipeline)
7. [Project Structure](#project-structure)
8. [Getting Started](#getting-started)
9. [Environment Variables Reference](#environment-variables-reference)
10. [Requirements](#requirements)
11. [Deployment](#-deployment)
12. [API Endpoints](#-api-endpoints)
13. [Application Pages](#-application-pages)
14. [Detection Capabilities](#detection-capabilities)
15. [CLI Tools](#-cli-tools)
16. [Future Roadmap](#future-roadmap)
17. [Contributing](#-contributing)
18. [License](#-license)
19. [Team](#-team)
20. [Documentation](#-documentation)
21. [Links](#-links)

---

## Problem Statement

Modern web applications are increasingly vulnerable to injection attacks, malicious automated bots, and zero-day threats. Traditional security systems rely on static signatures and predefined rules, which fail to detect novel or obfuscated attack patterns. As attackers continuously evolve techniques using encoding, payload obfuscation, and adaptive behavior, signature-based detection becomes insufficient.

This project proposes an **AI-driven anomaly detection system** that models normal web request behavior and identifies statistical deviations using unsupervised machine learning. By learning baseline traffic patterns, the system can detect injection attempts, suspicious request structures, and previously unseen zero-day threats — **without relying on predefined attack signatures**.

---

## ✨ Features

- 🤖 **AI-Powered Detection** — Isolation Forest model for unsupervised anomaly detection
- 🔀 **Multi-Model Pipeline** — Three-stage threat assessment using HuggingFace-hosted specialist models
- 🎯 **Real-Time Analysis** — Instant threat scoring for incoming HTTP requests
- 📦 **Batch Processing** — Upload a CSV of requests for bulk analysis
- 📊 **Interactive Dashboard** — Beautiful UI with stats overview and request logs
- 🔐 **Secure Authentication** — Firebase-powered login with Google OAuth and email/password
- 📈 **Request Analyzer** — Test any HTTP request and get immediate threat assessment
- 🗄️ **Persistent Logging** — MongoDB Atlas primary storage with JSON file fallback
- 🌐 **About Page** — Comprehensive explanation of the problem and solution
- 🚀 **Production Ready** — Deployed on Render (backend) and Vercel (frontend)

---

## Tech Stack

### Backend
| Category          | Technology                                        |
|-------------------|---------------------------------------------------|
| Language          | Python 3.10+                                      |
| Framework         | FastAPI                                           |
| Data Processing   | Pandas, NumPy                                     |
| Machine Learning  | scikit-learn (IsolationForest, StandardScaler)    |
| Remote Models     | HuggingFace Spaces (Model 1, 2, 3 via HTTP)       |
| HTTP Client       | httpx (async-compatible)                          |
| Database          | MongoDB Atlas via Motor (async) + JSON file fallback |
| Visualization     | Matplotlib, Seaborn                               |
| Deployment        | Render                                            |

### Frontend
| Category          | Technology                                        |
|-------------------|---------------------------------------------------|
| Framework         | Next.js 16                                        |
| Language          | TypeScript                                        |
| UI Library        | React 19                                          |
| Styling           | Tailwind CSS                                      |
| 3D Graphics       | Spline                                            |
| Authentication    | Firebase (Google OAuth, Email/Password)           |
| Deployment        | Vercel                                            |

---

## How It Works

### 1. Feature Engineering

Every incoming HTTP request is converted into a **numeric feature vector** before being passed to the model. The feature set is divided into three categories:

#### Structural Features
| Feature | Description |
|---|---|
| `request_length` | Total character length of the request string |
| `url_depth` | Number of `/` separators in the URL path |
| `param_count` | Number of query parameters (count of `=` signs) |

#### Complexity Features
| Feature | Description |
|---|---|
| `special_char_count` | Count of injection-related special characters: `' " ; < > = % (` |
| `shannon_entropy` | Shannon entropy of the request string (UUIDs stripped first to avoid false positives) |

#### Semantic Risk Indicators
| Feature | Description |
|---|---|
| `sql_keyword_score` | Presence score of SQL keywords: `SELECT`, `DROP`, `UNION`, `INSERT`, `DELETE`, `UPDATE`, `OR`, `AND`, `EXEC`, `EXECUTE` |
| `script_tag_score` | Presence score of XSS/script injection patterns: `<script>`, `onerror`, `onload`, `javascript:`, `eval(`, `alert(`, `document.`, `window.` |

> **UUID Stripping:** Before computing Shannon entropy, UUID/GUID segments are removed from the request string. UUIDs produce artificially high entropy (~3.7 bits/char), identical to obfuscated payloads, which would cause false positives on legitimate REST routes.

These **7 features** form the input vector for the base anomaly detection model.

---

### 2. ML Model — Isolation Forest

The base model is trained **exclusively on normal traffic**, making it inherently unsupervised and signature-free.

```
Algorithm    : Isolation Forest
Training Set : Normal (benign) HTTP requests only
Contamination: ~0.05 (5% expected anomaly rate)
n_estimators : 100
Scaler       : StandardScaler (zero mean, unit variance)
Random State : 42
```

**How Isolation Forest detects anomalies:**
- Builds an ensemble of random decision trees
- Anomalous samples are isolated in fewer splits (shorter path length)
- A low (negative) anomaly score → suspicious / attack-like request
- A high (positive) anomaly score → normal benign request

---

### 3. Output

For every request processed, the system outputs:

| Field | Description |
|---|---|
| `raw_request` | The original request string analyzed |
| `anomaly_score` | Continuous score from the model (negative = suspicious) |
| `prediction` | `Normal` or `Suspicious` classification label |
| `threat_type` | Specific threat category (see [Detection Capabilities](#detection-capabilities)) |
| `features` | The 7-element feature vector used for scoring |

---

## Architecture & Pipeline

### High-Level Architecture

```
User Request
     ↓
Feature Extraction Engine  (feature_engineering.py)
     ↓
Feature Vector  [7 numeric features]
     ↓
Preprocessing (StandardScaler)
     ↓
Base Isolation Forest Model  ─── Normal? ──→ "Normal" result
     ↓ Suspicious
Three-Stage Specialist Pipeline
  ├─ Stage 1: Network Traffic Anomaly  (Model 3 — HuggingFace Space)
  ├─ Stage 2: Bot / Botnet Detection   (Model 2 — HuggingFace Space)
  └─ Stage 3: Payload / Injection      (Model 1 — HuggingFace Space)
     ↓
Threat Type Classification
     ↓
Log to MongoDB / JSON file
     ↓
API Response
```

---

### Detailed Workflow

#### Step 1 — Data Collection
Collect normal web request samples representing legitimate baseline traffic. The model is trained exclusively on this benign data (`data/normal_traffic.csv`).

#### Step 2 — Feature Extraction
Convert each raw HTTP request string into a numerical feature vector covering structural, complexity, and semantic risk dimensions (see [How It Works](#how-it-works)).

#### Step 3 — Baseline Modeling
Train the Isolation Forest on only legitimate traffic. The model learns what "normal" looks like without ever seeing attack samples.

#### Step 4 — Detection Phase
For each incoming request:

```
Incoming Request → Feature Extraction → Scaling → Base Model Prediction → Score
```

#### Step 5 — Risk Decision

```python
if anomaly_score < 0:        # base model flags as suspicious
    # Run three-stage specialist pipeline to classify threat type
    threat_type = classify_threat(request, features)
else:
    threat_type = "Normal"   # allow request through
```

---

### Internal Pipeline Design

| Layer | Component | Responsibility |
|---|---|---|
| Layer 1 | **Input Parsing** | Receives raw HTTP request string |
| Layer 2 | **Feature Engineering Module** | Extracts the 7 numerical features (`feature_engineering.py`) |
| Layer 3 | **Feature Scaling** | Applies `StandardScaler` (zero mean, unit variance) |
| Layer 4 | **Base Anomaly Detection** | Isolation Forest scores the request |
| Layer 5 | **Specialist Models** | HuggingFace-hosted models confirm and classify the threat |
| Layer 6 | **Risk Scoring Engine** | Resolves threat type to a final label |
| Layer 7 | **Logging & Storage** | Records all requests to MongoDB Atlas (or JSON fallback) |

---

## Multi-Model Threat Detection Pipeline

When the base Isolation Forest flags a request as suspicious, CyHub invokes three specialist models hosted on **HuggingFace Spaces** for a second opinion and precise threat classification. Each model was trained on network-flow features (CIC-IDS style) and receives a proxy feature vector derived from the HTTP request.

### Stage 1 — Network Traffic Anomaly (Model 3)

Detects unusual network-level traffic patterns.

- **Input:** 35-feature engineered vector (18 base + 17 derived ratio/log features)
- **Output:** `True` if traffic looks anomalous
- **Threat label:** `Traffic Anomaly`
- **Environment variable:** `HF_MODEL3_URL`

### Stage 2 — Bot / Botnet Detection (Model 2)

Identifies automated bot or botnet-style requests.

- **Input:** 14-feature proxy vector (flow duration, byte rates, packet counts, flag signals, etc.)
- **Output:** `True` if traffic looks bot-generated
- **Threat label:** `Bot Activity`
- **Environment variable:** `HF_MODEL2_URL`

### Stage 3 — Payload / Injection Attack (Model 1)

Confirms payload-level injection attacks (SQL, XSS, command injection, etc.).

- **Input:** 35-feature engineered vector (same as Model 3)
- **Output:** `True` if a payload attack is detected
- **Threat label:** `Injection Attack` (or more specific via feature heuristics)
- **Environment variable:** `HF_MODEL1_URL`

### Threat Classification Priority

The stages are evaluated in the following priority order:

```
1. Traffic Anomaly  (Model 3 → True)
2. Bot Activity     (Model 2 → True)
3. SQL Injection    (sql_keyword_score > 0)
4. XSS Attack       (script_tag_score > 0)
5. Path Traversal   ("../" or encoded variants found)
6. Injection Attack (Model 1 → True, or base model flag without a more specific category)
```

### Fallback Behavior

All three HuggingFace calls are wrapped with timeouts and error handling. If a remote model is unreachable:
- The stage is skipped and treated as "not detected"
- The pipeline continues with the remaining stages
- The base Isolation Forest score alone is used for the final `Normal`/`Suspicious` label

### Default HuggingFace Endpoints

| Model | Default URL |
|---|---|
| Model 1 (Payload) | `https://bhavyasoni21-model1.hf.space/predict` |
| Model 2 (Bot)     | `https://bhavyasoni21-model2.hf.space/predict` |
| Model 3 (Traffic) | `https://bhavyasoni21-model3.hf.space/predict` |

All URLs can be overridden via environment variables (see [Environment Variables Reference](#environment-variables-reference)).

---

## Project Structure

```
CyperPox_CyHub_HackNova-CyberTech-Track/
│
├── backend/
│   ├── data/
│   │   ├── normal_traffic.csv         # Benign request samples for training
│   │   ├── test_traffic.csv           # Mixed requests for evaluation
│   │   └── request_logs.json          # JSON fallback log (auto-created)
│   │
│   ├── src/
│   │   ├── __init__.py
│   │   ├── feature_engineering.py     # Converts raw requests to feature vectors
│   │   ├── multi_predict.py           # Three-stage HuggingFace model pipeline
│   │   ├── train_model.py             # Trains and saves the Isolation Forest model
│   │   ├── predict.py                 # Single-model predictor (CLI + library)
│   │   └── visualize.py              # Plots anomaly score distributions
│   │
│   ├── models/
│   │   └── isolation_forest.pkl       # Serialized trained model (auto-generated)
│   │
│   ├── main.py                        # FastAPI backend server
│   ├── requirements.txt
│   ├── .env.example                   # Backend environment variable template
│   └── .python-version                # Python version pin
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx             # Root layout
│   │   │   ├── globals.css            # Global styles
│   │   │   ├── page.tsx               # Dashboard home page
│   │   │   ├── login/                 # Authentication page
│   │   │   └── about/                 # About page
│   │   │
│   │   ├── components/
│   │   │   ├── dashboard/             # Dashboard components
│   │   │   ├── ui/                    # Reusable UI components
│   │   │   └── navigation.tsx         # Navigation bar
│   │   │
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx        # Firebase authentication context
│   │   │
│   │   └── lib/
│   │       ├── api.ts                 # API client (axios-based)
│   │       ├── firebase.ts            # Firebase client initialization
│   │       └── types.ts               # TypeScript type definitions
│   │
│   ├── public/                        # Static assets
│   ├── package.json
│   ├── next.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.*
│   └── .env.example                   # Frontend environment variable template
│
├── render.yaml                        # Render deployment config
├── Firebase_Setup.md                  # Firebase authentication setup guide
├── DEPLOYMENT_CHECKLIST.md            # Deployment steps and troubleshooting
├── LICENSE.md
└── README.md
```

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **npm or yarn**
- **Firebase account** (for authentication)
- **MongoDB Atlas account** (optional — JSON file fallback is used if not configured)

### Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track.git
   cd CyperPox_CyHub_HackNova-CyberTech-Track/backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

4. **Train the model:**
   ```bash
   python src/train_model.py
   ```
   This reads `data/normal_traffic.csv`, trains the Isolation Forest, and saves the pipeline to `models/isolation_forest.pkl`.

5. **Start the FastAPI server:**
   ```bash
   uvicorn main:app --reload --port 8000
   ```

6. **API will be available at:** `http://localhost:8000`
   - Interactive docs: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

### Frontend Setup

1. **Navigate to frontend directory:**
   ```bash
   cd ../frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**

   Create a `.env.local` file in the `frontend/` directory:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8000
   NEXT_PUBLIC_FIREBASE_API_KEY=your-firebase-api-key
   NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
   NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
   NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
   NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
   ```

4. **Set up Firebase authentication:**

   Follow the guide in [Firebase_Setup.md](Firebase_Setup.md) to:
   - Create a Firebase project
   - Get your credentials
   - Enable Email/Password and Google sign-in

5. **Start the development server:**
   ```bash
   npm run dev
   ```

6. **Open your browser:** `http://localhost:3000`

### Quick Start (Both Services)

Run both backend and frontend simultaneously:

```bash
# Terminal 1 — Backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
npm run dev
```

---

## Environment Variables Reference

### Backend (`backend/.env`)

| Variable | Default | Description |
|---|---|---|
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated list of allowed frontend origins |
| `MODEL_PATH` | `models/isolation_forest.pkl` | Path to the serialized Isolation Forest pipeline |
| `MONGODB_URI` | *(empty)* | MongoDB connection URI — leave blank to use JSON file fallback |
| `MONGODB_DB` | `cyhub` | MongoDB database name |
| `LOGS_FILE` | `data/request_logs.json` | Path for the JSON file fallback log |
| `HF_MODEL1_URL` | `https://bhavyasoni21-model1.hf.space/predict` | HuggingFace endpoint for Model 1 (payload/injection) |
| `HF_MODEL2_URL` | `https://bhavyasoni21-model2.hf.space/predict` | HuggingFace endpoint for Model 2 (bot detection) |
| `HF_MODEL3_URL` | `https://bhavyasoni21-model3.hf.space/predict` | HuggingFace endpoint for Model 3 (traffic anomaly) |
| `HF_MODEL1_TIMEOUT` | `8.0` | Request timeout in seconds for Model 1 |
| `HF_MODEL2_TIMEOUT` | `8.0` | Request timeout in seconds for Model 2 |
| `HF_MODEL3_TIMEOUT` | `8.0` | Request timeout in seconds for Model 3 |
| `HF_API_TOKEN` | *(empty)* | HuggingFace API token for private Spaces (optional) |
| `HF_BASE_MODEL_URL` | *(empty)* | Override the base Isolation Forest with a remote HuggingFace endpoint |
| `HF_BASE_MODEL_TIMEOUT` | `8.0` | Request timeout for the remote base model |

### Frontend (`frontend/.env.local`)

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_URL` | Backend API base URL (e.g., `http://localhost:8000` or your Render URL) |
| `NEXT_PUBLIC_FIREBASE_API_KEY` | Firebase Web API key |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | Firebase auth domain (e.g., `your-project.firebaseapp.com`) |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | Firebase project ID |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | Firebase storage bucket |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | Firebase messaging sender ID |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | Firebase app ID |

---

## Requirements

### Backend (`backend/requirements.txt`)
```
fastapi
uvicorn
pandas
numpy
scikit-learn
matplotlib
seaborn
python-multipart
python-dotenv
joblib
httpx
motor
pymongo
```

### Frontend (`frontend/package.json`)
```
next
react
react-dom
typescript
tailwindcss
firebase
axios
framer-motion
lucide-react
@splinetool/react-spline
```

---

## 🚀 Deployment

### Backend (Render)

The backend is deployed on **Render** using the configuration in `render.yaml`.

**What Render does on deployment:**
1. Installs Python dependencies (`pip install -r requirements.txt`)
2. Trains the Isolation Forest model (`python src/train_model.py`)
3. Starts the FastAPI server (`uvicorn main:app --host 0.0.0.0 --port $PORT`)
4. Mounts a 1 GB persistent disk at `/opt/render/project/src/models` for the model file

**Live API:** `https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com`

**Environment Variables Required on Render:**

| Variable | Value |
|---|---|
| `CORS_ORIGINS` | `https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app` |
| `MODEL_PATH` | `models/isolation_forest.pkl` |
| `MONGODB_URI` | Your MongoDB Atlas connection string |
| `MONGODB_DB` | `cyhub` |

### Frontend (Vercel)

The frontend is deployed on **Vercel** with automatic deployments from the GitHub `main` branch.

**Live App:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)

**Environment Variables Required on Vercel:**

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_URL` | Your Render backend URL |
| `NEXT_PUBLIC_FIREBASE_API_KEY` | Firebase Web API key |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | Firebase auth domain |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | Firebase project ID |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | Firebase storage bucket |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | Firebase messaging sender ID |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | Firebase app ID |

### Firebase Configuration

For production deployment:
1. Go to **Firebase Console → Authentication → Sign-in method**
2. Enable **Email/Password** and **Google**
3. Go to **Authentication → Settings → Authorized domains**
4. Add your Vercel production domain (e.g., `cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app`)

### MongoDB Atlas Setup

1. Create a free cluster at [https://cloud.mongodb.com](https://cloud.mongodb.com)
2. Create a database user with read/write permissions
3. Whitelist the Render IP (or allow access from anywhere: `0.0.0.0/0`)
4. Copy your connection string and set it as `MONGODB_URI` in Render
5. The `request_logs` collection is created automatically on first insert — no manual setup required

> **Note:** If `MONGODB_URI` is not set, the backend automatically falls back to a local JSON file (`data/request_logs.json`) for log persistence.

---

## 🌐 API Endpoints

All endpoints are served by the FastAPI backend. Interactive documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc) when the server is running.

---

### `POST /predict`

Analyze a single HTTP request for anomalies.

**Request body:**
```json
{
  "raw_request": "GET /admin?id=1' OR '1'='1 HTTP/1.1\nHost: example.com"
}
```

**Response:**
```json
{
  "raw_request": "GET /admin?id=1' OR '1'='1 HTTP/1.1\nHost: example.com",
  "anomaly_score": -0.234,
  "prediction": "Suspicious",
  "threat_type": "SQL Injection",
  "features": {
    "request_length": 56,
    "url_depth": 1,
    "param_count": 2,
    "special_char_count": 5,
    "shannon_entropy": 3.87,
    "sql_keyword_score": 2,
    "script_tag_score": 0
  }
}
```

| Field | Type | Description |
|---|---|---|
| `raw_request` | string | The original request string |
| `anomaly_score` | float | Model score — negative values are suspicious |
| `prediction` | string | `"Normal"` or `"Suspicious"` |
| `threat_type` | string | Specific threat label (see [Detection Capabilities](#detection-capabilities)) |
| `features` | object | The 7-element feature vector |

---

### `POST /predict/batch`

Upload a CSV file of HTTP requests for bulk analysis.

**Request:** `multipart/form-data` with a `file` field containing a CSV.  
The CSV must have a `request` column.

**Example CSV:**
```csv
request
"GET /api/users HTTP/1.1"
"GET /admin' OR '1'='1 HTTP/1.1"
"<script>alert(1)</script>"
```

**Response:** Array of `PredictResponse` objects (same schema as `/predict`).

---

### `GET /logs`

Retrieve the scored request log history.

**Query parameters:**
| Parameter | Default | Description |
|---|---|---|
| `limit` | `100` | Maximum number of log entries to return |

**Response:**
```json
[
  {
    "id": "abc123",
    "timestamp": "2025-01-15T10:30:00+00:00",
    "raw_request": "GET /api/users HTTP/1.1",
    "anomaly_score": 0.15,
    "prediction": "Normal"
  }
]
```

Entries are returned in **reverse chronological order** (newest first).

---

### `GET /stats`

Get aggregate statistics from all logged requests.

**Response:**
```json
{
  "total_scanned": 142,
  "normal_count": 128,
  "suspicious_count": 14,
  "model_status": "Ready"
}
```

| Field | Description |
|---|---|
| `total_scanned` | Total number of analyzed requests |
| `normal_count` | Requests classified as normal |
| `suspicious_count` | Requests classified as suspicious |
| `model_status` | `"Ready"` when model is loaded, `"Not Loaded"` otherwise |

---

### `GET /health`

API health check.

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "version": "1.0.0"
}
```

---

## 🎨 Application Pages

### Dashboard (`/`)
- **Hero Section** with 3D Spline visualization
- **Stats Overview** showing detection metrics (auto-refreshes every 30 seconds)
- **Request Analyzer** for manual testing — paste any HTTP request and click "Analyze"
- **Request Logs** displaying recent detections with scores and threat labels

### Login (`/login`)
- Email/Password authentication
- Google OAuth sign-in
- Dark-themed UI
- Automatic redirect to dashboard after login

### About (`/about`)
- Problem statement explanation
- Solution overview
- How it works (step-by-step walkthrough)
- Technology stack showcase
- Feature highlights and detection capabilities

---

## Detection Capabilities

| Threat Type | Detection Mechanism |
|---|---|
| SQL Injection | SQL keyword scoring + entropy spike |
| XSS / Script Injection | Script tag pattern scoring |
| Path Traversal | `../` or URL-encoded variants in request string |
| Obfuscated Payloads | Shannon entropy deviation (high randomness) |
| Traffic Anomaly | Network-flow feature anomaly (Model 3) |
| Bot Activity | Bot behavioral signature detection (Model 2) |
| Injection Attack | General payload confirmation (Model 1) |
| Zero-Day / Unknown Attacks | Statistical outlier via Isolation Forest |

---

## 🖥 CLI Tools

### `predict.py` — Single-Model CLI Predictor

Score requests from a CSV file directly from the command line using only the base Isolation Forest model.

```bash
cd backend

# Score a test CSV
python src/predict.py --input data/test_traffic.csv

# Use a different model file
python src/predict.py --input data/test_traffic.csv --model models/isolation_forest.pkl
```

**Arguments:**
| Argument | Default | Description |
|---|---|---|
| `--input` | `data/test_traffic.csv` | Path to CSV with a `request` column |
| `--model` | `models/isolation_forest.pkl` | Path to the serialized model pipeline |

**Example output:**
```
================================================================================
Request                                             Score        Label
================================================================================
GET /api/users?page=1 HTTP/1.1                     0.1423       Normal
GET /admin?id=1' OR '1'='1 HTTP/1.1               -0.2341      Suspicious
<script>alert(document.cookie)</script>            -0.4012      Suspicious

[SUMMARY] 2/3 requests flagged as suspicious (66.7%)
```

### `train_model.py` — Model Training

Retrain the Isolation Forest model on new or updated normal traffic data.

```bash
cd backend
python src/train_model.py
```

This script:
1. Loads `data/normal_traffic.csv` (must have a `request` column)
2. Extracts all 7 features for every request
3. Fits a `StandardScaler` and `IsolationForest`
4. Saves the pipeline to `models/isolation_forest.pkl`
5. Prints training statistics (anomaly rate, score range, mean)

### `visualize.py` — Score Distribution Visualization

Plot the anomaly score distribution for a labeled dataset.

```bash
cd backend
python src/visualize.py
```

---

## Future Roadmap

- [x] Modern web UI with Next.js and React
- [x] User authentication with Firebase
- [x] Real-time request analysis API
- [x] Multi-model HuggingFace threat pipeline
- [x] Batch CSV upload and analysis
- [x] MongoDB Atlas persistence with JSON fallback
- [x] Production deployment (Render + Vercel)
- [ ] User-specific detection history (per-account logs)
- [ ] Advanced analytics dashboard (charts, trends)
- [ ] Deep learning-based sequence modeling (LSTM / Transformer)
- [ ] Alert notifications (email/webhook)
- [ ] Rate limiting and API keys
- [ ] Containerized deployment with Docker
- [ ] API gateway integration (NGINX middleware)
- [ ] Automated model retraining pipeline

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE.md) for details.

---

## 👥 Team

**Project:** CyperPox - CyHub  
**Hackathon:** HackNova CyberTech Track  
**Repository:** [GitHub](https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track)

---

## 📚 Documentation

- [Firebase Setup Guide](Firebase_Setup.md) — Complete authentication configuration
- [Deployment Checklist](DEPLOYMENT_CHECKLIST.md) — Step-by-step production deployment guide
- [API Documentation](http://localhost:8000/docs) — Interactive Swagger UI (when running locally)
- [ReDoc API Reference](http://localhost:8000/redoc) — Alternative API docs (when running locally)

---

## 🔗 Links

- **Live Demo:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)
- **GitHub:** [Repository](https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track)
- **Backend API:** `https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com`
- **Backend API Docs:** `https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com/docs`

---

**Built with ❤️ by the CyperPox Team**
