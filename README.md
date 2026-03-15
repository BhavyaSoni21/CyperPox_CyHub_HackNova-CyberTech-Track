# CyHub — AI-Driven Web Anomaly Detection System

> A multi-model machine learning pipeline that detects SQL injection, XSS attacks, path traversal, bot activity, malicious domains, and zero-day threats using a 5-signal fusion engine — signature-free, real-time, and zero-day capable.

**Live Demo:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)
**GitHub:** [CyperPox_CyHub_HackNova-CyberTech-Track](https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track)
**Version:** 2.0 — Signal Fusion

---

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Architecture — Signal Fusion v2](#architecture--signal-fusion-v2)
4. [How It Works](#how-it-works)
5. [Feature Engineering](#feature-engineering)
6. [Threat Engine — 5-Signal Fusion](#threat-engine--5-signal-fusion)
7. [Model Details](#model-details)
8. [Domain Intelligence](#domain-intelligence)
9. [Behavioral Bot Detection](#behavioral-bot-detection)
10. [API Endpoints](#api-endpoints)
11. [Tech Stack](#tech-stack)
12. [Project Structure](#project-structure)
13. [Getting Started](#getting-started)
14. [Environment Variables](#environment-variables)
15. [Frontend Pages & Components](#frontend-pages--components)
16. [Detection Capabilities](#detection-capabilities)
17. [Deployment](#deployment)
18. [Future Roadmap](#future-roadmap)
19. [License](#license)

---

## Overview

CyHub replaces traditional signature-based intrusion detection with a **5-signal fusion pipeline** that learns what normal web traffic looks like and identifies statistical deviations in real time. It accepts raw HTTP requests, URLs, or both, and returns a `ComprehensiveThreatReport` with a 4-tier verdict, per-model scores, and human-readable recommendations.

Key design principles:
- **No signatures** — the base model (Isolation Forest) is trained exclusively on normal traffic
- **No gatekeeper** — the base model is one signal among five, not a gatekeeping filter
- **Context-adaptive** — fusion weights shift between API and Browser request types
- **Hard rules override** — malware domains, payload attacks, and blocklisted URLs always escalate regardless of the numeric score

---

## Problem Statement

Modern web applications are increasingly vulnerable to injection attacks, malicious automated bots, and zero-day threats. Traditional security systems rely on static signatures and predefined rules, which fail to detect novel or obfuscated attack patterns.

As attackers continuously evolve techniques — encoding payloads, obfuscating structures, using adaptive timing — signature-based detection becomes insufficient. Organizations need a system that can:

- Detect **previously unseen attack vectors** without predefined signatures
- Identify **obfuscated and encoded payloads** that bypass traditional WAF rules
- Classify threats with **granular labels** (SQL Injection, XSS, Path Traversal, Bot, Traffic Anomaly) rather than a binary flag
- Adapt to **evolving patterns** by re-scoring every dimension of a request in real time
- Flag **malicious domains** before the request even reaches the application

---

## Architecture — Signal Fusion v2

```
Incoming Request (URL and/or raw HTTP)
              │
              ├─── Feature Extraction (7 features)
              │          └─── request_length, url_depth, param_count,
              │               special_char_count, shannon_entropy,
              │               sql_keyword_score, script_tag_score
              │
              ├─── Domain Intelligence  (pre-filter + Model 4)
              │          └─── whitelist → blocklist → DNS → heuristics → M4 HF
              │
              ├─── M1 Payload Model    (HuggingFace, 11 features)
              ├─── M2 Bot Model        (HuggingFace, 14 flow features)
              ├─── M3 Traffic Model    (Local RandomForest, 35 features)
              │
              └─── Behavioral Bot Detector  (in-memory sliding window per IP)
                             │
                             ▼
                  ┌──────────────────────┐
                  │  Threat Engine       │
                  │  5-Signal Fusion     │
                  │  Adaptive Weights    │
                  │  Hard Rule Override  │
                  └──────────────────────┘
                             │
                             ▼
              Safe / Caution / Suspicious / Dangerous / Blocked
```

M1, M2, M3 run conditionally:
- **M1** runs when `raw_request` is non-empty and the request is an API call (POST/PUT/PATCH/DELETE or structured content-type)
- **M2 + M3** run when exactly 14 network flow features are supplied
- All active models run in **parallel** via `asyncio.gather()`

---

## How It Works

### Step 1 — Domain Pre-Filter

Before any ML model runs, every URL passes through the Domain Intelligence pipeline:

```
extract_domain() → normalize_domain()
  → whitelist check  (fast-track → classification="normal")
  → blocklist check  (fail → blocked, passes_domain_filter=False)
  → DNS validation   (fail → "non_existent_domain")
  → heuristic scan   (fail → "suspicious")
  → Model 4 call     (classifies as: normal/adult/betting/malware/phishing/unknown)
```

16 major domains are whitelisted by default (`google.com`, `github.com`, `facebook.com`, etc.). Additional domains can be whitelisted via the `WHITELIST_DOMAINS` env var or MongoDB.

### Step 2 — Feature Extraction

Every HTTP request is converted into a numeric vector. UUID/GUID segments are stripped before entropy computation to prevent false positives on legitimate REST routes.

| Feature | Description |
|---|---|
| `request_length` | Total character length of the raw request |
| `url_depth` | Number of `/` separators in the URL path |
| `param_count` | Count of `=` signs (query parameters) |
| `special_char_count` | Count of `' " ; < > = % ( )` — hyphens excluded |
| `shannon_entropy` | Randomness of the request (UUID-stripped) |
| `sql_keyword_score` | Presence of SQL keywords: SELECT, DROP, UNION, INSERT, OR, AND |
| `script_tag_score` | Presence of: `<script>`, `onerror`, `javascript:`, `eval(`, `alert(` |

### Step 3 — Heuristic Payload Flags

These run **regardless of HTTP method** (GET or POST):

| Condition | Effect |
|---|---|
| `sql_keyword_score > 0` | `payload_attack=True`, `threat_type="SQL Injection"` |
| `script_tag_score > 0` | `payload_attack=True`, `threat_type="XSS Attack"` |
| `../`, `..\\`, `%2e%2e`, `..%2f` in request | `payload_attack=True`, `threat_type="Path Traversal"` |

Any `payload_attack=True` propagates to the fusion engine and triggers a **Dangerous** hard rule.

### Step 4 — Parallel Model Calls

Active models run concurrently. Each returns a threat score (0.0–1.0):

| Model | Source | Features | Detects |
|---|---|---|---|
| M4 URL | HuggingFace Space | Domain-level features + TF flags | malware / phishing / adult / betting / unknown |
| M3 Traffic | Local RandomForest | 35 derived network-flow features | traffic anomalies, DDoS patterns |
| M2 Bot | HuggingFace Space | 14 raw network flow values | automated scanners, bot traffic |
| M1 Payload | HuggingFace Space | 11 request-level features | injection, XSS, payload attacks |

### Step 5 — Signal Fusion & Verdict

Five signals are combined with context-adaptive weights (see [Threat Engine](#threat-engine--5-signal-fusion)), then verdict thresholds and hard rules are applied.

---

## Feature Engineering

### Base 7-Feature Vector (used by base IsolationForest + M1)

All values are float. Computed by `src/feature_engineering.py`.

### Extended 11-Feature Vector (M1 Payload model)

Adds to the base 7: `digit_ratio`, `path_traversal_score`, `cookie_length`, `user_agent_length`

### 14-Feature Network Flow Vector (M2 Bot model)

Raw 14-element vector supplied by the caller (from a network monitoring layer). Validated with `np.isfinite` before sending to HF.

### 35-Feature Traffic Vector (M3 RandomForest)

Derived internally from 18 base network-flow values. The other 17 are engineered (log transforms, byte/packet ratios, IAT statistics, etc.).

---

## Threat Engine — 5-Signal Fusion

Source: `backend/src/threat_engine.py`

### URL Score Mapping (Model 4)

| M4 Classification | Base Score | With Confidence |
|---|---|---|
| `normal` | 0.0 | `0.0 × confidence` |
| `unknown` | 0.5 | `0.5 × confidence` |
| `adult` | 0.9 | `0.9 × confidence` |
| `betting` | 0.9 | `0.9 × confidence` |
| `phishing` | 0.95 | `0.95 × confidence` |
| `malware` | 1.0 | `1.0 × confidence` |
| `blocked` | 1.0 | `1.0 × confidence` |

### Context-Adaptive Weight Matrix

| Signal | API Weight | Browser Weight |
|---|---|---|
| M4 URL Model | 0.20 | 0.25 |
| M3 Traffic | 0.20 | 0.25 |
| M2 Bot | 0.20 | 0.20 |
| M1 Payload | 0.25 | 0.15 |
| Domain Intel | 0.15 | 0.15 |

When a model does not run (e.g., no flow features supplied → M2/M3 skip), its weight is zeroed and the remaining weights are **renormalized** to sum to 1.0.

API detection: POST/PUT/DELETE/PATCH method, or `Content-Type: application/json / application/xml / application/x-www-form-urlencoded`.

### Domain Intelligence Score

| Condition | Score |
|---|---|
| No domain check performed | 0.30 |
| classification == `"normal"` | 0.00 |
| passes_domain_filter == False | 1.00 |
| threat flag `type_malware > 0` | 0.90 |
| threat flag `type_phishing > 0` | 0.85 |
| threat flag `type_defacement > 0` | 0.70 |
| blocked_reason present | 0.70 |
| classification == `"suspicious"` | 0.50 |
| classification == `"unknown"` | 0.30 |
| default | 0.10 |

### Fused Score Formula

```
active_weights = { signal: weight for each signal if model ran }
total_w = sum(active_weights)
scale = 1.0 / total_w
overall_score = sum(signal_score × weight × scale)
```

### Verdict Thresholds

| Fused Score | Verdict | Default Recommendation |
|---|---|---|
| `< 0.20` | **Safe** | No significant threats detected |
| `0.20 – 0.50` | **Caution** | Allow but monitor closely |
| `0.50 – 0.80` | **Suspicious** | Flag for security review |
| `≥ 0.80` | **Dangerous** | Block immediately |

### Hard Rules (override thresholds, checked first)

| Condition | Verdict | Reason |
|---|---|---|
| M4 == `"blocked"` | **Blocked** | Domain is blocklisted or failed pre-filter checks |
| M4 == `"malware"` | **Dangerous** | Malware domain detected — block immediately |
| M4 == `"adult"` | **Blocked** | Policy — adult content domain |
| M4 == `"betting"` | **Blocked** | Policy — gambling/betting domain |
| `traffic_anomaly AND bot_activity` | **Dangerous** | Combined traffic + bot signal |
| `payload_attack_detected` (any method) | **Dangerous** | Injection/XSS/traversal detected |

---

## Model Details

### M1 — Payload Attack Model (HuggingFace)

- **Purpose:** Confirms injection attacks, XSS, and payload-based threats
- **Input:** 11 HTTP request features
- **Endpoint:** `HF_MODEL1_URL` env var
- **Default:** `https://bhavyasoni21-model1.hf.space/predict`

### M2 — Bot Detection Model (HuggingFace)

- **Purpose:** Identifies automated scanner and bot traffic
- **Input:** 14 raw network flow features
- **Endpoint:** `HF_MODEL2_URL` env var
- **Default:** `https://bhavyasoni21-model2.hf.space/predict`

### M3 — Traffic Anomaly Model (Local RandomForest)

- **Purpose:** Detects traffic-level anomalies (DDoS, port scans, volume spikes)
- **Input:** 35 engineered network features
- **Hosted:** Local `RandomForest` (deployed with backend)

### M4 — URL Classifier (HuggingFace)

- **Purpose:** Classifies the destination domain: normal / adult / betting / malware / phishing / unknown
- **Input:** Domain-level features + heuristic threat flags
- **Endpoint:** `HF_MODEL4_URL` env var
- **Default:** `https://bhavyasoni21-model4.hf.space/predict`
- **Key normalization:** HF returns `predicted_label` → renamed to `classification`
- **Confidence normalization:** auto-divides by 100 if raw value > 1.0

### Base Model — Isolation Forest (scikit-learn)

- **Purpose:** Unsupervised baseline — trained exclusively on normal traffic
- **Role in v2:** One signal among five (not a gatekeeper)
- **Contamination:** ~0.05 (5% expected anomaly rate)
- **Scaler:** StandardScaler (zero mean, unit variance)
- **Stored at:** `backend/models/isolation_forest.pkl`

---

## Domain Intelligence

Source: `backend/src/domain_intelligence.py`

### Pre-Filter Pipeline

```
URL → extract_domain()
    → normalize_domain()
    → whitelist check    → hit: classification="normal" (skip remaining)
    → blocklist check    → hit: blocked, passes_domain_filter=False
    → DNS validation     → fail: "non_existent_domain"
    → heuristic scan     → fail: "suspicious"
    → in-memory cache    → hit: return cached result
    → Model 4 call       → classify + cache result
```

### Whitelisted Domains (hardcoded)

`google.com`, `github.com`, `stackoverflow.com`, `linkedin.com`, `facebook.com`, `twitter.com`, `reddit.com`, `youtube.com`, `wikipedia.org`, `aws.amazon.com`, `microsoft.com`, `apple.com`, `netflix.com`, `slack.com`, `discord.com`, `twitch.tv`

Additional domains: `WHITELIST_DOMAINS` env var (comma-separated) or MongoDB `whitelisted_domains` collection.

### Heuristic Rules (domain structure)

| Rule | Flag |
|---|---|
| `domain.count("-") > 4` | `excessive_hyphens` |
| subdomain depth > 3 | `excessive_subdomains` |
| `len(domain) > 63` | `domain_too_long` |
| Suspicious keyword in hostname part | `suspicious_keyword_{part}` |
| Pattern match (phishing/malware/betting/defacement) | `suspicious_pattern_{type}` |

**Suspicious keywords:** `login`, `secure`, `update`, `verify`, `confirm`, `validate`, `auth`, `account`, `bank`, `paypal`, `amazon`, `apple`, `microsoft`, `admin`, `panel`, `dashboard`, `signin`, `signup`

**Pattern groups:**
| Pattern Group | Keywords |
|---|---|
| Defacement | `hacked`, `defaced`, `deface` |
| Phishing | `phish`, `fake`, `spoof` |
| Malware | `malware`, `virus`, `trojan`, `worm`, `bot` |
| Betting | `bet`, `casino`, `poker`, `gamble`, `slots`, `bingo` |

### Blocklist Sources (live threat intelligence)

Loaded on startup when `LOAD_BLOCKLISTS_ON_STARTUP=true` and MongoDB is configured:

| Source | Env Var | Feed Type |
|---|---|---|
| URLhaus (abuse.ch) | `URLHAUS_API_URL` | Malware distribution URLs |
| PhishTank | `PHISHTANK_API_URL` | Verified phishing URLs |
| Spamhaus DROP | `SPAMHAUS_API_URL` | Known bad IP ranges |

### Domain Cache

- **TTL:** `DOMAIN_CACHE_TTL` env var (default: 30 days)
- **Layers:** In-memory `dict` + MongoDB `domain_cache` collection
- Stale MongoDB entries are pruned automatically

---

## Behavioral Bot Detection

Built entirely in-memory inside `backend/main.py`. No external model required.

### Sliding Window

- Last **20 requests** tracked per client IP (`deque(maxlen=20)`)
- Records: `timestamp`, `endpoint`, `method`, `request_hash`
- Background task `analyze_bot_behavior(ip)` fires on every `/analyze` call

### Scoring Heuristics

| Condition | Score Bump |
|---|---|
| Request rate > 2.0 req/s | +0.35 |
| Timing interval variance < 0.05 (robot cadence) | +0.30 |
| All requests hit the same endpoint | +0.20 |
| Request repetition ratio > 0.80 | +0.15 |

Minimum 10 samples required before scoring. Score capped at 1.0.

- Score **> 0.5** → stored in `bot_alerts[ip]`, injected into fusion as `bot_activity_score`
- Score **< 0.2** → alert cleared

---

## API Endpoints

Base URL (local): `http://localhost:8000`
All requests proxied through Next.js `/api/*` rewrite in production.

### `POST /analyze` — Unified (Recommended)

Accepts URL, raw HTTP request, or both. Returns a full `ComprehensiveThreatReport`.

**Request:**
```json
{
  "url": "https://example.com/login",
  "raw_request": "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"admin' OR '1'='1\"}",
  "network_flow_features": [0.5, 1.2, 0.0, ...]
}
```

**Response — `ComprehensiveThreatReport`:**
```json
{
  "url": "https://example.com/login",
  "domain": "example.com",
  "threat_scores": {
    "url_threat_score": 0.0,
    "traffic_anomaly_score": 0.0,
    "bot_activity_score": 0.0,
    "payload_threat_score": 0.95,
    "domain_intel_score": 0.0,
    "is_api_request": true,
    "overall_threat_score": 0.91
  },
  "model_details": {
    "model4_classification": "normal",
    "model4_confidence": 0.87,
    "traffic_anomaly_detected": false,
    "bot_activity_detected": false,
    "payload_attack_detected": true,
    "payload_threat_type": "SQL Injection",
    "is_api_request": true,
    "domain_heuristic_flags": []
  },
  "overall_verdict": "Dangerous",
  "recommendation": "Block immediately",
  "passes_domain_filter": true,
  "blocked_reason": null,
  "from_cache": false,
  "request_type": "API"
}
```

### `POST /predict` — Legacy Single Request

```json
// Request
{ "raw_request": "GET /admin' OR '1'='1 HTTP/1.1" }

// Response
{
  "raw_request": "...",
  "anomaly_score": -0.234,
  "prediction": "Suspicious",
  "threat_type": "SQL Injection",
  "features": {
    "request_length": 35, "url_depth": 1, "param_count": 0,
    "special_char_count": 5, "shannon_entropy": 3.45,
    "sql_keyword_score": 2, "script_tag_score": 0
  }
}
```

### `POST /predict/batch` — CSV Batch Upload

Submit a CSV with a `request` column. Returns `List[PredictResponse]`.

### `POST /predict-url` — Legacy URL Analysis

```json
// Request
{ "url": "https://suspicious-login-verify.xyz" }
```

### `GET /logs?limit=100` — Request History

Returns up to 100 recent `LogEntry` records. Persisted to MongoDB (primary) or `data/request_logs.json` (fallback).

### `GET /stats` — Aggregate Statistics

```json
{ "total_scanned": 1420, "normal_count": 1310, "suspicious_count": 110, "model_status": "loaded" }
```

### `GET /health` — Health Check

```json
{ "status": "ok", "model_loaded": true, "version": "1.0.0" }
```

---

## Tech Stack

### Backend

| Category | Technology |
|---|---|
| Language | Python 3.10+ |
| Framework | FastAPI + uvicorn[standard] |
| ML — Base | scikit-learn (IsolationForest, RandomForest, StandardScaler) |
| ML — Remote | HuggingFace Spaces (M1/M2/M4) via httpx |
| Data | Pandas, NumPy |
| HTTP | httpx (async, connection pool: 20 max / 10 keepalive) |
| Database | MongoDB via motor (async driver) |
| Auth | Firebase (frontend-side only; backend trusts Firebase-issued tokens) |
| Serialization | joblib |
| Config | python-dotenv |
| Deployment | Render |

### Frontend

| Category | Technology |
|---|---|
| Framework | Next.js 16.1.6 |
| UI Library | React 19.2.3 |
| Language | TypeScript 5 |
| Styling | Tailwind CSS 4 |
| HTTP | axios 1.13.5 |
| Auth | Firebase 11.10.0 (Google OAuth, Email/Password, Phone OTP) |
| Animation | framer-motion 12.34.3 |
| Icons | lucide-react 0.575.0 |
| 3D | @splinetool/react-spline 4.1.0 |
| Utilities | clsx, tailwind-merge |
| Deployment | Vercel |

---

## Project Structure

```
CyHub/
├── backend/
│   ├── main.py                       # FastAPI app, all endpoints, startup/shutdown hooks
│   ├── requirements.txt
│   ├── src/
│   │   ├── feature_engineering.py    # 7-feature extraction, FEATURE_COLUMNS, entropy
│   │   ├── model4_features.py        # extract_model4_features() helper
│   │   ├── multi_predict.py          # Model router, shared httpx client, M1/M2/M3 HF calls
│   │   ├── threat_engine.py          # 5-signal fusion, verdict logic, ComprehensiveThreatReport
│   │   ├── domain_intelligence.py    # URL pre-filter, DNS, heuristics, Model 4, blocklists
│   │   ├── predict.py                # Legacy single-model predict (base IsolationForest)
│   │   ├── train_model.py            # IsolationForest training script
│   │   └── visualize.py              # Anomaly score distribution plots
│   ├── models/
│   │   └── isolation_forest.pkl      # Serialized trained model
│   └── data/
│       ├── normal_traffic.csv        # Benign training samples
│       ├── test_traffic.csv          # Evaluation samples
│       └── request_logs.json         # Disk fallback for logs (when MongoDB unavailable)
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx            # Root layout, AuthProvider
│   │   │   ├── page.tsx              # Dashboard (protected, auth-gated)
│   │   │   ├── login/page.tsx        # Firebase auth page
│   │   │   └── about/page.tsx        # System explainer page
│   │   ├── components/
│   │   │   ├── navigation.tsx        # Responsive nav bar (hamburger on mobile)
│   │   │   ├── footer.tsx            # Shared footer (CyHub × CyperPox branding)
│   │   │   ├── dashboard/
│   │   │   │   ├── hero-section.tsx      # Landing hero with Spline 3D
│   │   │   │   ├── request-analyzer.tsx  # Primary analyzer (URL + HTTP textarea)
│   │   │   │   ├── batch-upload.tsx      # CSV batch upload + results table
│   │   │   │   ├── stats-overview.tsx    # Stats cards (total, normal, suspicious)
│   │   │   │   └── request-logs.tsx      # Request log table with pagination
│   │   │   └── ui/
│   │   │       ├── animated-state-icons.tsx  # Verdict icons (Safe/Caution/etc)
│   │   │       ├── card.tsx                  # shadcn/ui card primitives
│   │   │       ├── splite.tsx                # Spline 3D component wrapper
│   │   │       ├── spotlight.tsx             # Background spotlight effect
│   │   │       └── spotlight-cursor.tsx      # Cursor spotlight effect
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx        # Firebase auth state (user, signOut, loading)
│   │   └── lib/
│   │       ├── api.ts                 # All API calls (analyzeRequest, fetchLogs, etc.)
│   │       ├── types.ts               # TypeScript types (ComprehensiveThreatReport, etc.)
│   │       └── firebase.ts            # Firebase client initialization
│   ├── package.json
│   └── next.config.ts                 # /api/* → backend proxy rewrite
│
├── LICENSE.md
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+, npm
- Firebase project (for authentication)
- MongoDB Atlas account (optional — system works without it)

### Backend Setup

```bash
git clone https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track.git
cd CyHub/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The server will be available at `http://localhost:8000`. Interactive API docs at `http://localhost:8000/docs`.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` in your browser.

### Quick Start (both services)

```bash
# Terminal 1 — Backend
cd backend && uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend && npm run dev
```

---

## Environment Variables

### Backend — `backend/.env`

```env
# HuggingFace model endpoints
HF_MODEL1_URL=https://bhavyasoni21-model1.hf.space/predict
HF_MODEL2_URL=https://bhavyasoni21-model2.hf.space/predict
HF_MODEL3_URL=https://bhavyasoni21-model3.hf.space/predict
HF_MODEL4_URL=https://bhavyasoni21-model4.hf.space/predict

# HuggingFace timeouts (seconds)
HF_MODEL1_TIMEOUT=8.0
HF_MODEL2_TIMEOUT=8.0
HF_MODEL3_TIMEOUT=8.0
HF_MODEL4_TIMEOUT=8.0

# Optional: HuggingFace API token
HF_API_TOKEN=

# MongoDB (optional — system works without it, falls back to in-memory + disk)
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/cyhub

# Load live threat intelligence blocklists on startup (requires MongoDB)
LOAD_BLOCKLISTS_ON_STARTUP=true

# CORS (default: http://localhost:3000)
CORS_ORIGINS=http://localhost:3000,https://your-production-domain.vercel.app

# Domain intel
WHITELIST_DOMAINS=your-internal-domain.com,another.internal.io
DOMAIN_CACHE_TTL=2592000
DNS_VALIDATION_TIMEOUT=5.0

# Model path
MODEL_PATH=models/isolation_forest.pkl
```

### Frontend — `frontend/.env.local`

```env
NEXT_PUBLIC_API_URL=http://localhost:8000

NEXT_PUBLIC_FIREBASE_API_KEY=your-firebase-api-key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
```

---

## Frontend Pages & Components

### Pages

| Route | Description |
|---|---|
| `/` | **Dashboard** — protected (auth redirect). Hero section, stats cards, request analyzer, batch upload, and request logs. |
| `/login` | **Authentication** — Firebase email/password, Google OAuth, Phone OTP. Dark-themed UI with animated inputs. |
| `/about` | **System Explainer** — problem statement, solution overview, how-it-works step-by-step, full tech stack grid. |

### Key Components

| Component | Description |
|---|---|
| `RequestAnalyzer` | Dual input: URL field + raw HTTP textarea. Submits to `/analyze`. Displays `ComprehensiveThreatReport` with per-model score bars, verdict badge, and threat type. |
| `BatchUpload` | CSV file upload to `/predict/batch`. Shows results table with per-row predictions. |
| `StatsOverview` | Cards showing total scanned, normal count, suspicious count, model status. Polls `/stats`. |
| `RequestLogs` | Paginated table of recent requests from `/logs`. Sortable by verdict. |
| `HeroSection` | Full-width hero with Spline 3D embed, headline, and CTA. |
| `Navigation` | Responsive nav bar — full links on desktop, hamburger menu on mobile. Shows logged-in user email. |
| `Footer` | Shared footer — CyHub × CyperPox branding, nav links, tech pills, GitHub/live demo links, "All Rights Reserved". |
| `AnimatedStateIcons` | SVG icons for each verdict state: Safe / Caution / Suspicious / Dangerous / Blocked. |

### Authentication Flow

1. User visits `/` → no auth → redirect to `/login`
2. Login via Firebase (email, Google, or phone)
3. `AuthContext` stores `user` object
4. Dashboard loads with full access
5. Logout clears Firebase session → redirect to `/login`

---

## Detection Capabilities

| Threat Type | Primary Signal | Supporting Signal |
|---|---|---|
| SQL Injection | Heuristic `sql_keyword_score` | M1 HuggingFace payload model |
| XSS / Script Injection | Heuristic `script_tag_score` | M1 confirmation |
| Path Traversal | `../`, `%2e%2e`, `%2f` pattern match | M1 if API request |
| Bot Activity | In-memory behavioral analysis (timing, repetition) | M2 HuggingFace bot model |
| Traffic Anomaly | M3 RandomForest (35 flow features) | Behavioral rate analysis |
| Malware Domains | M4 URL classifier | URLhaus blocklist |
| Phishing Domains | M4 URL classifier | PhishTank blocklist |
| Adult / Betting Content | M4 URL classifier | Domain pattern heuristics |
| Zero-Day / Unknown | Base IsolationForest anomaly score | Entropy + structural deviation |
| Obfuscated Payloads | Shannon entropy spike | Special character density |

---

## Deployment

### Backend → Render

1. Push to `main` — Render auto-deploys from GitHub
2. Set all env vars in Render dashboard (see [Backend Env Vars](#backend--backendenv))
3. **Start command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Render will load HF models, ping MongoDB, and start blocklist fetchers on startup

### Frontend → Vercel

1. Import GitHub repo in Vercel
2. Set all `NEXT_PUBLIC_FIREBASE_*` env vars in Vercel project settings
3. Add your Vercel production domain to Firebase → Authentication → **Authorized Domains**
4. Vercel auto-deploys on every push to `main`

### Firebase Authentication Setup

1. Go to [Firebase Console](https://console.firebase.google.com) → Create project
2. Navigate to **Authentication** → **Sign-in method**
3. Enable: **Email/Password**, **Google**, **Phone**
4. Under **Authorized Domains**, add your Vercel deployment URL
5. Copy config values from **Project Settings** into `frontend/.env.local`

---

## Future Roadmap

- [x] Multi-model pipeline (M1–M4 + Domain Intel)
- [x] 5-signal fusion engine with adaptive weights
- [x] Behavioral in-memory bot detection
- [x] Live threat intelligence (URLhaus, PhishTank, Spamhaus)
- [x] MongoDB-optional architecture
- [x] Firebase authentication (Google, Email, Phone OTP)
- [x] Batch CSV analysis
- [x] Production deployment (Render + Vercel)
- [ ] User-specific detection history (per-UID MongoDB scoping)
- [ ] Advanced analytics dashboard (time-series, attack heatmaps)
- [ ] Deep learning sequence modeling (LSTM / Transformer for payload analysis)
- [ ] Email / webhook alert notifications
- [ ] Rate limiting and API key management
- [ ] Docker + Docker Compose for local full-stack setup
- [ ] NGINX middleware integration
- [ ] Automated model retraining pipeline (cron + new labeled data)
- [ ] MITRE ATT&CK framework mapping for detected threats

---

## Contributing

Contributions are welcome. Please open an issue first to discuss major changes, then submit a Pull Request.

---

## License

MIT License — see [LICENSE](LICENSE.md) for details.

---

© 2024 CyHub × CyperPox — All rights reserved.
Built for the HackNova CyberTech Track.
