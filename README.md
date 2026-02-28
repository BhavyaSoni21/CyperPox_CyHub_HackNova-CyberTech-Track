# CyHub — AI-Driven Web Anomaly Detection System

> An unsupervised machine learning system that detects injection attacks, bot activity, and zero-day threats by modeling normal web request behavior and identifying statistical deviations.

🌐 **Live Demo:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)

---

## Problem Statement

Modern web applications are increasingly vulnerable to injection attacks, malicious automated bots, and zero-day threats. Traditional security systems rely on static signatures and predefined rules, which fail to detect novel or obfuscated attack patterns. As attackers continuously evolve techniques using encoding, payload obfuscation, and adaptive behavior, signature-based detection becomes insufficient.

This project proposes an **AI-driven anomaly detection system** that models normal web request behavior and identifies statistical deviations using unsupervised machine learning. By learning baseline traffic patterns, the system can detect injection attempts, suspicious request structures, and previously unseen zero-day threats — **without relying on predefined attack signatures**.

---

## ✨ Features

- 🤖 **AI-Powered Detection** — Isolation Forest model for unsupervised anomaly detection
- 🎯 **Real-Time Analysis** — Instant threat scoring for incoming HTTP requests
- 📊 **Interactive Dashboard** — Beautiful UI with stats overview and request logs
- 🔐 **Secure Authentication** — Supabase-powered login with Google OAuth and email/password
- 📈 **Request Analyzer** — Test any HTTP request and get immediate threat assessment
- 🌐 **About Page** — Comprehensive explanation of the problem and solution
- 🚀 **Production Ready** — Deployed on Render (backend) and Vercel (frontend)

---

## Tech Stack

### Backend
| Category          | Technology                          |
|-------------------|-------------------------------------|
| Language          | Python 3.10+                        |
| Framework         | FastAPI                             |
| Data Processing   | Pandas, NumPy                       |
| Machine Learning  | scikit-learn (IsolationForest, StandardScaler) |
| Visualization     | Matplotlib, Seaborn                 |
| Deployment        | Render                              |

### Frontend
| Category          | Technology                          |
|-------------------|-------------------------------------|
| Framework         | Next.js 16                          |
| Language          | TypeScript                          |
| UI Library        | React 19                            |
| Styling           | Tailwind CSS                        |
| 3D Graphics       | Spline                              |
| Authentication    | Supabase (Google OAuth, Email/Password) |
| Deployment        | Vercel                              |

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
| `special_char_count` | Count of characters: `' " ; < > = % ( ) -` |
| `shannon_entropy` | Shannon entropy of the full request string — measures randomness/unpredictability |

#### Semantic Risk Indicators
| Feature | Description |
|---|---|
| `sql_keyword_score` | Presence score of SQL keywords: `SELECT`, `DROP`, `UNION`, `INSERT`, `OR`, `AND` |
| `script_tag_score` | Presence score of script injection patterns: `<script>`, `onerror`, `javascript:`, etc. |

These **6–7 features** form the input vector for the anomaly detection model.

---

### 2. ML Model — Isolation Forest

The model is trained **exclusively on normal traffic**, making it inherently unsupervised and signature-free.

```
Algorithm    : Isolation Forest
Training Set : Normal (benign) HTTP requests only
Contamination: ~0.05 (5% expected anomaly rate)
Scaler       : StandardScaler (zero mean, unit variance)
```

**How Isolation Forest detects anomalies:**
- Builds an ensemble of random decision trees
- Anomalous samples are isolated in fewer splits (shorter path length)
- A low anomaly score → suspicious / attack-like request
- A high anomaly score → normal benign request

---

### 3. Output

For every request processed, the system outputs:

| Field | Description |
|---|---|
| `anomaly_score` | Continuous score from the model (lower = more suspicious) |
| `prediction` | `Normal` or `Suspicious` classification label |

---

## Architecture & Pipeline

### High-Level Architecture

```
User Request
     ↓
Feature Extraction Engine
     ↓
Feature Vector
     ↓
Preprocessing (Scaling)
     ↓
Isolation Forest Model
     ↓
Anomaly Score
     ↓
Risk Classification
     ↓
Alert / Log
```

---

### Detailed Workflow

#### Step 1 — Data Collection
Collect normal web request samples representing legitimate baseline traffic. The model is trained exclusively on this benign data.

#### Step 2 — Feature Extraction
Convert each raw HTTP request string into a numerical feature vector covering structural, complexity, and semantic risk dimensions (see [How It Works](#how-it-works)).

#### Step 3 — Baseline Modeling
Train the Isolation Forest on only legitimate traffic. The model learns what "normal" looks like without ever seeing attack samples.

#### Step 4 — Detection Phase
For each incoming request:

```
Incoming Request → Feature Extraction → Scaling → Model Prediction → Score
```

#### Step 5 — Risk Decision

```python
if prediction == -1:
    # Flag as anomaly → trigger alert / log suspicious request
else:
    # Allow request → normal traffic
```

---

### Internal Pipeline Design

| Layer | Component | Responsibility |
|---|---|---|
| Layer 1 | **Input Parsing** | Receives raw HTTP request string |
| Layer 2 | **Feature Engineering Module** | Extracts the 6–7 numerical features |
| Layer 3 | **Feature Scaling** | Applies `StandardScaler` (zero mean, unit variance) |
| Layer 4 | **Anomaly Detection Model** | Isolation Forest scores the request |
| Layer 5 | **Risk Scoring Engine** | Converts raw score to `Normal` / `Suspicious` label |
| Layer 6 | **Logging & Alert System** | Records flagged requests with score, timestamp, and raw input |

---

## Project Structure

```
CyHub/
│
├── backend/
│   ├── data/
│   │   ├── normal_traffic.csv       # Benign request samples for training
│   │   └── test_traffic.csv         # Mixed requests for evaluation
│   │
│   ├── src/
│   │   ├── feature_engineering.py   # Converts raw requests to feature vectors
│   │   ├── train_model.py           # Trains and saves the Isolation Forest model
│   │   ├── predict.py               # Loads model and scores new requests
│   │   └── visualize.py             # Plots anomaly score distributions
│   │
│   ├── models/
│   │   └── isolation_forest.pkl     # Serialized trained model
│   │
│   ├── main.py                      # FastAPI backend server
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx             # Dashboard home page
│   │   │   ├── login/               # Authentication page
│   │   │   └── about/               # About page
│   │   │
│   │   ├── components/
│   │   │   ├── dashboard/           # Dashboard components
│   │   │   ├── ui/                  # Reusable UI components
│   │   │   └── navigation.tsx       # Navigation bar
│   │   │
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx      # Authentication context
│   │   │
│   │   └── lib/
│   │       ├── api.ts               # API client
│   │       ├── supabase.ts          # Supabase client
│   │       └── types.ts             # TypeScript types
│   │
│   ├── package.json
│   └── next.config.ts
│
├── render.yaml                      # Render deployment config
├── SUPABASE_SETUP.md               # Authentication setup guide
└── README.md
```

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **npm or yarn**
- **Supabase account** (for authentication)

### Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track.git
   cd CyHub/backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the model:**
   ```bash
   python src/train_model.py
   ```

4. **Start the FastAPI server:**
   ```bash
   uvicorn main:app --reload --port 8000
   ```

5. **API will be available at:** `http://localhost:8000`

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
   
   Create a `.env.local` file in the frontend directory:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8000
   NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
   ```

4. **Set up Supabase authentication:**
   
   Follow the detailed guide in [SUPABASE_SETUP.md](SUPABASE_SETUP.md) to:
   - Create a Supabase project
   - Get your credentials
   - Enable Google OAuth (optional)
   - Configure authentication providers

5. **Start the development server:**
   ```bash
   npm run dev
   ```

6. **Open your browser:** `http://localhost:3000`

### Quick Start (Both Services)

Run both backend and frontend simultaneously:

```bash
# Terminal 1 - Backend
cd backend
uvicorn main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

---

## Requirements

### Backend
```
fastapi
uvicorn
pandas
numpy
scikit-learn
matplotlib
seaborn
python-multipart
```

### Frontend
```
next
react
react-dom
typescript
tailwindcss
@supabase/supabase-js
@supabase/auth-ui-react
axios
framer-motion
lucide-react
@splinetool/react-spline
```

---

## 🚀 Deployment

### Backend (Render)
The backend is deployed on **Render** with automatic deployments from the main branch.

**Live API:** Check your Render dashboard for the URL

Configuration in `render.yaml`:
- Automatically trains model on startup
- Serves FastAPI endpoints
- Configured CORS for frontend access

### Frontend (Vercel)
The frontend is deployed on **Vercel** with automatic deployments from GitHub.

**Live App:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)

**Environment Variables Required on Vercel:**
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`

### Supabase Configuration
For production deployment:
1. Add your production URL to Site URL in Supabase
2. Update redirect URLs for OAuth providers
3. Configure email templates for production

---

## 🌐 API Endpoints

### POST `/predict`
Analyze a single HTTP request for anomalies.

**Request:**
```json
{
  "request": "GET /admin' OR '1'='1"
}
```

**Response:**
```json
{
  "request": "GET /admin' OR '1'='1",
  "anomaly_score": -0.234,
  "prediction": "Suspicious",
  "features": {
    "request_length": 23,
    "url_depth": 1,
    "param_count": 0,
    "special_char_count": 5,
    "shannon_entropy": 3.45,
    "sql_keyword_score": 2,
    "script_tag_score": 0
  }
}
```

### GET `/history`
Retrieve recent detection history (last 50 requests).

---

## 🎨 Application Pages

### Dashboard (`/`)
- **Hero Section** with 3D Spline visualization
- **Stats Overview** showing detection metrics
- **Request Analyzer** for manual testing
- **Request Logs** displaying recent detections

### Login (`/login`)
- Email/Password authentication
- Google OAuth sign-in
- Beautiful dark-themed UI
- Automatic redirect after login

### About (`/about`)
- Problem statement explanation
- Solution overview
- How it works (step-by-step)
- Technology stack showcase
- Feature highlights

---

## Detection Capabilities

| Threat Type | Detection Mechanism |
|---|---|
| SQL Injection | SQL keyword scoring + entropy spike |
| XSS / Script Injection | Script tag presence scoring |
| Path Traversal | URL depth anomaly + special char count |
| Obfuscated Payloads | Shannon entropy deviation |
| Zero-Day / Unknown Attacks | Statistical outlier via Isolation Forest |
| Automated Bot Requests | Structural feature deviation from baseline |

---

## Future Roadmap

- [x] Modern web UI with Next.js and React
- [x] User authentication with Supabase
- [x] Real-time request analysis API
- [x] Production deployment (Render + Vercel)
- [ ] User-specific detection history
- [ ] Advanced analytics dashboard
- [ ] Deep learning-based sequence modeling (LSTM / Transformer)
- [ ] Alert notifications (email/webhook)
- [ ] Rate limiting and API keys
- [ ] Containerized deployment with Docker
- [ ] API gateway integration (NGINX middleware)
- [ ] Automated model retraining pipeline

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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

- [Supabase Setup Guide](SUPABASE_SETUP.md) - Complete authentication configuration
- [API Documentation](http://localhost:8000/docs) - Interactive API docs (when running locally)

---

## 🔗 Links

- **Live Demo:** [https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app](https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app)
- **GitHub:** [Repository](https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track)
- **Backend API:** Check Render dashboard for endpoint

---

**Built with ❤️ by the CyperPox Team**
