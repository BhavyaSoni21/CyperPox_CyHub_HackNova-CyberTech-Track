# CyHub — AI-Driven Web Anomaly Detection System

> An unsupervised machine learning system that detects injection attacks, bot activity, and zero-day threats by modeling normal web request behavior and identifying statistical deviations.

---

## Problem Statement

Modern web applications are increasingly vulnerable to injection attacks, malicious automated bots, and zero-day threats. Traditional security systems rely on static signatures and predefined rules, which fail to detect novel or obfuscated attack patterns. As attackers continuously evolve techniques using encoding, payload obfuscation, and adaptive behavior, signature-based detection becomes insufficient.

This project proposes an **AI-driven anomaly detection system** that models normal web request behavior and identifies statistical deviations using unsupervised machine learning. By learning baseline traffic patterns, the system can detect injection attempts, suspicious request structures, and previously unseen zero-day threats — **without relying on predefined attack signatures**.

---

## Tech Stack

| Category          | Technology                          |
|-------------------|-------------------------------------|
| Language          | Python 3.10+                        |
| Data Processing   | Pandas, NumPy                       |
| Machine Learning  | scikit-learn (IsolationForest, StandardScaler) |
| Visualization     | Matplotlib, Seaborn                 |
| Optional UI       | Streamlit *(if time permits)*       |

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
AyushLink/
│
├── data/
│   ├── normal_traffic.csv       # Benign request samples for training
│   └── test_traffic.csv         # Mixed requests for evaluation
│
├── src/
│   ├── feature_engineering.py   # Converts raw requests to feature vectors
│   ├── train_model.py           # Trains and saves the Isolation Forest model
│   ├── predict.py               # Loads model and scores new requests
│   └── visualize.py             # Plots anomaly score distributions
│
├── models/
│   └── isolation_forest.pkl     # Serialized trained model
│
├── app.py                       # Streamlit UI (optional)
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites

```bash
Python 3.10+
```

### Installation

```bash
git clone https://github.com/your-username/AyushLink.git
cd AyushLink
pip install -r requirements.txt
```

### Train the Model

```bash
python src/train_model.py
```

### Run Predictions

```bash
python src/predict.py --input data/test_traffic.csv
```

### Launch Streamlit UI *(optional)*

```bash
streamlit run app.py
```

---

## Requirements

```
pandas
numpy
scikit-learn
matplotlib
seaborn
streamlit
```

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

- [ ] Deep learning-based sequence modeling (LSTM / Transformer encoder)
- [ ] Real-time traffic ingestion pipeline
- [ ] Containerized deployment with Docker
- [ ] API gateway integration (NGINX / Apache middleware)
- [ ] Dashboard with live anomaly alerts

---

## License

MIT License — see [LICENSE](LICENSE) for details.
