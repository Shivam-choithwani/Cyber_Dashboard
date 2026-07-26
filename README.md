<<<<<<< HEAD

=======
# 🛡️ E-Commerce & Real-Time Cyber Security Dashboard Platform

An enterprise-grade, real-time Cyber Security Ingestion & Anomaly Detection Platform coupled with a modular FastAPI E-Commerce application. The platform continuously monitors HTTP traffic, analyzes request payloads and execution profiles using **Scikit-Learn Machine Learning models (`IsolationForest`, `LogisticRegression`)**, **Welford's streaming statistical latency algorithms**, **windowed rate aggregators**, and **regex signature matchers**, streaming real-time threat alerts to a modern React-based administration dashboard over WebSockets.

---

## 📖 Documentation Quick Links

* 📊 **[SCHEMA.md](file:///c:/Users/Shivam/OneDrive/Documents/Desktop/cyber_security/SCHEMA.md)** — Complete Database Schemas, Entity Relationship Diagrams (ERDs), column constraints, PostgreSQL indexes, and JSON telemetry contracts.
* 🤖 **[ML_README.md](file:///c:/Users/Shivam/OneDrive/Documents/Desktop/cyber_security/ML_README.md)** — Detailed Machine Learning documentation, Isolation Forest math, Logistic Regression feature vectors, Welford Z-score formulas, and hot-reload model loaders.

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    subgraph Client Layer
        User[User / Attack Simulator]
        DashboardUser[Security Analyst]
    end

    subgraph E-Commerce Microservice [Port 8000]
        API[FastAPI App Core]
        Middleware[HTTP Telemetry Tracing Middleware]
        EcomDB[(PostgreSQL / SQLite: e_commerce)]
        API --> EcomDB
        API <--> Middleware
    end

    subgraph Messaging & Ingestion Layer
        Kafka[Apache Kafka KRaft Broker :9092]
        SocketFallback[Direct TCP Socket Ingestion / DB Poll]
        Middleware -->|Stream Events| Kafka
        Middleware -.->|Fallback| SocketFallback
    end

    subgraph Cyber Security Ingestion & Detection [Port 8001]
        IngestionAPI[FastAPI Ingestion Server]
        AnomalyDetector[Signature & Stat Anomaly Engine]
        WSManager[WebSocket Manager]
        CyberDB[(PostgreSQL / SQLite: cyber_security)]
        
        Kafka --> IngestionAPI
        SocketFallback --> IngestionAPI
        IngestionAPI --> AnomalyDetector
        IngestionAPI --> CyberDB
        AnomalyDetector --> CyberDB
        AnomalyDetector --> WSManager
    end

    subgraph Threat Pipeline Micro-Consumers & ML Engine
        ModelFiles[(trained models/*.pkl)]
        ConsumerDDoS[Volumetric DDoS Consumer]
        ConsumerFraud[Checkout Fraud Consumer - ML LogisticReg]
        ConsumerBehavioral[Behavioral Anomaly Consumer - ML IsolationForest]
        
        ModelFiles --> ConsumerFraud
        ModelFiles --> ConsumerBehavioral
        Kafka --> ConsumerDDoS
        Kafka --> ConsumerFraud
        Kafka --> ConsumerBehavioral
        ConsumerDDoS --> CyberDB
        ConsumerFraud --> CyberDB
        ConsumerBehavioral --> CyberDB
    end

    subgraph Web Frontend [Port 5173]
        ReactApp[React + Vite + Tailwind Console]
        WSManager -->|Live WebSockets| ReactApp
        DashboardUser <--> ReactApp
    end

    User --> API
```

---

## ✨ Key System Features

* **Real-Time HTTP Telemetry Middleware**: Intercepts every inbound request to collect trace IDs, HTTP methods, paths, status codes, query strings, headers, user agents, response latencies, and user session identifiers without blocking request handling.
* **Resilient Messaging Pipeline**: Built on Apache Kafka (KRaft mode). Automatically degrades to direct TCP socket streaming (`port 9092`) or database polling if Kafka is unavailable.
* **Scikit-Learn Machine Learning Engine**:
  * 🌲 **Isolation Forest (`IsolationForest`)**: Unsupervised anomaly detection on 4D feature vectors `[latency_avg, latency_std, error_rate, path_variety]` to isolate zero-day threats.
  * 🎯 **Logistic Regression (`LogisticRegression`)**: Supervised fraud classification on checkout order velocity, transaction amount spikes, and customer historical averages.
  * 🔥 **Dynamic Model Hot-Reloading**: Automatically detects updated `.pkl` model files on disk (`os.path.getmtime`) and reloads them in-memory without server downtime.
  * 🔄 **Dual Execution Fallback**: Falls back seamlessly to rule-based heuristics if model binary `.pkl` files are not present.
* **Streaming Statistical Latency Engine**: Implements **Welford's Algorithm** to calculate running mean $\mu$ and variance $\sigma^2$ per route in $O(1)$ constant time, flagging latency anomalies with a statistical threshold ($Z\text{-score} > 3.5$).
* **Volumetric & Signature Inspection**:
  * Detects Directory Fuzzing / Path Scanning (e.g., 10+ 404 responses within 15s) and Authentication Brute-Force attacks (e.g., 5+ failed logins within 30s).
  * Volumetric DDoS sliding window request rate counter ($\ge 30$ req/10s).
  * Regex signature matching for SQL Injection (`UNION SELECT`, `' OR 1=1`), XSS (`<script>`, `onerror=`), and security scanners (`sqlmap`, `nikto`, `gobuster`).
* **Live WebSocket Broadcast**: Instant streaming of log events, latency profiles, threat alerts, and system metrics to the React frontend console.

---

## 🚨 Threat Detection Rules & Severity Matrix

| Anomaly Type | Category | Severity | Engine / Detection Logic |
| :--- | :--- | :--- | :--- |
| `BEHAVIORAL_ANOMALY` | Machine Learning | `HIGH` | **Isolation Forest ML Model** decision threshold outlier detection |
| `CHECKOUT_FRAUD` | Machine Learning | `HIGH` | **Logistic Regression ML Model** order velocity & price anomaly probability |
| `SQL_INJECTION` | Payload Signature | `CRITICAL` | URL/query regex matching `UNION SELECT`, `INSERT INTO`, `--`, `OR 1=1`, `xp_cmdshell` |
| `XSS` | Payload Signature | `CRITICAL` | Script tag, `javascript:`, `onerror=`, `onload=`, or `<iframe>` in query or path |
| `SUSPICIOUS_AGENT` | Header Signature | `HIGH` | User-Agent match against security scanners (`sqlmap`, `nikto`, `dirbuster`, `nmap`) |
| `PATH_FUZZING` | Behavioral Window | `HIGH` | Cumulative count of $404\text{ Not Found}$ status codes $\ge 10$ from an IP within 15s |
| `BRUTE_FORCE_AUTH` | Behavioral Window | `HIGH` | Failed auth requests ($401\text{ Unauthorized}$) $\ge 5$ from an IP within 30s |
| `VOLUMETRIC_DDOS` | Traffic Velocity | `CRITICAL` | Request volume from single IP $\ge 30$ requests within a 10s sliding window |
| `HIGH_LATENCY` | Statistical | `MEDIUM` | Response time exceeds statistical norm ($Z\text{-score} = \frac{\text{latency} - \mu}{\sigma} > 3.5$) |

---

## 📁 Repository Structure

```
cyber_security/
├── docker-compose.yml              # Complete multi-container deployment orchestration
├── test_telemetry.py               # Live attack simulator & telemetry generator
├── README.md                       # Master platform documentation
├── SCHEMA.md                       # Database schema & ERD specifications
├── ML_README.md                    # Machine Learning architecture & algorithms guide
├── cyber_dashboard/                # Cyber Security Ingestion & Dashboard System
│   ├── docker-compose.yml          # Container configuration for cyber stack
│   ├── backend/
│   │   ├── train_models.py         # Scikit-Learn Model Training Script (Isolation Forest & Logistic Regression)
│   │   ├── models/                 # Saved ML binary artifacts (.pkl files)
│   │   │   ├── anomaly/model.pkl   # Isolation Forest trained model binary (~1.0 MB)
│   │   │   └── fraud/model.pkl     # Logistic Regression trained model binary (~703 B)
│   │   ├── api/
│   │   │   ├── app.py              # Ingestion REST & WebSocket Server (Modular Mode)
│   │   │   └── routes/             # Feature routes (anomaly.py, ddos.py, fraud.py)
│   │   ├── consumers/              # Isolated threat detection consumers
│   │   │   ├── anomaly/consumer.py # Behavioral anomaly ML worker
│   │   │   ├── ddos/consumer.py    # Volumetric DDoS consumer worker
│   │   │   └── fraud/consumer.py   # Checkout fraud ML worker
│   │   ├── db/
│   │   │   ├── db.py               # PostgreSQL connection & table initializer
│   │   │   └── schema.sql          # Relational DB DDL schema
│   │   ├── anomaly_detector.py     # Core detection rules & Welford statistical algorithms
│   │   ├── consumer.py             # Kafka & socket stream consumer helper
│   │   ├── main.py                 # Standalone API server (SQLite mode)
│   │   ├── Dockerfile              # Backend container file
│   │   └── requirements.txt        # Python dependencies (scikit-learn, numpy, fastapi, etc.)
│   └── frontend/
│       ├── src/                    # React dashboard application
│       │   ├── App.jsx             # Main dashboard layout & WebSocket listener
│       │   ├── components/         # Security widgets, traffic charts, alert logs
│       │   └── index.css           # Styling system & dark mode aesthetics
│       ├── package.json            # Node dependencies & scripts
│       └── Dockerfile              # Frontend container file
└── e_commerce/                     # E-Commerce Application Service
    ├── verify_endpoints.py         # End-to-end API test suite
    └── backend/
        ├── app/
        │   ├── middleware/
        │   │   └── http_tracing.py # Telemetry middleware producer
        │   ├── routes/             # Auth, Product, Cart, Order, Review endpoints
        │   ├── models/             # SQLAlchemy ORM schemas
        │   └── telemetry/          # Kafka streaming logic
        ├── main.py                 # E-Commerce FastAPI entrypoint
        └── requirements.txt        # E-Commerce dependencies
```

---

## ⚙️ Prerequisites & Environment Setup

### Software Requirements
* **Python**: 3.12 or higher
* **Node.js**: v18.0 or higher
* **PostgreSQL**: 15.0+ (for modular / production deployment)
* **Docker & Docker Compose**: (Optional, recommended for quick start)

### Key Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://postgres:2003@localhost:5432/cyber_security` | Connection string for PostgreSQL |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker bootstrap servers |
| `SECRET_KEY` | `supersecretkey` | JWT authentication key for E-Commerce API |

---

## 🚀 Running the Platform

Choose one of three deployment modes depending on your setup:

### Option 1: Docker Compose Stack (Easiest & Complete)

Launches PostgreSQL, Kafka KRaft, Kafka-UI, PgAdmin, DB Initialization, Ingestion API, 3 Micro-Consumers (with ML models), and the React Frontend with a single command:

```bash
cd cyber_dashboard
docker compose up --build
```

#### Service Endpoints Access Matrix:
* 📺 **Security Dashboard Console**: [http://localhost:5173](http://localhost:5173)
* ⚡ **Cyber Security Ingestion API**: [http://localhost:8001](http://localhost:8001) / Docs: [http://localhost:8001/docs](http://localhost:8001/docs)
* 📊 **Kafka UI Dashboard**: [http://localhost:8080](http://localhost:8080)
* 🗄️ **PgAdmin Database Manager**: [http://localhost:5050](http://localhost:5050) (`admin@cyber.com` / `admin`)

---

### Option 2: Modular Local Development Mode

#### Step 1: Initialize Database
```powershell
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
python .\cyber_dashboard\backend\db\db.py
```

#### Step 2: Train Machine Learning Models
Train and generate the Scikit-Learn `.pkl` model binaries:
```powershell
python .\cyber_dashboard\backend\train_models.py
```

#### Step 3: Start E-Commerce Backend (Port 8000)
```powershell
cd .\e_commerce\backend
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/e_commerce"
$env:SECRET_KEY="supersecretkey"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

#### Step 4: Start Cyber Ingestion Backend (Port 8001)
```powershell
cd .\cyber_dashboard\backend
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
python -m uvicorn api.app:app --host 127.0.0.1 --port 8001
```

#### Step 5: Launch Pipeline Micro-Consumers (Separate Terminals)
```powershell
# 1. Behavioral Anomaly Consumer (Runs Isolation Forest ML Inference)
python .\cyber_dashboard\backend\consumers\anomaly\consumer.py

# 2. Volumetric DDoS Consumer (Runs Sliding Window Rate Engine)
python .\cyber_dashboard\backend\consumers\ddos\consumer.py

# 3. Checkout Fraud Consumer (Runs Logistic Regression ML Inference)
python .\cyber_dashboard\backend\consumers\fraud\consumer.py
```

#### Step 6: Start React Frontend (Port 5173)
```powershell
cd .\cyber_dashboard\frontend
npm install
npm run dev
```

---

### Option 3: Standalone Zero-Dependency Mode (SQLite)

Runs the ingestion backend with SQLite (`cyber_dashboard.db`) and an embedded anomaly detector in a background thread—no external services needed:

```powershell
cd .\cyber_dashboard\backend
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

In a separate terminal, start the React frontend:
```powershell
cd .\cyber_dashboard\frontend
npm run dev
```

---

## 🧪 Testing & Live Attack Simulation

### 1. E-Commerce Smoke Verification
Verify all e-commerce REST endpoints (Users, Products, Cart, Orders, Reviews):
```powershell
python .\e_commerce\verify_endpoints.py
```

### 2. Live Attack Simulation Suite
Execute simulated traffic including clean baseline traffic, SQL Injection, XSS scripts, Failed Login Brute Force, and Directory Fuzzing:
```powershell
python .\test_telemetry.py
```

#### Simulation Attack Matrix Executed:
1. **Normal Traffic**: Standard `GET /` requests.
2. **SQL Injection**: `GET /products/slug/test-product?q=%27%20UNION%20SELECT%20username,password%20FROM%20users%20--`
3. **XSS Script Attack**: `GET /products/slug/test-product?search=%3Cscript%3Ealert(%27HACKED%27)%3C/script%3E`
4. **Brute Force Login**: 5 rapid failed `POST /auth/login` requests.
5. **Path Directory Scanning**: 12 rapid requests to unmapped paths (`/admin-portal`, `/wp-login.php`, `/.env`, etc.).

Watch the dashboard at [http://localhost:5173](http://localhost:5173) update in real-time as WebSocket alert events flash on screen!

---

## 🤖 Machine Learning Retraining Workflow

To retrain the Machine Learning models on newly collected production traffic vectors:

1. Live HTTP traffic feature vectors are automatically saved to PostgreSQL tables `anomaly_feature_windows` and `fraud_feature_windows`.
2. Run the training script:
   ```powershell
   python .\cyber_dashboard\backend\train_models.py
   ```
3. The script outputs fresh `.pkl` files to `cyber_dashboard/backend/models/`.
4. Active consumer workers automatically detect the updated `.pkl` timestamps and reload the models in memory without requiring a service restart!

---

## 📝 API Endpoints Summary

### E-Commerce API (`http://localhost:8000`)
* `POST /auth/register` — Register a new user account
* `POST /auth/login` — Authenticate and retrieve JWT token
* `GET /products` — List product catalog
* `GET /products/slug/{slug}` — Product details lookup
* `POST /cart/items` — Add product to cart
* `POST /orders/checkout` — Finalize cart checkout & process order
* `POST /reviews` — Submit product review

### Cyber Security API (`http://localhost:8001`)
* `POST /ingest` — Manual HTTP telemetry ingestion endpoint
* `GET /events` — Fetch ingested log events with pagination
* `GET /anomalies` — Fetch detected security anomalies and threat alerts
* `GET /stats/summary` — Overview metrics (total logs, anomaly count, attack breakdown)
* `GET /stats/latency` — Route latency averages and variance statistics
* `WS /ws` — Real-time WebSocket connection for live telemetry & alert streaming

---

## 📄 License

This project is open-source and available under the **MIT License**.
>>>>>>> c2d7a36 (Add ML models, training engine, and platform documentation)
