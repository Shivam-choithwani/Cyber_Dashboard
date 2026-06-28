# E-Commerce & Cyber Security Dashboard Platform

This workspace contains a full-featured E-Commerce API coupled with a real-time Cyber Security Ingestion & Detection Dashboard. The system monitors HTTP traffic, detects various types of anomalies (volumetric DDoS, path fuzzing, brute-force logins, SQL Injection, XSS, and custom behavioral anomalies), and broadcasts real-time threat alerts to a React-based administration console.

---

## Workspace Structure

*   **`e_commerce/`**: A modular FastAPI e-commerce application.
    *   `backend/`: Contains the REST API, SQLAlchemy models, database migrations, and telemetry-producing middleware.
    *   `verify_endpoints.py`: End-to-end smoke test verifying all e-commerce routes.
*   **`cyber_dashboard/`**: The security monitoring dashboard.
    *   `backend/`: The ingestion API. Can run in modular mode (Postgres + separate pipelines) or standalone mode (SQLite + local detector).
    *   `frontend/`: React + Vite dashboard displaying log traffic, latency profiles, and security threat events over WebSockets.
*   **`test_telemetry.py`**: A traffic generator simulating various attack patterns (SQLi, XSS, failed logins, scanning) to test telemetry ingestion and alerts.

---

## Prerequisites & Configuration

1.  **Python**: 3.12+ (standard interpreters and virtual environments are located in `e_commerce/backend/myenv312` and `cyber_dashboard/backend/cyberenv`).
2.  **Node.js**: Installed (frontend dependencies are located in `cyber_dashboard/frontend/node_modules`).
3.  **PostgreSQL**: A local instance running on port `5432` with access credentials:
    *   **User**: `postgres`
    *   **Password**: `2003`
    *   **E-Commerce DB**: `e_commerce` (pre-created and migrated)
    *   **Cyber Security DB**: `cyber_security` (create this database before running Option 1)

---

## Option 1: Running the Complete Modular Mode (Recommended)

This mode runs the core API servers and three separate anomaly pipeline consumer processes. When Kafka is offline, telemetry shifts automatically to **TCP socket ingestion on port 9092** and **PostgreSQL database polling** for the consumers.

### Step 1: Create the Cyber Security Database
Ensure you run this SQL query on your PostgreSQL server:
```sql
CREATE DATABASE cyber_security;
```

### Step 2: Initialize the Cyber Security Schema
From the workspace root, run the PostgreSQL database setup:
```powershell
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
.\cyber_dashboard\backend\cyberenv\Scripts\python.exe .\cyber_dashboard\backend\db\db.py
```

### Step 3: Run the E-Commerce Backend (Port 8000)
Open a new shell and execute:
```powershell
cd .\e_commerce\backend
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/e_commerce"
$env:SECRET_KEY="supersecretkey"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
.\myenv312\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Step 4: Run the Cyber Dashboard Ingestion backend (Port 8001)
Open a new shell and execute:
```powershell
cd .\cyber_dashboard\backend
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
.\cyberenv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8001
```

### Step 5: Start the Threat Detection Consumers
Run each consumer in its own terminal window to parse PostgreSQL logs:
*   **Behavioral Anomaly Consumer**:
    ```powershell
    cd .\cyber_dashboard\backend
    $env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
    $env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
    .\cyberenv\Scripts\python.exe .\consumers\anomaly\consumer.py
    ```
*   **Volumetric DDoS Consumer**:
    ```powershell
    cd .\cyber_dashboard\backend
    $env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
    $env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
    .\cyberenv\Scripts\python.exe .\consumers\ddos\consumer.py
    ```
*   **Checkout Fraud Consumer**:
    ```powershell
    cd .\cyber_dashboard\backend
    $env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/cyber_security"
    $env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
    .\cyberenv\Scripts\python.exe .\consumers\fraud\consumer.py
    ```

### Step 6: Start the React Frontend Dashboard (Port 5173)
Open a new shell and execute:
```powershell
cd .\cyber_dashboard\frontend
npm run dev
```

---

## Option 2: Running the Simplified Standalone Mode

This mode runs the entire pipeline within two FastAPI API processes using SQLite, completely bypassing the need for separate consumer shells or database configurations.

### Step 1: Start E-Commerce Backend (Port 8000)
```powershell
cd .\e_commerce\backend
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/e_commerce"
$env:SECRET_KEY="supersecretkey"
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
.\myenv312\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Step 2: Start Standalone Cyber Backend (Port 8001)
This configuration initializes the SQLite database `cyber_dashboard.db` and runs rules-based threat analysis in a background thread:
```powershell
cd .\cyber_dashboard\backend
$env:KAFKA_BOOTSTRAP_SERVERS="localhost:9092"
.\cyberenv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001
```

### Step 3: Start React Frontend Dashboard (Port 5173)
```powershell
cd .\cyber_dashboard\frontend
npm run dev
```

---

## Verification & Attack Simulation Testing

### 1. Verification of E-Commerce API Endpoints
Run the end-to-end endpoint verification script to perform a diagnostic check on user auth, product lookups, cart items, order transactions, and reviews:
```powershell
cd .\e_commerce
$env:DATABASE_URL="postgresql://postgres:2003@localhost:5432/e_commerce"
..\e_commerce\backend\myenv312\Scripts\python.exe .\verify_endpoints.py
```

### 2. Live Attack Telemetry Simulator
Generate live simulated traffic (including high-severity attacks) to view real-time changes, websocket broadcasts, and flashing screens in the dashboard:
```powershell
# Run from the workspace root directory
.\e_commerce\backend\myenv312\Scripts\python.exe .\test_telemetry.py
```
This triggers:
*   Standard GET requests (clean traffic baseline).
*   **SQL Injection Attack**: A payload attempting user table data leakage.
*   **XSS Attack**: script injection payload in query params.
*   **Brute Force Login**: 5 rapid failed authenticate requests.
*   **Directory Fuzzing Scanner**: 12 rapid requests to non-existent admin/config paths.
