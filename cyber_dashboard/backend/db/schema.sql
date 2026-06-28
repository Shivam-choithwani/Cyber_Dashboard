-- schema.sql
-- PostgreSQL Database Schema for Security Platform Ingestion & Analytics

-- 1. Cold Storage for raw log telemetry
CREATE TABLE IF NOT EXISTS http_events (
    id SERIAL PRIMARY KEY,
    trace_id VARCHAR(64) UNIQUE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(32),
    method VARCHAR(16),
    path TEXT,
    status_code INTEGER,
    response_time_ms REAL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    user_id VARCHAR(64),
    session_id VARCHAR(64),
    query_params TEXT,
    details TEXT
);

-- 2. DDoS Alerts table (Frequency & volumetric anomaly)
CREATE TABLE IF NOT EXISTS ddos_alerts (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(64) NOT NULL,
    request_count INTEGER NOT NULL,
    requests_per_second REAL NOT NULL,
    severity VARCHAR(16) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    description TEXT
);

-- 3. Behavioral Anomaly Feature Windows (Cold training features log)
CREATE TABLE IF NOT EXISTS anomaly_feature_windows (
    id SERIAL PRIMARY KEY,
    key_type VARCHAR(32) NOT NULL,
    key_value VARCHAR(128) NOT NULL,
    feature_vector TEXT NOT NULL, -- JSON-string of engineered feature array
    window_end_ts TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 4. Behavioral Anomaly Scores and Alerts
CREATE TABLE IF NOT EXISTS anomaly_scores (
    id SERIAL PRIMARY KEY,
    key_type VARCHAR(32) NOT NULL,
    key_value VARCHAR(128) NOT NULL,
    score REAL NOT NULL,
    is_anomaly BOOLEAN NOT NULL,
    scored_at TIMESTAMP WITH TIME ZONE NOT NULL,
    details TEXT
);

-- 5. Checkout Fraud Feature Windows (Cold training features log)
CREATE TABLE IF NOT EXISTS fraud_feature_windows (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(128) NOT NULL,
    feature_vector TEXT NOT NULL, -- JSON-string of engineered fraud features
    window_end_ts TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 6. Checkout Fraud Scores and Alerts
CREATE TABLE IF NOT EXISTS fraud_scores (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(128) NOT NULL,
    score REAL NOT NULL,
    is_fraud BOOLEAN NOT NULL,
    scored_at TIMESTAMP WITH TIME ZONE NOT NULL,
    details TEXT
);

-- Indexes for efficient queries in dashboard and training scripts
CREATE INDEX IF NOT EXISTS idx_http_events_ip ON http_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_http_events_timestamp ON http_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ddos_alerts_detected ON ddos_alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_scores_scored ON anomaly_scores(scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_scores_scored ON fraud_scores(scored_at DESC);
