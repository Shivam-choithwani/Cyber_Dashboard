import os
import json
import sqlite3
import asyncio
import logging
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from anomaly_detector import AnomalyDetector
from consumer import start_consumer, stop_consumer

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cyber.backend")

DB_PATH = "cyber_dashboard.db"
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

app = FastAPI(
    title="Cyber Security Ingestion & Detection Platform",
    description="Real-time log ingestion, anomaly detection, and analytics server.",
    version="1.0.0"
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
detector = AnomalyDetector()
main_loop = None
consumer_thread = None

# Database Helpers
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id TEXT,
        timestamp TEXT,
        event_type TEXT,
        method TEXT,
        path TEXT,
        status_code INTEGER,
        response_time_ms REAL,
        ip_address TEXT,
        user_agent TEXT,
        user_id TEXT,
        session_id TEXT,
        query_params TEXT,
        details TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id TEXT,
        timestamp TEXT,
        event_id TEXT,
        event_type TEXT,
        anomaly_type TEXT,
        severity TEXT,
        description TEXT,
        ip_address TEXT,
        path TEXT,
        details TEXT
    )
    """)
    conn.commit()
    conn.close()
    logger.info("SQLite database tables initialized successfully.")

def save_event(event_type: str, data: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO events (
        trace_id, timestamp, event_type, method, path, status_code, 
        response_time_ms, ip_address, user_agent, user_id, session_id, 
        query_params, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("trace_id") or data.get("event_id"),
        data.get("timestamp"),
        event_type,
        data.get("method"),
        data.get("path"),
        data.get("status_code"),
        data.get("response_time_ms"),
        data.get("ip_address"),
        data.get("user_agent"),
        data.get("user_id"),
        data.get("session_id"),
        data.get("query_params"),
        json.dumps(data.get("details")) if "details" in data else None
    ))
    conn.commit()
    conn.close()

def save_anomaly(anomaly: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO anomalies (
        anomaly_id, timestamp, event_id, event_type, anomaly_type, 
        severity, description, ip_address, path, details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        anomaly.get("anomaly_id"),
        anomaly.get("timestamp"),
        anomaly.get("event_id"),
        anomaly.get("event_type"),
        anomaly.get("anomaly_type"),
        anomaly.get("severity"),
        anomaly.get("description"),
        anomaly.get("ip_address"),
        anomaly.get("path"),
        json.dumps(anomaly.get("details"))
    ))
    conn.commit()
    conn.close()

# WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Dashboard client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Dashboard client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# Background Event Callback
def on_event_received(topic: str, data: dict):
    """Callback triggered by consumer loop in background thread on log ingestion."""
    try:
        # Save raw event to DB
        save_event(topic, data)
        
        # Analyze event for anomalies
        anomalies = detector.detect(data, topic)
        
        # Broadcast the raw event log to active dashboard sessions
        if main_loop:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast({
                    "type": "log_event",
                    "topic": topic,
                    "event": data
                }),
                main_loop
            )
            
        # Handle detected anomalies
        for anomaly in anomalies:
            logger.warning(f"ANOMALY DETECTED: [{anomaly['anomaly_type']}] - {anomaly['description']}")
            save_anomaly(anomaly)
            
            # Broadcast alert to active dashboard sessions
            if main_loop:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({
                        "type": "anomaly_alert",
                        "anomaly": anomaly
                    }),
                    main_loop
                )
    except Exception as e:
        logger.error(f"Error handling ingested event: {e}")

# Lifecycle Handlers
@app.on_event("startup")
async def startup_event():
    global main_loop, consumer_thread
    main_loop = asyncio.get_running_loop()
    init_db()
    
    # Start the Kafka consumer thread (with mock fallback)
    logger.info(f"Starting consumer thread (bootstrap servers: {KAFKA_BOOTSTRAP_SERVERS})...")
    consumer_thread = start_consumer(KAFKA_BOOTSTRAP_SERVERS, on_event_received)

@app.on_event("shutdown")
def shutdown_event():
    logger.info("Stopping background consumer thread...")
    stop_consumer()
    if consumer_thread:
        consumer_thread.join(timeout=2.0)
    logger.info("Shutdown complete.")

# HTTP API Endpoints
@app.get("/api/events")
def get_events(limit: int = Query(default=100, le=500)):
    """Fetches list of historical events (logs)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM events 
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for r in rows:
        d = dict(r)
        if d["details"]:
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        events.append(d)
    return events

@app.get("/api/anomalies")
def get_anomalies(limit: int = Query(default=100, le=500)):
    """Fetches list of historical anomalies."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM anomalies 
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    anomalies = []
    for r in rows:
        d = dict(r)
        if d["details"]:
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        anomalies.append(d)
    return anomalies

@app.get("/api/stats")
def get_stats():
    """Returns general platform statistics for dashboard charts and metrics."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM anomalies")
        total_anomalies = cursor.fetchone()[0]
        
        anomaly_rate = (total_anomalies / total_events * 100) if total_events > 0 else 0.0
        
        cursor.execute("SELECT AVG(response_time_ms) FROM events WHERE response_time_ms IS NOT NULL AND response_time_ms > 0")
        avg_latency = cursor.fetchone()[0] or 0.0
        
        # HTTP Status Distribution
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 300 AND 399 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 500 AND 599 THEN 1 ELSE 0 END)
            FROM events
        """)
        row = cursor.fetchone()
        status_distribution = {
            "2xx": row[0] or 0,
            "3xx": row[1] or 0,
            "4xx": row[2] or 0,
            "5xx": row[3] or 0
        }
        
        # Anomalies segmented by type
        cursor.execute("SELECT anomaly_type, COUNT(*) FROM anomalies GROUP BY anomaly_type")
        anomalies_by_type = dict(cursor.fetchall())
        
        # Top 5 most active malicious client IPs
        cursor.execute("""
            SELECT ip_address, COUNT(*) FROM anomalies 
            WHERE ip_address != 'unknown' 
            GROUP BY ip_address 
            ORDER BY COUNT(*) DESC LIMIT 5
        """)
        top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        # Slowest paths
        cursor.execute("""
            SELECT path, AVG(response_time_ms) 
            FROM events 
            WHERE response_time_ms IS NOT NULL AND response_time_ms > 0 AND path IS NOT NULL
            GROUP BY path 
            ORDER BY AVG(response_time_ms) DESC 
            LIMIT 5
        """)
        slowest_paths = [{"path": row[0], "avg_latency": round(row[1], 2)} for row in cursor.fetchall()]
        
    except Exception as e:
        logger.error(f"Error compiling stats: {e}")
        return {"error": str(e)}
    finally:
        conn.close()
        
    return {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "anomaly_rate": round(anomaly_rate, 2),
        "avg_latency": round(avg_latency, 2),
        "status_distribution": status_distribution,
        "anomalies_by_type": anomalies_by_type,
        "top_ips": top_ips,
        "slowest_paths": slowest_paths
    }

# WebSocket Route
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Keep connection open and send heartbeats or handle client commands
        while True:
            # Wait for any messages from client (optional, mostly listening)
            data = await websocket.receive_text()
            # If client requests initial sync, we can reply
            if data == "get_initial_data":
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
