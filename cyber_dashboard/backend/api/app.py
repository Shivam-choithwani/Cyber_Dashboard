# app.py
import os
import sys
import json
import socket
import asyncio
import threading
import logging
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

# Ensure parent directory is on path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.db import init_db, get_db, SessionLocal
from consumers.shared.config import KAFKA_BOOTSTRAP_SERVERS
from consumers.shared.logger import setup_logger
from consumers.shared.kafka import check_kafka_broker
from api.routes.ddos import router as ddos_router
from api.routes.anomaly import router as anomaly_router
from api.routes.fraud import router as fraud_router

logger = setup_logger("cyber.api")

app = FastAPI(
    title="Cyber Security Modular Ingestion & Detection Platform",
    description="Real-time unified dashboard API server connecting DDoS, Behavioral, and Checkout Fraud engines.",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register sub-routers
app.include_router(ddos_router, prefix="/api")
app.include_router(anomaly_router, prefix="/api")
app.include_router(fraud_router, prefix="/api")

# WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Dashboard client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Dashboard client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# Background TCP fallback socket server (Port 9092)
# If Kafka is not running, we bind to 9092 to receive direct TCP sockets from the e-commerce telemetry
tcp_server_running = True

def run_tcp_fallback_server():
    """Listens on Port 9092 to receive direct TCP logs from e-commerce telemetry and write them to PostgreSQL."""
    addr = KAFKA_BOOTSTRAP_SERVERS.split(",")[0]
    if ":" in addr:
        host, port_str = addr.split(":")
        port = int(port_str)
    else:
        host = addr
        port = 9092
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
        logger.info(f"TCP Mock Ingestion Broker listening on {host}:{port}")
    except Exception as e:
        logger.warning(f"Unable to bind TCP Ingestion Broker to {host}:{port} (Kafka is likely running): {e}")
        return

    while tcp_server_running:
        try:
            client_sock, client_addr = server_socket.accept()
            t = threading.Thread(target=handle_tcp_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            logger.error(f"TCP ingestion socket error: {e}")
            break
            
    server_socket.close()

def handle_tcp_client(sock, addr):
    logger.info(f"E-commerce producer telemetry connected from {addr}")
    buffer = ""
    sock.settimeout(1.0)
    try:
        while tcp_server_running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                        topic = payload.get("topic", "http-logs")
                        event_data = payload.get("data", {})
                        
                        # Write raw log directly to PostgreSQL
                        db = SessionLocal()
                        try:
                            # Map and write raw event
                            query = text("""
                                INSERT INTO http_events (
                                    trace_id, timestamp, event_type, method, path, status_code, 
                                    response_time_ms, ip_address, user_agent, user_id, session_id, 
                                    query_params, details
                                ) VALUES (
                                    :trace_id, :timestamp, :event_type, :method, :path, :status_code, 
                                    :response_time_ms, :ip_address, :user_agent, :user_id, :session_id, 
                                    :query_params, :details
                                )
                            """)
                            
                            db.execute(query, {
                                "trace_id": event_data.get("trace_id") or event_data.get("event_id"),
                                "timestamp": datetime.utcnow(),
                                "event_type": topic,
                                "method": event_data.get("method"),
                                "path": event_data.get("path"),
                                "status_code": event_data.get("status_code"),
                                "response_time_ms": event_data.get("response_time_ms"),
                                "ip_address": event_data.get("ip_address"),
                                "user_agent": event_data.get("user_agent"),
                                "user_id": event_data.get("user_id"),
                                "session_id": event_data.get("session_id"),
                                "query_params": event_data.get("query_params"),
                                "details": json.dumps(event_data.get("details")) if "details" in event_data else None
                            })
                            db.commit()
                        except Exception as dbe:
                            db.rollback()
                            logger.error(f"Failed to save fallback raw event log to Postgres: {dbe}")
                        finally:
                            db.close()
                    except Exception as je:
                        logger.error(f"Failed to parse fallback TCP log line: {je}")
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        sock.close()
        logger.info(f"E-commerce producer telemetry disconnected from {addr}")


# Background polling thread for real-time WebSocket broadcasting
loop_running = True

async def poll_database_for_websocket_broadcasts():
    """
    Background loop that polls PostgreSQL for newly ingested logs or alarms
    and broadcasts them to all connected frontend WebSockets.
    """
    last_log_id = 0
    last_ddos_id = 0
    last_anomaly_id = 0
    last_fraud_id = 0
    
    # Initialize high-water marks on startup to avoid spamming historical alerts
    db = SessionLocal()
    try:
        last_log_id = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM http_events")).scalar()
        last_ddos_id = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM ddos_alerts")).scalar()
        last_anomaly_id = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM anomaly_scores")).scalar()
        last_fraud_id = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM fraud_scores")).scalar()
    except Exception as e:
        logger.error(f"Failed to retrieve highwater marks for broadcasts: {e}")
    finally:
        db.close()

    while loop_running:
        db = SessionLocal()
        try:
            # 1. Fetch new raw http-logs
            new_logs = db.execute(
                text("SELECT id, method, path, status_code, response_time_ms, ip_address, timestamp FROM http_events WHERE id > :last_id ORDER BY id ASC LIMIT 50"),
                {"last_id": last_log_id}
            ).fetchall()
            
            for log in new_logs:
                last_log_id = log[0]
                await manager.broadcast({
                    "type": "log_event",
                    "topic": "http-logs",
                    "event": {
                        "trace_id": str(log[0]),
                        "method": log[1],
                        "path": log[2],
                        "status_code": log[3],
                        "response_time_ms": log[4],
                        "ip_address": log[5],
                        "timestamp": log[6].isoformat() + "Z" if log[6] else ""
                    }
                })

            # 2. Fetch new DDoS Alerts
            new_ddos = db.execute(
                text("SELECT id, source_ip, severity, description, detected_at, request_count FROM ddos_alerts WHERE id > :last_id ORDER BY id ASC"),
                {"last_id": last_ddos_id}
            ).fetchall()
            
            for alert in new_ddos:
                last_ddos_id = alert[0]
                await manager.broadcast({
                    "type": "anomaly_alert",
                    "anomaly": {
                        "anomaly_id": f"ddos-{alert[0]}",
                        "timestamp": alert[4].isoformat() + "Z" if alert[4] else "",
                        "event_type": "http-logs",
                        "anomaly_type": "RATE_LIMIT_VIOLATION" if "Scanner" not in alert[3] else "PATH_FUZZING",
                        "severity": alert[2],
                        "description": alert[3],
                        "ip_address": alert[1],
                        "path": "",
                        "details": {"request_count": alert[5]}
                    }
                })

            # 3. Fetch new Behavioral Anomalies (where is_anomaly = True)
            new_anom = db.execute(
                text("SELECT id, key_value, score, scored_at, details FROM anomaly_scores WHERE id > :last_id AND is_anomaly = TRUE ORDER BY id ASC"),
                {"last_id": last_anomaly_id}
            ).fetchall()
            
            for anom in new_anom:
                last_anomaly_id = anom[0]
                await manager.broadcast({
                    "type": "anomaly_alert",
                    "anomaly": {
                        "anomaly_id": f"anom-{anom[0]}",
                        "timestamp": anom[3].isoformat() + "Z" if anom[3] else "",
                        "event_type": "http-logs",
                        "anomaly_type": "BEHAVIORAL_ANOMALY",
                        "severity": "CRITICAL" if anom[2] > 0.8 else "HIGH",
                        "description": f"Behavior anomaly detected: {anom[4]}",
                        "ip_address": anom[1],
                        "path": "",
                        "details": {"score": anom[2], "reason": anom[4]}
                    }
                })

            # 4. Fetch new Fraud Checkout Alerts (where is_fraud = True)
            new_fraud = db.execute(
                text("SELECT id, customer_id, score, scored_at, details FROM fraud_scores WHERE id > :last_id AND is_fraud = TRUE ORDER BY id ASC"),
                {"last_id": last_fraud_id}
            ).fetchall()
            
            for fraud in new_fraud:
                last_fraud_id = fraud[0]
                await manager.broadcast({
                    "type": "anomaly_alert",
                    "anomaly": {
                        "anomaly_id": f"fraud-{fraud[0]}",
                        "timestamp": fraud[3].isoformat() + "Z" if fraud[3] else "",
                        "event_type": "security-events",
                        "anomaly_type": "BRUTE_FORCE", # maps cleanly to existing threat categories
                        "severity": "HIGH",
                        "description": f"Checkout fraud suspected for user {fraud[1]}: {fraud[4]}",
                        "ip_address": "mismatch" if "mismatch" in fraud[4].lower() else "velocity",
                        "path": "/orders",
                        "details": {"customer_id": fraud[1], "score": fraud[2]}
                    }
                })

        except Exception as e:
            logger.error(f"Error in WebSocket broadcasting poll task: {e}")
        finally:
            db.close()
            
        await asyncio.sleep(1.0)


# Startup and Shutdown hooks
@app.on_event("startup")
def startup_event():
    # Initialize postgres schema
    init_db()
    
    # Start TCP Mock ingestion broker if Kafka is down
    if not check_kafka_broker():
        logger.info("Kafka broker is offline. Launching fallback TCP ingestion socket server...")
        threading.Thread(target=run_tcp_fallback_server, daemon=True).start()
    
    # Start websocket broadcaster task in event loop
    asyncio.create_task(poll_database_for_websocket_broadcasts())

@app.on_event("shutdown")
def shutdown_event():
    global tcp_server_running, loop_running
    logger.info("Shutting down API subservices...")
    tcp_server_running = False
    loop_running = False

# REST API Endpoints
@app.get("/api/events")
def get_events(limit: int = Query(default=100, le=500), db: Session = Depends(get_db)):
    """Fetches list of historical logs from the PostgreSQL cold storage."""
    try:
        query = text("""
            SELECT id, method, path, status_code, response_time_ms, ip_address, user_agent, user_id, session_id, timestamp, query_params, details
            FROM http_events
            ORDER BY id DESC
            LIMIT :limit
        """)
        rows = db.execute(query, {"limit": limit}).fetchall()
        
        events = []
        for r in rows:
            events.append({
                "trace_id": str(r[0]),
                "method": r[1],
                "path": r[2],
                "status_code": r[3],
                "response_time_ms": r[4],
                "ip_address": r[5],
                "user_agent": r[6],
                "user_id": r[7],
                "session_id": r[8],
                "timestamp": r[9].isoformat() + "Z" if r[9] else "",
                "query_params": r[10],
                "details": json.loads(r[11]) if r[11] else {}
            })
        return events
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/anomalies")
def get_anomalies(limit: int = Query(default=100, le=500), db: Session = Depends(get_db)):
    """Unified feed compiling threats from DDoS, Anomaly, and Fraud PostgreSQL tables."""
    try:
        # SQL Union to compile recent threat alerts
        query = text("""
            SELECT * FROM (
                SELECT 
                    'ddos-' || id as anomaly_id, 
                    detected_at as timestamp, 
                    'http-logs' as event_type, 
                    CASE WHEN severity = 'CRITICAL' THEN 'PATH_FUZZING' ELSE 'RATE_LIMIT_VIOLATION' END as anomaly_type,
                    severity, 
                    description, 
                    source_ip as ip_address, 
                    '' as path, 
                    '{"count": ' || request_count || '}' as details
                FROM ddos_alerts
                
                UNION ALL
                
                SELECT 
                    'anom-' || id as anomaly_id, 
                    scored_at as timestamp, 
                    'http-logs' as event_type, 
                    'SUSPICIOUS_AGENT' as anomaly_type, 
                    CASE WHEN score > 0.8 THEN 'CRITICAL' ELSE 'HIGH' END as severity, 
                    details as description, 
                    key_value as ip_address, 
                    '' as path, 
                    '{"score": ' || score || '}' as details
                FROM anomaly_scores 
                WHERE is_anomaly = TRUE
                
                UNION ALL
                
                SELECT 
                    'fraud-' || id as anomaly_id, 
                    scored_at as timestamp, 
                    'security-events' as event_type, 
                    'BRUTE_FORCE' as anomaly_type, 
                    'HIGH' as severity, 
                    'Checkout Fraud Suspected: ' || details as description, 
                    customer_id as ip_address, 
                    '/orders' as path, 
                    '{"score": ' || score || '}' as details
                FROM fraud_scores 
                WHERE is_fraud = TRUE
            ) as unified_threats
            ORDER BY timestamp DESC
            LIMIT :limit
        """)
        
        rows = db.execute(query, {"limit": limit}).fetchall()
        anomalies = []
        for r in rows:
            details_json = {}
            if r[8]:
                try:
                    details_json = json.loads(r[8])
                except Exception:
                    details_json = {"raw": r[8]}
            anomalies.append({
                "anomaly_id": r[0],
                "timestamp": r[1].isoformat() + "Z" if r[1] else "",
                "event_type": r[2],
                "anomaly_type": r[3],
                "severity": r[4],
                "description": r[5],
                "ip_address": r[6],
                "path": r[7],
                "details": details_json
            })
        return anomalies
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Unified stats reporting aggregates across HTTP logs, DDoS alerts, anomaly and fraud records."""
    try:
        # Total event logs count
        total_events = db.execute(text("SELECT COUNT(*) FROM http_events")).scalar() or 0
        
        # Total active alerts count
        total_ddos = db.execute(text("SELECT COUNT(*) FROM ddos_alerts")).scalar() or 0
        total_anom = db.execute(text("SELECT COUNT(*) FROM anomaly_scores WHERE is_anomaly = TRUE")).scalar() or 0
        total_fraud = db.execute(text("SELECT COUNT(*) FROM fraud_scores WHERE is_fraud = TRUE")).scalar() or 0
        total_anomalies = total_ddos + total_anom + total_fraud
        
        anomaly_rate = (total_anomalies / total_events * 100) if total_events > 0 else 0.0
        
        avg_latency = db.execute(text("SELECT AVG(response_time_ms) FROM http_events WHERE response_time_ms > 0")).scalar() or 0.0
        
        # Status code distributions
        row = db.execute(text("""
            SELECT 
                SUM(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 300 AND 399 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
                SUM(CASE WHEN status_code BETWEEN 500 AND 599 THEN 1 ELSE 0 END)
            FROM http_events
        """)).fetchone()
        
        status_distribution = {
            "2xx": row[0] or 0,
            "3xx": row[1] or 0,
            "4xx": row[2] or 0,
            "5xx": row[3] or 0
        }
        
        # Threat breakdown by type
        anomalies_by_type = {
            "RATE_LIMIT_VIOLATION": db.execute(text("SELECT COUNT(*) FROM ddos_alerts WHERE description NOT LIKE '%Scanner%'")).scalar() or 0,
            "PATH_FUZZING": db.execute(text("SELECT COUNT(*) FROM ddos_alerts WHERE description LIKE '%Scanner%'")).scalar() or 0,
            "BEHAVIORAL_ANOMALY": total_anom,
            "FRAUD_CHECKOUT": total_fraud
        }
        
        # Top 5 offending clients/customers from union of threat logs
        top_ips_rows = db.execute(text("""
            SELECT ip, COUNT(*) as threat_count FROM (
                SELECT source_ip as ip FROM ddos_alerts
                UNION ALL
                SELECT key_value as ip FROM anomaly_scores WHERE is_anomaly = TRUE
                UNION ALL
                SELECT customer_id as ip FROM fraud_scores WHERE is_fraud = TRUE
            ) as unified_ips
            GROUP BY ip
            ORDER BY threat_count DESC
            LIMIT 5
        """)).fetchall()
        top_ips = [{"ip": r[0], "count": r[1]} for r in top_ips_rows]
        
        # Top 5 slowest paths
        slowest_rows = db.execute(text("""
            SELECT path, AVG(response_time_ms) as latency 
            FROM http_events 
            WHERE response_time_ms > 0 AND path IS NOT NULL
            GROUP BY path 
            ORDER BY latency DESC 
            LIMIT 5
        """)).fetchall()
        slowest_paths = [{"path": r[0], "avg_latency": round(r[1], 2)} for r in slowest_rows]
        
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
    except Exception as e:
        logger.error(f"Error compiling stats: {e}")
        return {"error": str(e)}

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Maintain connection and listen for heartbeat
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket session error: {e}")
        manager.disconnect(websocket)
