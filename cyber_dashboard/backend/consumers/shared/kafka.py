# kafka.py
import json
import time
import socket
import threading
from db.db import SessionLocal
from sqlalchemy import text
from consumers.shared.config import KAFKA_BOOTSTRAP_SERVERS
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.shared.kafka")

HAS_KAFKA_PYTHON = False
try:
    from kafka import KafkaConsumer
    HAS_KAFKA_PYTHON = True
except ImportError:
    logger.warning("kafka-python is not installed. Will default to Database Polling fallback.")


def check_kafka_broker() -> bool:
    """Performs a fast TCP handshake to check if a real broker is listening."""
    addr = KAFKA_BOOTSTRAP_SERVERS.split(",")[0]
    if ":" in addr:
        host, port_str = addr.split(":")
        port = int(port_str)
    else:
        host = addr
        port = 9092
        
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(0.5)
        test_sock.connect((host, port))
        test_sock.close()
        return True
    except Exception:
        return False

class SecurityTelemetryConsumer:
    def __init__(self, group_id: str, topics: list[str]):
        self.group_id = group_id
        self.topics = topics
        self.running = False
        
    def start(self, callback_fn):
        """Starts the consumer loop in a separate thread (non-blocking)."""
        self.running = True
        self.thread = threading.Thread(
            target=self._run_loop,
            args=(callback_fn,),
            name=f"ConsumerThread-{self.group_id}",
            daemon=True
        )
        self.thread.start()
        return self.thread

    def stop(self):
        """Stops the consumer loop."""
        self.running = False
        if hasattr(self, "thread"):
            self.thread.join(timeout=2.0)

    def _run_loop(self, callback_fn):
        kafka_active = check_kafka_broker()
        
        if HAS_KAFKA_PYTHON and kafka_active:
            self._run_kafka_consumer(callback_fn)
        else:
            logger.warning(
                f"Kafka broker offline or kafka-python missing. Starting PostgreSQL polling fallback for group '{self.group_id}'"
            )
            self._run_db_polling_consumer(callback_fn)

    def _run_kafka_consumer(self, callback_fn):
        try:
            consumer = KafkaConsumer(
                *self.topics,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
                group_id=self.group_id,
                auto_offset_reset="latest",
                enable_auto_commit=True
            )
            logger.info(f"Subscribed to Kafka topics {self.topics} on group '{self.group_id}'")
            
            while self.running:
                msg_pack = consumer.poll(timeout_ms=1000)
                for tp, messages in msg_pack.items():
                    for msg in messages:
                        if not self.running:
                            break
                        topic = msg.topic
                        try:
                            data = json.loads(msg.value.decode("utf-8"))
                            callback_fn(topic, data)
                        except Exception as e:
                            logger.error(f"Failed to process message in group '{self.group_id}' on topic {topic}: {e}")
                            
            consumer.close()
            logger.info(f"Kafka consumer closed for group '{self.group_id}'")
        except Exception as e:
            logger.error(f"Kafka consumer thread crashed in group '{self.group_id}': {e}")

    def _run_db_polling_consumer(self, callback_fn):
        """
        Database Polling Fallback Loop:
        Polls the `http_events` table for new rows since the last processed ID.
        This allows multiple consumer processes to run independently on a shared Postgres DB
        even if Kafka is not running locally.
        """
        # Determine the initial max ID to start reading from
        last_processed_id = 0
        db = SessionLocal()
        try:
            res = db.execute(text("SELECT MAX(id) FROM http_events")).scalar()
            if res:
                last_processed_id = res
            logger.info(f"DB Polling starting from http_events ID: {last_processed_id}")
        except Exception as e:
            logger.error(f"Failed to fetch initial event log ID in group '{self.group_id}': {e}")
        finally:
            db.close()

        while self.running:
            db = SessionLocal()
            try:
                # Query new events inserted after last_processed_id
                query = text(
                    "SELECT id, event_type, method, path, status_code, response_time_ms, ip_address, "
                    "user_agent, user_id, session_id, query_params, details, timestamp "
                    "FROM http_events WHERE id > :last_id ORDER BY id ASC LIMIT 50"
                )
                rows = db.execute(query, {"last_id": last_processed_id}).fetchall()
                
                for r in rows:
                    event_id = r[0]
                    # Map to the same telemetry dict structure used by the platform
                    event_data = {
                        "trace_id": str(event_id), # fallback trace_id is serial ID
                        "timestamp": r[12].isoformat() if r[12] else "",
                        "event_type": r[1],
                        "method": r[2],
                        "path": r[3],
                        "status_code": r[4],
                        "response_time_ms": r[5],
                        "ip_address": r[6],
                        "user_agent": r[7],
                        "user_id": r[8],
                        "session_id": r[9],
                        "query_params": r[10]
                    }
                    if r[11]:
                        try:
                            event_data["details"] = json.loads(r[11])
                        except Exception:
                            event_data["details"] = r[11]

                    # Trigger pipeline callback
                    topic = r[1] or "http-logs"
                    
                    # Wait, if topics list is specified, filter by it
                    if topic in self.topics:
                        try:
                            callback_fn(topic, event_data)
                        except Exception as cb_err:
                            logger.error(f"Callback error in polling consumer '{self.group_id}': {cb_err}")

                    last_processed_id = event_id
                    
            except Exception as e:
                logger.error(f"Database polling error in group '{self.group_id}': {e}")
            finally:
                db.close()
                
            time.sleep(1.0)
