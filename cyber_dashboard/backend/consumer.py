import json
import socket
import threading
import logging
import time

logger = logging.getLogger("cyber.consumer")

HAS_KAFKA_PYTHON = False
try:
    from kafka import KafkaConsumer
    HAS_KAFKA_PYTHON = True
except ImportError:
    logger.warning("kafka-python is not installed on Cyber Dashboard backend. Using TCP fallback.")


# Shared flag to stop the consumer thread
running = True

def parse_bootstrap_server(bootstrap_servers: str):
    """Utility to parse bootstrap servers into host and port."""
    addr = bootstrap_servers.split(",")[0]
    if ":" in addr:
        host, port_str = addr.split(":")
        return host, int(port_str)
    return addr, 9092

def start_kafka_consumer(bootstrap_servers: str, on_event_callback):
    """Subscribes to Kafka topics and loops polling for messages."""
    try:
        consumer = KafkaConsumer(
            "http-logs", "security-events", "sql-logs",
            bootstrap_servers=bootstrap_servers.split(","),
            group_id="cyber-security-dashboard",
            auto_offset_reset="latest",
            enable_auto_commit=True
        )
        logger.info(f"Subscribed to Kafka topics on {bootstrap_servers}")
        
        while running:
            msg_pack = consumer.poll(timeout_ms=1000)
            for tp, messages in msg_pack.items():
                for msg in messages:
                    if not running:
                        break
                    topic = msg.topic
                    try:
                        data = json.loads(msg.value.decode("utf-8"))
                        on_event_callback(topic, data)
                    except Exception as e:
                        logger.error(f"Failed to process Kafka message on topic {topic}: {e}")
                        
        consumer.close()
    except Exception as e:
        logger.error(f"Kafka consumer failed: {e}")
        raise e


def start_tcp_fallback_server(host: str, port: int, on_event_callback):
    """Spins up a TCP server that acts as a simple mock message broker."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
        logger.info(f"TCP Mock Broker Server started on {host}:{port}")
    except Exception as e:
        logger.error(f"Failed to bind TCP Mock Broker Server to {host}:{port}: {e}")
        return
        
    def handle_client(client_socket, client_address):
        logger.info(f"E-commerce producer connected from {client_address}")
        buffer = ""
        client_socket.settimeout(1.0)
        try:
            while running:
                try:
                    data = client_socket.recv(4096)
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
                            on_event_callback(topic, event_data)
                        except Exception as je:
                            logger.error(f"Failed to parse mock JSON telemetry event: {je}")
                except socket.timeout:
                    continue
                except Exception as ce:
                    logger.error(f"Error reading from producer socket: {ce}")
                    break
        finally:
            client_socket.close()
            logger.info(f"E-commerce producer disconnected from {client_address}")

    while running:
        try:
            client_sock, client_addr = server_socket.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logger.error(f"TCP socket server accept error: {e}")
            break
            
    server_socket.close()
    logger.info("TCP Mock Broker Server shut down.")


def run_consumer_loop(bootstrap_servers: str, on_event_callback):
    """
    Main driver running the ingestion loop. Performs a fast TCP check on the 
    bootstrap address to determine if a real broker is online, and runs either
    the Kafka Consumer or our mock TCP server.
    """
    host, port = parse_bootstrap_server(bootstrap_servers)
    real_kafka_active = False
    
    # Fast TCP handshake check
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(0.5)
        test_sock.connect((host, port))
        test_sock.close()
        real_kafka_active = True
        logger.info(f"Verified active Kafka broker listening on {host}:{port}")
    except Exception:
        logger.warning(f"No active Kafka broker found on {host}:{port}. Defaulting to TCP socket server fallback.")
        
    if HAS_KAFKA_PYTHON and real_kafka_active:
        try:
            start_kafka_consumer(bootstrap_servers, on_event_callback)
            return
        except Exception as ke:
            logger.warning(f"Kafka consumer failed to launch: {ke}. Falling back to TCP socket server.")
            
    # Fallback Mode: TCP server on port 9092
    start_tcp_fallback_server(host, port, on_event_callback)


def start_consumer(bootstrap_servers: str, on_event_callback) -> threading.Thread:
    """Starts the consumer thread and returns the thread object."""
    global running
    running = True
    thread = threading.Thread(
        target=run_consumer_loop,
        args=(bootstrap_servers, on_event_callback),
        name="TelemetryConsumerThread",
        daemon=True
    )
    thread.start()
    return thread

def stop_consumer():
    """Stops the consumer loop."""
    global running
    running = False
