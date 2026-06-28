# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Kafka broker configurations
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

# Database configurations (propagates from db.py)
from db.db import DATABASE_URL

# Consumer topics
HTTP_LOGS_TOPIC = "http-traces"
SECURITY_EVENTS_TOPIC = "soc-events"

# Detection threshold baselines (fallbacks)
DEFAULT_Z_SCORE_THRESHOLD = 3.5
DEFAULT_RATE_LIMIT_THRESHOLD = 40
DEFAULT_BRUTE_FORCE_LIMIT = 5
DEFAULT_SCANNING_LIMIT = 10
