# train_models.py
"""
Scikit-Learn Model Training Script for Cyber Security Platform.

This script reads engineered feature vectors from PostgreSQL / SQLite databases 
(or generates baseline synthetic distributions if tables are empty) to train:
1. An Unsupervised Isolation Forest model for Behavioral Anomaly Detection.
2. A Supervised Logistic Regression model for Checkout Fraud Detection.

The resulting trained .pkl models are saved to:
- cyber_dashboard/backend/models/anomaly/model.pkl
- cyber_dashboard/backend/models/fraud/model.pkl
"""

import os
import sys
import json
import pickle
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cyber.ml.trainer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ANOMALY_MODEL_DIR = os.path.join(BASE_DIR, "models", "anomaly")
FRAUD_MODEL_DIR = os.path.join(BASE_DIR, "models", "fraud")

def fetch_db_features(table_name: str) -> list[list[float]]:
    """Attempts to fetch feature vectors stored in PostgreSQL."""
    try:
        from db.db import SessionLocal
        from sqlalchemy import text
        
        db = SessionLocal()
        query = text(f"SELECT feature_vector FROM {table_name} ORDER BY id DESC LIMIT 2000")
        result = db.execute(query).fetchall()
        db.close()
        
        features = []
        for row in result:
            vec = json.loads(row[0])
            if isinstance(vec, list) and len(vec) == 4:
                features.append(vec)
        return features
    except Exception as e:
        logger.warning(f"Could not fetch features from DB table {table_name}: {e}")
        return []

def generate_synthetic_anomaly_data(sample_count: int = 1000) -> np.ndarray:
    """
    Generates synthetic training dataset for Isolation Forest:
    Features: [latency_avg, latency_std, error_rate, path_variety]
    - 95% Normal Traffic (low latency ~50-200ms, low error rate ~0.0-0.05, low path variety)
    - 5% Outlier Anomalies (high latency >800ms, high error rate >0.4, high path variety >0.8)
    """
    np.random.seed(42)
    normal_count = int(sample_count * 0.95)
    anom_count = sample_count - normal_count

    # Normal traffic distribution
    normal_latency_avg = np.random.normal(loc=120.0, scale=30.0, size=(normal_count, 1))
    normal_latency_std = np.random.normal(loc=15.0, scale=5.0, size=(normal_count, 1))
    normal_error_rate = np.random.beta(a=0.5, b=10, size=(normal_count, 1)) * 0.1
    normal_path_variety = np.random.uniform(low=0.1, high=0.4, size=(normal_count, 1))

    normal_data = np.hstack([
        np.clip(normal_latency_avg, 10.0, 400.0),
        np.clip(normal_latency_std, 1.0, 50.0),
        np.clip(normal_error_rate, 0.0, 0.1),
        np.clip(normal_path_variety, 0.1, 0.5)
    ])

    # Anomaly traffic distribution
    anom_latency_avg = np.random.normal(loc=950.0, scale=200.0, size=(anom_count, 1))
    anom_latency_std = np.random.normal(loc=180.0, scale=40.0, size=(anom_count, 1))
    anom_error_rate = np.random.uniform(low=0.4, high=1.0, size=(anom_count, 1))
    anom_path_variety = np.random.uniform(low=0.8, high=1.0, size=(anom_count, 1))

    anom_data = np.hstack([
        np.clip(anom_latency_avg, 500.0, 3000.0),
        np.clip(anom_latency_std, 50.0, 500.0),
        np.clip(anom_error_rate, 0.3, 1.0),
        np.clip(anom_path_variety, 0.7, 1.0)
    ])

    return np.vstack([normal_data, anom_data])

def generate_synthetic_fraud_data(sample_count: int = 1000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generates synthetic training dataset for Fraud Logistic Regression:
    Features: [order_count_last_hour, current_order_price, avg_order_price, payment_method_val]
    """
    np.random.seed(42)
    normal_count = int(sample_count * 0.90)
    fraud_count = sample_count - normal_count

    # Normal order profiles (class 0)
    norm_orders_1h = np.random.randint(1, 3, size=(normal_count, 1))
    norm_price = np.random.normal(loc=85.0, scale=35.0, size=(normal_count, 1))
    norm_avg_price = norm_price + np.random.normal(loc=0.0, scale=10.0, size=(normal_count, 1))
    norm_pay_idx = np.random.choice([0, 1, 2], size=(normal_count, 1))
    X_normal = np.hstack([
        norm_orders_1h,
        np.clip(norm_price, 10.0, 300.0),
        np.clip(norm_avg_price, 10.0, 300.0),
        norm_pay_idx
    ])
    y_normal = np.zeros(normal_count)

    # Fraudulent order profiles (class 1)
    fraud_orders_1h = np.random.randint(4, 15, size=(fraud_count, 1))
    fraud_price = np.random.normal(loc=3500.0, scale=1000.0, size=(fraud_count, 1))
    fraud_avg_price = np.random.normal(loc=50.0, scale=15.0, size=(fraud_count, 1))
    fraud_pay_idx = np.random.choice([0, 1], size=(fraud_count, 1))
    X_fraud = np.hstack([
        fraud_orders_1h,
        np.clip(fraud_price, 800.0, 10000.0),
        np.clip(fraud_avg_price, 10.0, 100.0),
        fraud_pay_idx
    ])
    y_fraud = np.ones(fraud_count)

    X = np.vstack([X_normal, X_fraud])
    y = np.concatenate([y_normal, y_fraud])
    return X, y

def train_anomaly_model():
    """Trains and saves the Scikit-Learn Isolation Forest model."""
    logger.info("--- Training Behavioral Anomaly Detection Model ---")
    db_features = fetch_db_features("anomaly_feature_windows")
    
    if len(db_features) >= 50:
        logger.info(f"Using {len(db_features)} feature vectors fetched from database.")
        X = np.array(db_features)
    else:
        logger.info("Database table empty or insufficient. Generating synthetic baseline dataset...")
        X = generate_synthetic_anomaly_data()

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    os.makedirs(ANOMALY_MODEL_DIR, exist_ok=True)
    model_path = os.path.join(ANOMALY_MODEL_DIR, "model.pkl")
    
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
        
    logger.info(f"✅ Anomaly Isolation Forest model successfully saved to: {model_path}")

def train_fraud_model():
    """Trains and saves the Scikit-Learn Logistic Regression model."""
    logger.info("--- Training Checkout Fraud Classification Model ---")
    X, y = generate_synthetic_fraud_data()

    model = LogisticRegression(random_state=42)
    model.fit(X, y)

    os.makedirs(FRAUD_MODEL_DIR, exist_ok=True)
    model_path = os.path.join(FRAUD_MODEL_DIR, "model.pkl")
    
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
        
    logger.info(f"✅ Fraud Logistic Regression model successfully saved to: {model_path}")

if __name__ == "__main__":
    logger.info("==================================================")
    logger.info("   Starting Cyber Security Model Training Engine   ")
    logger.info("==================================================")
    
    train_anomaly_model()
    train_fraud_model()
    
    logger.info("==================================================")
    logger.info("   Model Training Complete!                      ")
    logger.info("==================================================")
