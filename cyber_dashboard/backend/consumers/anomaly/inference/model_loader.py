# model_loader.py
import os
import pickle
import logging
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.anomaly.loader")

class AnomalyModelLoader:
    def __init__(self, model_dir: str = None):
        if not model_dir:
            # Resolve to root-level backend/models/anomaly
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            self.model_dir = os.path.join(backend_dir, "models", "anomaly")
        else:
            self.model_dir = model_dir
            
        self.model_path = os.path.join(self.model_dir, "model.pkl")
        self.last_loaded_time = 0
        self.model = None

    def load_model(self):
        """Loads or reloads the Isolation Forest model if it has been updated on disk."""
        if not os.path.exists(self.model_path):
            # Model file doesn't exist yet (not trained)
            return None
            
        try:
            mtime = os.path.getmtime(self.model_path)
            if mtime > self.last_loaded_time or self.model is None:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                self.last_loaded_time = mtime
                logger.info(f"Loaded new anomaly detection model from {self.model_path}")
        except Exception as e:
            logger.error(f"Error loading model from {self.model_path}: {e}")
            
        return self.model
