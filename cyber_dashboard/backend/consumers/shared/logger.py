# logger.py
import logging
import sys

def setup_logger(name: str, level=logging.INFO) -> logging.Logger:
    """Configures a standardized logger outputting to stderr."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] (%(process)d): %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger
