# db.py
import os
import sys
import time
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

logger = logging.getLogger("cyber.db")

# Load environment variables
load_dotenv()

# We resolve the Database URL in order of priority:
# 1. DATABASE_URL environment variable in current process/env
# 2. DATABASE_URL in e_commerce/backend/.env
# 3. Default local postgres fallback
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    # Try looking in e-commerce backend .env file
    for env_path in ["../../e_commerce/backend/.env", "../e_commerce/backend/.env", "e_commerce/backend/.env"]:
        abs_path = os.path.abspath(env_path)
        if os.path.exists(abs_path):
            try:
                with open(abs_path, "r") as f:
                    for line in f:
                        if line.strip().startswith("DATABASE_URL="):
                            val = line.split("=", 1)[1].strip()
                            if val:
                                DATABASE_URL = val
                                logger.info(f"Loaded DATABASE_URL from {env_path}")
                                break
            except Exception as e:
                logger.warning(f"Failed to read env file {env_path}: {e}")
        if DATABASE_URL:
            break

if not DATABASE_URL:
    # Fallback to standard local postgres configuration
    DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/cyber_security"
    logger.warning(f"No DATABASE_URL found. Defaulting to local: {DATABASE_URL}")

# Create engine (enable connection pool settings suitable for multi-process database operations)
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_recycle=300,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency for getting a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes schema tables using schema.sql DDL."""
    try:
        db_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(db_dir, "schema.sql")
        
        if not os.path.exists(schema_path):
            logger.error(f"schema.sql not found at {schema_path}!")
            return False
            
        with open(schema_path, "r") as f:
            schema_ddl = f.read()
            
        # Execute schema DDL statements
        with engine.connect() as conn:
            # PostgreSQL requires transactions to run separate DDL scripts.
            # Split commands by semicolon or execute them in a single block.
            conn.execute(text(schema_ddl))
            conn.commit()
            
        logger.info("PostgreSQL database tables initialized successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize database tables: {e}")
        return False

if __name__ == "__main__":
    # Test connection and initialize tables when run directly
    logging.basicConfig(level=logging.INFO)
    logger.info("Testing database connection with retries...")
    
    success = False
    for attempt in range(1, 11):
        logger.info(f"Database initialization attempt {attempt}/10...")
        if init_db():
            logger.info("Database connection and initialization SUCCEEDED.")
            success = True
            break
        else:
            logger.warning(f"Database initialization failed on attempt {attempt}. Retrying in 3 seconds...")
            time.sleep(3)
            
    if not success:
        logger.error("Database connection or initialization FAILED after 10 attempts.")
        sys.exit(1)
