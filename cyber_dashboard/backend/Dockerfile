FROM python:3.12-slim

# Install system dependencies for psycopg2 and other packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Expose port 8001 for FastAPI
EXPOSE 8001

# Command is overridden in docker-compose.yml for consumers
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
