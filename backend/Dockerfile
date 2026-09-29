FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory for SQLite
RUN mkdir -p /data

EXPOSE 8000 5514/udp 5514/tcp

ENV ULPF_DB_PATH=/data/ulpf.db
ENV ULPF_PLUGINS_DIR=/app/parser_engine/plugins
ENV ULPF_CONFIG_DIR=/app/config

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
