FROM python:3.11-slim

# Install iputils-ping and curl for diagnostics & Wiz Defend runtime sensor demos
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Deliberate IaC/Container demo posture issue: running as root (detected by Wiz Code & Wiz Cloud)
USER root

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
