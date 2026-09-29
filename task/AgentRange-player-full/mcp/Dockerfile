FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir fastapi==0.111.0 "uvicorn[standard]==0.30.1" httpx==0.27.0
COPY _base/mcp_base ./mcp_base
COPY . ./mcp_pkgs
COPY managed-host.env /app/.env
ENV SERVER=shell_runner.server
CMD ["sh", "-c", "PYTHONPATH=/app:/app/mcp_pkgs uvicorn ${SERVER}:app --host 0.0.0.0 --port 8000"]
