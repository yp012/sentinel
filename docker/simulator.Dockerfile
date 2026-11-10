# SentinelSOAR attack/traffic simulator: POSTs generated log lines to ENGINE_URL/ingest.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements-simulator.txt ./
RUN pip install --no-cache-dir -r requirements-simulator.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel

COPY simulator/ ./simulator/

USER sentinel

# No HEALTHCHECK: the simulator serves nothing to probe, and it already waits on the
# engine's /health and retries by itself, so "running" is the only meaningful state.
CMD ["python", "-m", "simulator.simulate"]
