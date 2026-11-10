# SentinelSOAR detection + SOAR engine (FastAPI on :8000). State lives under /data.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SENTINEL_DATA_DIR=/data \
    SENTINEL_DB_PATH=/data/incidents.db

WORKDIR /app

COPY requirements-engine.txt ./
RUN pip install --no-cache-dir -r requirements-engine.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /data && chown sentinel:sentinel /data

COPY sentinel/ ./sentinel/

USER sentinel
EXPOSE 8000
VOLUME ["/data"]

# slim has no curl: probe /health with urllib and require status "ok".
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import json,sys,urllib.request as u; r=u.urlopen('http://127.0.0.1:8000/health', timeout=4); sys.exit(0 if json.load(r).get('status') == 'ok' else 1)"]

CMD ["uvicorn", "sentinel.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
