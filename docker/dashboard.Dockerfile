# SentinelSOAR SOC dashboard (Streamlit on :8501). Reads the engine API at ENGINE_URL.
FROM python:3.11-slim

# Headless: no email prompt, no browser launch, no usage stats, no file watcher.
# Hiding the welcome banner also stops its outbound "External URL" public-IP lookup.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    HOME=/tmp \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    STREAMLIT_SERVER_RUN_ON_SAVE=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_LOGGER_HIDE_WELCOME_MESSAGE=true

WORKDIR /app

COPY requirements-dashboard.txt ./
RUN pip install --no-cache-dir -r requirements-dashboard.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel

COPY .streamlit/config.toml ./.streamlit/config.toml
COPY dashboard/ ./dashboard/

USER sentinel
EXPOSE 8501

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"]

CMD ["streamlit", "run", "dashboard/app.py"]
