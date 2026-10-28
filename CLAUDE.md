# SentinelSOAR — project rules

Containerized Intrusion Detection (IDS) & Automated Threat Response Pipeline.
GitHub repo: `yp012/sentinel` (default branch `main`).

## Environment
- Local dev uses the existing `.venv` (Python 3.12). Do not recreate it.
- Code must run on Python 3.10–3.12 (CI matrix). Docker images use `python:3.11-slim`.
- Docker is Rancher Desktop: use `docker compose` (v2 syntax), never `docker-compose`.
- Extend `.gitignore`; never overwrite it.

## Architecture
- Package `sentinel/` is shared by the engine, the simulator, and the benchmark.
  - `parsers/` raw log lines -> `Event`
  - `detection/` detectors + engine
  - `intel/` threat intel (AbuseIPDB)
  - `soar/` response actions (firewall, sessions, webhook, playbooks)
- `dashboard/` Streamlit UI, `simulator/` attack/traffic generator,
  `scripts/` benchmark + README metrics updater.

## Data contracts
- Every normalized event is a pydantic model `Event` (`sentinel/models.py`):
  - `ts`: timezone-aware UTC `datetime`
  - `source`: `"ssh" | "nginx" | "pacs" | "vpn"`
  - `event_type`: str
  - `src_ip`: str
  - `user`: str
  - `raw`: str (original log line)
  - `fields`: dict
  - `label`: optional ground-truth tag. **Only the simulator/benchmark may read or
    set it. Detection logic must never look at `label`.**
- Every detector implements `Detector.evaluate(event) -> list[Alert]`.
- `Alert` has: `id`, `rule_id`, `title`, `mitre_technique`,
  `severity` (`Low | Medium | High | Critical`), `src_ip`, `user`,
  `evidence` (dict), `created_at`, `detected_at_ns` (monotonic ns captured at event
  ingestion, used for MTTD math).

## Safety rules
- Firewall enforcement is **simulated by default**: an in-memory + JSON-file rule
  table that renders iptables-style command strings. Real iptables is used only when
  `SENTINEL_REAL_FIREWALL=1`. Never execute shell commands by default.
- No network access in tests. AbuseIPDB must have a deterministic mock mode when
  `ABUSEIPDB_API_KEY` is unset.
- All thresholds live in `sentinel/config.py` and are env-overridable.

## Quality gates
- `flake8` must pass (config in `setup.cfg`, max-line-length 100).
- `bandit -c bandit.yaml -r .` must report no HIGH findings.
- `pytest` must pass without network access.

## Git
- Never commit secrets.
- Never run `git commit` or `git push`. The owner does that.
