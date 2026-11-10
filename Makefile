# SentinelSOAR developer shortcuts. Uses the repo .venv when present.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: up down test lint bench logs

up: ## Build and start the cyber range (engine :8000, dashboard :8501, simulator)
	mkdir -p data
	docker compose up --build -d

down: ## Stop and remove the stack (data/ is kept)
	docker compose down

test: ## Run the test suite (no network access needed)
	$(PYTHON) -m pytest -q

lint: ## flake8 + bandit (fails on HIGH findings)
	$(PYTHON) -m flake8
	$(PYTHON) -m bandit -q -c bandit.yaml -r . -lll

# scripts/benchmark_soar.py is still an empty placeholder; this target is ready for it.
bench: ## Run the SOAR detection/response benchmark
	$(PYTHON) scripts/benchmark_soar.py

logs: ## Follow logs from all services
	docker compose logs -f
