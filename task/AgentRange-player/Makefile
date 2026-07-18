.PHONY: up down test seed smoke generate replay

up:
	docker compose up -d --build

down:
	docker compose down -v

test:
	pytest -q

seed:
	POSTGRES_HOST=localhost POSTGRES_PORT=55432 python backends/customer-db/seed.py

smoke:
	curl -fsS http://localhost:8100/health >/dev/null

generate:
	python corpus-generator/generate.py

replay:
	python scenario-runner/runner.py $(SCENARIO)
