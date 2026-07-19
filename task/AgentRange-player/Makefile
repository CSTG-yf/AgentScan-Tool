.PHONY: up down test seed smoke generate replay contracts static-scan rules attack-chain benchmark-summary report clean-reports

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

contracts:
	pytest -q contracts

static-scan:
	python integration/static_inventory.py --output integration/reports/static-scan.json

rules:
	python integration/rule_contract.py --output integration/reports/rule-contract.json

attack-chain:
	python integration/attack_chain.py --output integration/reports/attack-chains.json

benchmark-summary:
	python bench/benchmark.py summarize

report:
	python integration/report.py

clean-reports:
	python -c "import pathlib,shutil; [shutil.rmtree(p, ignore_errors=True) for p in (pathlib.Path('integration/reports'), pathlib.Path('bench/results'))]"
