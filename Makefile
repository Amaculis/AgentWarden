.PHONY: install lint fmt test test-all eval eval-rules eval-scan redteam run

MODE ?= all
ROUNDS ?= 1
BATCH ?= 5

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

test:
	uv run pytest -q -m "not slow"

test-all:
	uv run pytest -q

# Action eval. MODE = all | rules | local | spark | cascade
eval:
	uv run python eval/run.py --set actions --mode $(MODE)

eval-rules:
	uv run python eval/run.py --set actions --mode rules

# Scanner eval on eval/content/
eval-scan:
	uv run python eval/run.py --set content

# Meta red-team loop (Muse Spark generates attacks, cascade defends)
redteam:
	uv run python redteam/run.py --rounds $(ROUNDS) --batch $(BATCH)

run:
	uv run uvicorn agentwarden.daemon:app --host 127.0.0.1 --port 8765
