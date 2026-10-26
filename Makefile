.PHONY: install lint fmt test test-all eval eval-rules run

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

eval:
	uv run python eval/run.py --mode all

eval-rules:
	uv run python eval/run.py --mode rules

run:
	uv run uvicorn agentwarden.daemon:app --host 127.0.0.1 --port 8765
