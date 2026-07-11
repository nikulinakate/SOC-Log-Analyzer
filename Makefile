.PHONY: install run test lint format docker-up docker-down demo-linux demo-windows

install:
	python -m pip install -e ".[dev]"

run:
	uvicorn app.main:app --reload

test:
	pytest --cov=app --cov-report=term-missing

lint:
	ruff check .
	mypy app

format:
	ruff format .
	ruff check --fix .

docker-up:
	docker compose up --build

docker-down:
	docker compose down

demo-linux:
	curl -sS -X POST "http://localhost:8000/api/v1/analyze/file?source_type=linux_auth" -F "file=@samples/linux_auth.log" | python -m json.tool

demo-windows:
	curl -sS -X POST "http://localhost:8000/api/v1/analyze/file?source_type=windows_json" -F "file=@samples/windows_events.json" | python -m json.tool
