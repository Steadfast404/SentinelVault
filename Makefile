.PHONY: up down logs ps migrate revision psql fmt lint typecheck test check types e2e clean

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

migrate:
	docker compose exec backend alembic upgrade head

revision:
	@read -p "Message: " m; docker compose exec backend alembic revision --autogenerate -m "$$m"

psql:
	docker compose exec postgres psql -U postgres -d sentinelvault

fmt:
	uv run ruff format .
	pnpm -r format

lint:
	uv run ruff check .
	pnpm -r lint

typecheck:
	uv run mypy .
	pnpm -r typecheck

test:
	uv run pytest
	pnpm -r test

check: lint typecheck test
	@echo "Checking types freshness..."
	make types

types:
	@echo "Generating OpenAPI to TS"
	# Placeholder for generation logic

e2e:
	@echo "Running e2e tests"
	pnpm run e2e

clean:
	docker compose down -v
	rm -rf dist node_modules packages/*/dist packages/*/node_modules
