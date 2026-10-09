import os

workspace = r"d:\SentinelVault"

files = {
    "Makefile": """\
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
""",
    ".pre-commit-config.yaml": """\
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.3.5
    hooks:
      - id: ruff
        args: [ --fix ]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.1.0
    hooks:
      - id: prettier
        types_or: [javascript, jsx, ts, tsx, json, yaml, markdown]
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-added-large-files
        args: ['--maxkb=5000']
  - repo: local
    hooks:
      - id: forbid-env-files
        name: forbid .env files
        entry: '.*\.env.*$'
        language: fail
        files: '.*\.env.*$'
        exclude: '\.env\.example'
  - repo: https://github.com/zricethezav/gitleaks
    rev: v8.18.2
    hooks:
      - id: gitleaks
""",
    ".github/workflows/ci.yml": """\
name: CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: password
          POSTGRES_DB: sentinelvault_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4.1.1
      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: "0.4.x"
      - name: Set up Python
        uses: actions/setup-python@v5.0.0
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: uv sync
      - name: Lint (Ruff)
        run: uv run ruff check .
      - name: Typecheck (Mypy)
        run: uv run mypy .
      - name: Test (Pytest)
        env:
          DATABASE_URL: postgresql://postgres:password@localhost:5432/sentinelvault_test
          REDIS_URL: redis://localhost:6379/0
        run: uv run pytest

  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.1
      - name: Setup Node
        uses: actions/setup-node@v4.0.2
        with:
          node-version: 20
      - name: Setup pnpm
        uses: pnpm/action-setup@v3.0.0
        with:
          version: 9.x
      - name: Install dependencies
        run: pnpm install --frozen-lockfile
      - name: Lint
        run: pnpm -r lint
      - name: Typecheck
        run: pnpm -r typecheck
      - name: Test
        run: pnpm -r test
      - name: Build
        run: pnpm -r build
""",
    "docker-compose.yml": """\
version: '3.8'

services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-password}
      POSTGRES_DB: ${POSTGRES_DB:-sentinelvault}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./infra/postgres/init:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD:-password} --appendonly no --maxmemory-policy volatile-lru
    ports:
      - "127.0.0.1:6379:6379"
    healthcheck:
      test: ["CMD-SHELL", "redis-cli -a $${REDIS_PASSWORD:-password} ping | grep PONG"]
      interval: 5s
      timeout: 5s
      retries: 5

  mailpit:
    image: axllent/mailpit
    ports:
      - "127.0.0.1:1025:1025"
      - "127.0.0.1:8025:8025"
    environment:
      MP_MAX_MESSAGES: 500

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:9001:9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER:-admin}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:-admin123}
    volumes:
      - minio_data:/data

  minio-init:
    image: minio/mc
    depends_on:
      - minio
    entrypoint: >
      /bin/sh -c "
      until mc config host add minio http://minio:9000 $${MINIO_ROOT_USER:-admin} $${MINIO_ROOT_PASSWORD:-admin123}; do sleep 1; done;
      mc mb minio/sv-backups || true;
      mc policy set private minio/sv-backups;
      exit 0;
      "

  migrate:
    build:
      context: ./backend
    command: alembic upgrade head
    environment:
      - DATABASE_URL=postgresql://${POSTGRES_MIGRATOR_USER:-sv_migrator}:${POSTGRES_MIGRATOR_PASSWORD:-migpassword}@postgres:5432/${POSTGRES_DB:-sentinelvault}
    depends_on:
      postgres:
        condition: service_healthy

  backend:
    build:
      context: ./backend
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - DATABASE_URL=postgresql://${POSTGRES_APP_USER:-sv_app}:${POSTGRES_APP_PASSWORD:-apppassword}@postgres:5432/${POSTGRES_DB:-sentinelvault}
      - REDIS_URL=redis://:${REDIS_PASSWORD:-password}@redis:6379/0
      - SMTP_SERVER=mailpit
      - SMTP_PORT=1025
    depends_on:
      migrate:
        condition: service_completed_successfully

  worker:
    build:
      context: ./backend
    command: celery -A app.worker.celery worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://${POSTGRES_APP_USER:-sv_app}:${POSTGRES_APP_PASSWORD:-apppassword}@postgres:5432/${POSTGRES_DB:-sentinelvault}
      - REDIS_URL=redis://:${REDIS_PASSWORD:-password}@redis:6379/0
    depends_on:
      migrate:
        condition: service_completed_successfully
      redis:
        condition: service_healthy

  frontend:
    build:
      context: ./frontend
    command: pnpm dev
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
    depends_on:
      - backend

volumes:
  postgres_data:
  minio_data:
""",
    "infra/postgres/init/01-roles.sql": """\
-- Create migrator role (DDL, schema owner)
CREATE ROLE sv_migrator WITH LOGIN PASSWORD 'migpassword';
GRANT ALL PRIVILEGES ON DATABASE sentinelvault TO sv_migrator;
GRANT ALL ON SCHEMA public TO sv_migrator;

-- Create app role (DML only)
CREATE ROLE sv_app WITH LOGIN PASSWORD 'apppassword';
GRANT CONNECT ON DATABASE sentinelvault TO sv_app;
GRANT USAGE ON SCHEMA public TO sv_app;

-- Ensure sv_app can access newly created tables/sequences by sv_migrator
ALTER DEFAULT PRIVILEGES FOR ROLE sv_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sv_app;

ALTER DEFAULT PRIVILEGES FOR ROLE sv_migrator IN SCHEMA public
    GRANT SELECT, UPDATE ON SEQUENCES TO sv_app;
""",
    ".env.example": """\
# Database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=fake_pg_password
POSTGRES_DB=sentinelvault

# Migrator User
POSTGRES_MIGRATOR_USER=sv_migrator
POSTGRES_MIGRATOR_PASSWORD=fake_migrator_password

# App User
POSTGRES_APP_USER=sv_app
POSTGRES_APP_PASSWORD=fake_app_password

# Redis
REDIS_PASSWORD=fake_redis_password

# MinIO
MINIO_ROOT_USER=admin
MINIO_ROOT_PASSWORD=fake_minio_password

# SentinelVault Secrets
SV_SECRET_KEY=fake_secret_key_12345
SV_JWT_SECRET=fake_jwt_secret_67890
SV_ENCRYPTION_KEY=fake_encryption_key_abcdef
""",
    "scripts/gen-secrets.sh": """\
#!/bin/bash
set -e

generate_secret() {
    openssl rand -hex 32
}

echo "Generating random secrets for SV_* variables in .env.example..."

echo "SV_SECRET_KEY=$(generate_secret)"
echo "SV_JWT_SECRET=$(generate_secret)"
echo "SV_ENCRYPTION_KEY=$(generate_secret)"
""",
    "pnpm-workspace.yaml": """\
packages:
  - 'packages/*'
  - 'frontend'
""",
    "docs/DEVELOPMENT.md": """\
# Development Guide

## Prerequisites
- Docker & Docker Compose
- pnpm
- uv (Python)
- make

## Getting Started
1. `make init` (or manually configure .env)
2. `make up`

## Ports
- Frontend: 3000
- Backend: 8000
- Postgres: 5432
- Redis: 6379
- Mailpit UI: 8025
- Minio UI: 9001

## Credentials
Check `.env.example` for defaults.

## Testing
- `make test`
- `make e2e`

## Debugging
- `make logs`
- `make ps`
""",
    "docs/TESTING.md": """\
# Testing Strategy

- Unit tests for all pure functions in packages
- Integration tests for API endpoints using pytest
- E2E tests for the frontend using playwright/cypress
""",
    "docs/DATABASE.md": """\
# Database Configuration

- App user `sv_app` has restricted DML only permissions
- Migrations use `sv_migrator` which owns the schema
- Migrations run via Alembic
""",
    "docs/API.md": """\
# API Documentation

## Conventions
- Follow ARCHITECTURE §13.
- Use camelCase for JSON keys in responses.
- Standard error format.
- Pagination format.
""",
    "README.md": """\
# SentinelVault

## Quick Start
```bash
cp .env.example .env
make up
```
"""
}

# Create package skeletons
package_names = ["crypto-core", "schemas", "domain-match"]
for pkg in package_names:
    files[f"packages/{pkg}/package.json"] = f"""\
{{
  "name": "@sentinelvault/{pkg}",
  "version": "0.1.0",
  "type": "module",
  "exports": {{
    ".": "./dist/index.js"
  }},
  "scripts": {{
    "build": "tsup",
    "test": "vitest run"
  }},
  "devDependencies": {{
    "tsup": "^8.0.0",
    "typescript": "^5.0.0",
    "vitest": "^1.0.0"
  }}
}}
"""
    files[f"packages/{pkg}/tsconfig.json"] = """\
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
"""
    files[f"packages/{pkg}/tsup.config.ts"] = """\
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
});
"""
    files[f"packages/{pkg}/vitest.config.ts"] = """\
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
  },
});
"""
    files[f"packages/{pkg}/src/index.ts"] = f"""\
export const VERSION = "0.1.0";
export const packageName = "{pkg}";
"""
    files[f"packages/{pkg}/src/index.test.ts"] = f"""\
import {{ expect, test }} from 'vitest';
import {{ VERSION, packageName }} from './index';

test('exports correct version and name', () => {{
  expect(VERSION).toBe('0.1.0');
  expect(packageName).toBe('{pkg}');
}});
"""

for rel_path, content in files.items():
    abs_path = os.path.join(workspace, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, 'w', encoding='utf-8') as f:
        f.write(content)

print("Scaffolding complete.")
