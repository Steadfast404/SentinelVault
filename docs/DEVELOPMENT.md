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
