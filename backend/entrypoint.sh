#!/bin/bash
set -e

if [ "$1" = 'api' ]; then
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
elif [ "$1" = 'worker' ]; then
    exec python -m app.worker
elif [ "$1" = 'migrate' ]; then
    exec alembic upgrade head
else
    exec "$@"
fi
