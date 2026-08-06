#!/bin/sh
set -e

# If a sub-command was provided (e.g. the celery worker command), exec it as-is
# so the image entrypoint can serve both the API and the worker container.
if [ -n "$1" ]; then
  exec "$@"
fi

# Default mode: run migrations, then start the API server.
if [ "${SKIP_MIGRATIONS:-0}" != "1" ]; then
  echo "[entrypoint] running alembic migrations..."
  alembic upgrade head
fi

WORKERS="${UVICORN_WORKERS:-1}"
GRACEFUL="${UVICORN_GRACEFUL_TIMEOUT:-30}"

echo "[entrypoint] starting uvicorn with ${WORKERS} worker(s), graceful timeout ${GRACEFUL}s"
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers "${WORKERS}" \
  --timeout-graceful-shutdown "${GRACEFUL}"
