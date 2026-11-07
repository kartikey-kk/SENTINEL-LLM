#!/bin/sh
# Apply database migrations, then start the given command.
set -e

if [ "${SENTINEL_SKIP_MIGRATIONS:-false}" != "true" ]; then
  echo "[entrypoint] applying database migrations"
  alembic upgrade head
fi

exec "$@"
