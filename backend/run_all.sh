#!/usr/bin/env bash
#
# run_all.sh — boot the whole ECDAT backend stack in one go.
#
#   * applies pending Django migrations            (disable: --no-migrate)
#   * starts the huey task consumer / worker        (the only worker)
#   * starts the Django API dev server              (foreground)
#
# Ctrl+C (or SIGTERM/SIGINT) shuts down the server AND the worker cleanly.
#
# Usage:
#   ./run_all.sh                 # defaults: host 127.0.0.1, port 8000
#   ./run_all.sh --port 9000 --host 0.0.0.0
#   ./run_all.sh --workers 4     # pass a huey worker-count
#   ./run_all.sh --no-migrate
#
# Environment:
#   ECDAT_HOST, ECDAT_PORT, ECDAT_HUEY_WORKERS also honoured.
#   The app itself loads `.env` (viz. config/settings.py), so any
#   ECDAT_ACTIVE_MODE / DJANGO_* settings there apply automatically.
#
# Works in WSL / Git-Bash on Windows (venv/Scripts/python.exe) and on
# macOS / Linux (venv/bin/python).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# Python interpreter (venv-aware; supports POSIX and Windows venv layouts)
# ---------------------------------------------------------------------------
find_python() {
  for candidate in \
    "$ROOT/venv/bin/python" \
    "$ROOT/venv/Scripts/python.exe" \
    "$ROOT/.venv/bin/python" \
    "$ROOT/.venv/Scripts/python.exe"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  command -v python3 && return 0
  command -v python
}

PYTHON="$(find_python)" || { echo "ERROR: could not locate a python interpreter." >&2; exit 1; }
echo "[run_all] using python: $PYTHON"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
HOST="${ECDAT_HOST:-127.0.0.1}"
PORT="${ECDAT_PORT:-8000}"
WORKERS="${ECDAT_HUEY_WORKERS:-}"
DO_MIGRATE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --no-migrate) DO_MIGRATE=0; shift ;;
    -h|--help)
      sed -n '2,14p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      echo "Run '--help' for usage." >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [ ! -f "manage.py" ]; then
  echo "ERROR: manage.py not found in $ROOT" >&2
  exit 1
fi

mkdir -p logs

# ---------------------------------------------------------------------------
# 1. Migrations
# ---------------------------------------------------------------------------
if [ "$DO_MIGRATE" = "1" ]; then
  echo "[run_all] applying migrations (default)..."
  "$PYTHON" manage.py migrate --noinput
  echo "[run_all] applying migrations (demo)..."
  "$PYTHON" manage.py migrate --noinput --database=demo
fi

# ---------------------------------------------------------------------------
# 2. Huey worker (the only background worker)
# ---------------------------------------------------------------------------
HUEY_ARGS=(--loglevel INFO)
if [ -n "$WORKERS" ]; then
  HUEY_ARGS+=(--workers "$WORKERS")
fi

echo "[run_all] starting huey worker (crypto scans, analysis, mitigation)..."
"$PYTHON" manage.py run_huey "${HUEY_ARGS[@]}" > logs/huey.log 2>&1 &
HUEY_PID=$!

# ---------------------------------------------------------------------------
# 2b. Re-queue work a previous run left pending (scans/analyses/plans/chunks).
#     run_huey already sweeps at boot; this re-checks with the worker live so
#     any task enqueued here is picked up and completed immediately.
# ---------------------------------------------------------------------------
echo "[run_all] re-queuing any pending work left by the last run..."
"$PYTHON" manage.py sweep_pending || true

# ---------------------------------------------------------------------------
# 3. Django API server (foreground)
# ---------------------------------------------------------------------------
shutdown() {
  echo ""
  echo "[run_all] shutting down... (server then worker)"
  if kill -0 "$HUEY_PID" 2>/dev/null; then
    kill "$HUEY_PID" 2>/dev/null || true
    wait "$HUEY_PID" 2>/dev/null || true
  fi
  exit 0
}
trap shutdown INT TERM

echo "[run_all] worker pid $HUEY_PID — logs -> logs/huey.log"
echo "[run_all] starting django API server on http://$HOST:$PORT/ (logs -> logs/server.log)"

set +e
"$PYTHON" manage.py runserver "$HOST:$PORT" --noreload >> logs/server.log 2>&1
SERVER_EC=$?
set -e

echo "[run_all] API server exited (code $SERVER_EC) — see logs/server.log"
shutdown