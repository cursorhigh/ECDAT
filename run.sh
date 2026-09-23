#!/usr/bin/env bash
#
# run.sh — ECDAT full-stack launcher (backend API + worker + UI).
#
#   * asks which UI / frontend mode to use, then boots everything needed:
#       - django API server   (loopback only, default 127.0.0.1:8000)
#       - huey worker         (scans / analysis / mitigation jobs)
#       - selected UI         (browser dev, browser preview, desktop, or none)
#   * migrates both databases, re-queues pending work left by a previous run
#   * waits for a healthy backend before opening the UI
#   * reuses an already-running backend instead of starting a duplicate
#   * Ctrl+C (SIGINT/SIGTERM) shuts down the backend, worker, and UI cleanly
#
# Usage:
#   ./run.sh                                     # interactive mode menu
#   ./run.sh --mode browser-dev                  # non-interactive
#   ./run.sh --mode browser-preview --rebuild
#   ./run.sh --mode backend-only --skip-migrate
#
# Options:
#   --mode <browser-dev|browser-preview|desktop|backend-only>
#   --host <addr>        backend bind host   (default from ECDAT_HOST: 127.0.0.1)
#   --port <port>        backend bind port   (default from ECDAT_PORT: 8000)
#   --frontend-port <p>  UI dev/preview port (default ECDAT_FRONTEND_PORT: 3000)
#   --api-target <url>   public Django URL used by the UI (default NEXT_PUBLIC_API_BASE_URL: http://127.0.0.1:8000)
#   --rebuild            force `npm run build` before preview even when .next/BUILD_ID exists
#   --skip-migrate       don't run database migrations
#   --no-worker          don't start the huey worker (jobs will stay queued)
#   --no-sweep           don't re-queue pending work at boot
#   -h|--help            this help
#
# Environment: ECDAT_HOST, ECDAT_PORT, ECDAT_FRONTEND_PORT, NEXT_PUBLIC_API_BASE_URL,
#              ECDAT_HUEY_WORKERS (huey worker count) are honoured.
# Works in WSL / Git-Bash on Windows (venv/Scripts/python.exe) and on
# macOS / Linux (venv/bin/python).

set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
info() { echo "${CYAN}── ${BOLD}$*${RESET}"; }
step() { echo ""; echo "${GREEN}==> $*${RESET}"; }
warn() { echo "${YELLOW}WARN: $*${RESET}"; }
fail() { echo "${RED}ERROR: $*${RESET}"; }
ok()   { echo "${GREEN}OK: $*${RESET}"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

# ---------------------------------------------------------------------------
# Options / environment
# ---------------------------------------------------------------------------
HOST="${ECDAT_HOST:-127.0.0.1}"
PORT="${ECDAT_PORT:-8000}"
API_TARGET="${NEXT_PUBLIC_API_BASE_URL:-http://127.0.0.1:$PORT}"
WORKERS="${ECDAT_HUEY_WORKERS:-}"
FRONTEND_PORT=""
DO_MIGRATE=1
DO_WORKER=1
DO_SWEEP=1
REBUILD=0
MODE=""

usage() { sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="$2"; shift 2 ;;
    --api-target) API_TARGET="$2"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    --skip-migrate) DO_MIGRATE=0; shift ;;
    --no-worker) DO_WORKER=0; shift ;;
    --no-sweep) DO_SWEEP=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1"; echo "Run '$0 --help' for usage." >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Interpreter / toolchain detection
# ---------------------------------------------------------------------------
find_python() {
  for candidate in \
    "$BACKEND/venv/bin/python" \
    "$BACKEND/venv/Scripts/python.exe" \
    "$BACKEND/.venv/bin/python" \
    "$BACKEND/.venv/Scripts/python.exe"; do
    if [ -x "$candidate" ]; then echo "$candidate"; return 0; fi
  done
  command -v python3 && return 0
  command -v python
}

PYTHON="$(find_python)" || { fail "could not locate a python interpreter. Run backend/setup.sh first."; exit 1; }
info "python        : $PYTHON"

# Desktop capability check (Tauri shell is an optional, independently built piece)
DESKTOP_AVAILABLE=0
DESKTOP_NOTE=""
if [ -d "$ROOT/desktop" ] && [ -f "$ROOT/desktop/tauri.conf.json" ]; then
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    DESKTOP_AVAILABLE=1
  else
    DESKTOP_NOTE="(desktop/ exists but no Rust toolchain was found)"
  fi
else
  DESKTOP_NOTE="(no desktop/ Tauri shell has been built yet)"
fi

# ---------------------------------------------------------------------------
# Mode selection (interactive unless --mode given)
# ---------------------------------------------------------------------------
print_menu() {
  echo ""
  echo "${BOLD}Which UI / frontend mode should ECDAT run in?${RESET}"
  echo "  1) browser-dev      Browser UI + live Next.js dev server (HMR) + local backend"
  echo "  2) browser-preview  Browser UI, production build served locally + backend"
  echo "  3) desktop          Offline desktop shell (Tauri) + bundled backend"
  echo "  4) backend-only     Backend API + worker, no UI"
  if [ -n "$DESKTOP_NOTE" ]; then echo "     ${YELLOW}desktop not available: $DESKTOP_NOTE${RESET}"; fi
}

if [ -z "$MODE" ]; then
  if [ ! -t 0 ]; then
    fail "stdin is not a terminal. Pass --mode (browser-dev|browser-preview|desktop|backend-only) or run interactively."
    exit 1
  fi
  print_menu
  while true; do
    printf "Enter choice [1-4] (default 1): "
    read -r CHOICE
    CHOICE="${CHOICE:-1}"
    case "$CHOICE" in
      1) MODE="browser-dev"; break ;;
      2) MODE="browser-preview"; break ;;
      3) MODE="desktop"; break ;;
      4) MODE="backend-only"; break ;;
      *) warn "invalid choice '$CHOICE' (1-4)"; ;;
    esac
  done
fi

case "$MODE" in
  browser-dev|browser-preview|desktop|backend-only) ;;
  *) fail "unknown --mode '$MODE' (browser-dev|browser-preview|desktop|backend-only)"; exit 1 ;;
esac

if [ "$MODE" = "desktop" ]; then
  if [ "$DESKTOP_AVAILABLE" != "1" ]; then
    fail "desktop mode is not available on this machine${DESKTOP_NOTE:+: $DESKTOP_NOTE}."
    fail "Use 'browser-dev' or 'browser-preview' instead — the same frontend build runs in a browser."
    exit 1
  fi
fi

if [ "$MODE" != "backend-only" ]; then
  command -v node >/dev/null 2>&1 || { fail "node not found — required for the '$MODE' UI."; exit 1; }
  command -v npm >/dev/null 2>&1 || { fail "npm not found — required for the '$MODE' UI."; exit 1; }
  if [ ! -d "$FRONTEND" ] || [ ! -f "$FRONTEND/package.json" ]; then
    fail "frontend/ not found at $FRONTEND — browser UI cannot start."
    exit 1
  fi
fi

[ "$MODE" = "browser-dev" ] && FRONTEND_PORT="${FRONTEND_PORT:-3000}"
[ "$MODE" = "browser-preview" ] && FRONTEND_PORT="${FRONTEND_PORT:-3000}"

step "Selected mode: $MODE"

# ---------------------------------------------------------------------------
# Backend pre-flight
# ---------------------------------------------------------------------------
cd "$BACKEND"
if [ ! -f "manage.py" ]; then fail "manage.py not found in $BACKEND"; exit 1; fi

command -v curl >/dev/null 2>&1 || { fail "curl not found — needed for the health check."; exit 1; }

# Reuse an already-running backend — or prompt to kill it for a fresh start.
HEALTH_URL="http://127.0.0.1:$PORT/api/health/"
EXISTING=0
if curl --silent --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
  EXISTING=1
  ANSWER=""
  if [ -t 0 ]; then
    warn "a backend is already running at http://127.0.0.1:$PORT/ "
    printf "Kill it and restart fresh (incl. huey worker)? [y/N] "
    read -r ANSWER
  fi
  case "$ANSWER" in
    y|Y|yes)
      info "stopping the existing backend + worker..."
      if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command "Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { cmd.exe /c 'taskkill /PID \$_ /T /F' | Out-Null }"
        powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { \$_.Name -like 'python*' -and \$_.CommandLine -like '*run_huey*' } | Select-Object -ExpandProperty ProcessId | ForEach-Object { cmd.exe /c 'taskkill /PID \$_ /T /F' | Out-Null }"
      else
        lsof -ti tcp:"$PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
        pkill -f run_huey 2>/dev/null || true
      fi
      sleep 1
      EXISTING=0
      ;;
    *)
      info "reusing the already-running backend (no duplicate started)."
      ;;
  esac
fi

SRV_PID=""
HUEY_PID=""

cleanup() {
  echo ""
  echo "[run.sh] shutting down any processes we started..."
  if [ -n "$HUEY_PID" ] && kill -0 "$HUEY_PID" 2>/dev/null; then
    kill "$HUEY_PID" 2>/dev/null || true
    wait "$HUEY_PID" 2>/dev/null || true
  fi
  if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
  fi
  ok "all ECDAT processes stopped."
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------------------
# 1. Migrations
# ---------------------------------------------------------------------------
if [ "$EXISTING" = "1" ]; then
  info "skipping migrations/worker — external backend is already serving this port."
elif [ "$DO_MIGRATE" = "1" ]; then
  step "Applying migrations (default + demo databases)"
  "$PYTHON" manage.py migrate --noinput
  "$PYTHON" manage.py migrate --noinput --database=demo
  ok "migrations applied"
else
  warn "migrations skipped (--skip-migrate)"
fi

# ---------------------------------------------------------------------------
# 2. Worker (huey) + pending-work sweep
# ---------------------------------------------------------------------------
if [ "$EXISTING" != "1" ] && [ "$DO_WORKER" = "1" ]; then
  step "Starting huey worker (scans / analysis / mitigation jobs)"
  mkdir -p logs
  HUEY_ARGS=(--loglevel INFO)
  if [ -n "$WORKERS" ]; then HUEY_ARGS+=(--workers "$WORKERS"); fi
  "$PYTHON" manage.py run_huey "${HUEY_ARGS[@]}" > logs/huey.log 2>&1 &
  HUEY_PID=$!
  ok "worker pid $HUEY_PID — logs -> backend/logs/huey.log"

  if [ "$DO_SWEEP" = "1" ]; then
    info "re-queuing pending work left by a previous run..."
    "$PYTHON" manage.py sweep_pending >/dev/null 2>&1 || true
  fi
else
  info "skipping worker (--no-worker or external backend in use)"
fi

# ---------------------------------------------------------------------------
# 3. API server (background unless backend-only)
# ---------------------------------------------------------------------------
if [ "$EXISTING" = "1" ]; then
  : # nothing to start
elif [ "$MODE" = "backend-only" ]; then
  step "Starting Django API server (foreground) on http://$HOST:$PORT/"
  mkdir -p logs
  set +e
  "$PYTHON" manage.py runserver "$HOST:$PORT" --noreload 2>&1 | tee -a logs/server.log
  RUN_EC=${PIPESTATUS[0]}
  set -e
  echo "[run.sh] API server exited (code $RUN_EC) — see backend/logs/server.log"
  exit $RUN_EC
else
  step "Starting Django API server on http://$HOST:$PORT/ (logs -> backend/logs/server.log)"
  mkdir -p logs
  "$PYTHON" manage.py runserver "$HOST:$PORT" --noreload >> logs/server.log 2>&1 &
  SRV_PID=$!
fi

# ---------------------------------------------------------------------------
# 4. Health readiness gate
# ---------------------------------------------------------------------------
if [ "$EXISTING" != "1" ]; then
  step "Waiting for backend health at $HEALTH_URL"
  ATTEMPTS=0
  until curl --silent --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ $ATTEMPTS -ge 40 ]; then
      fail "backend did not become healthy after ~40s. Check backend/logs/server.log"
      fail "and, if the port was occupied, re-run with --port <free port>."
      exit 1
    fi
    sleep 1
  done
  ok "backend is healthy"
fi

# ---------------------------------------------------------------------------
# 5. UI
# ---------------------------------------------------------------------------
case "$MODE" in
  backend-only)
    ok "backend running. API: http://$HOST:$PORT/api/  (health: $HEALTH_URL)"
    echo "Press Ctrl+C to stop."
    wait
    ;;

  browser-dev)
    step "Starting Next.js dev server on port $FRONTEND_PORT (Django API: $API_TARGET)"
    if [ ! -f "$FRONTEND/.env" ]; then cp "$FRONTEND/.env.example" "$FRONTEND/.env"; fi
    cd "$FRONTEND"
    NEXT_PUBLIC_API_BASE_URL="$API_TARGET" npm run dev -- -p "$FRONTEND_PORT"
    ;;

  browser-preview)
    if [ ! -f "$FRONTEND/.env" ]; then cp "$FRONTEND/.env.example" "$FRONTEND/.env"; fi
    if [ "$REBUILD" = "1" ] || [ ! -f "$FRONTEND/.next/BUILD_ID" ]; then
      step "Building production frontend..."
      cd "$FRONTEND"
      npm run build
    else
      info "using existing frontend/.next — pass --rebuild to rebuild."
    fi
    step "Serving built frontend on port $FRONTEND_PORT (Django API: $API_TARGET)"
    cd "$FRONTEND"
    NEXT_PUBLIC_API_BASE_URL="$API_TARGET" npm run start -- -p "$FRONTEND_PORT"
    ;;

  desktop)
    info "launching Tauri desktop shell..."
    cd "$ROOT/desktop"
    npm install >/dev/null 2>&1 || true
    npm run tauri -- dev
    ;;
esac

# ---------------------------------------------------------------------------
# Only reached when the UI exits (its own process); stop the backend after.
# ---------------------------------------------------------------------------
exit 0