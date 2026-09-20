#!/usr/bin/env bash
#
# ECDAT backend — full automated setup (Linux, macOS, Git-Bash/WSL on Windows).
#
# - Creates & activates a virtual environment (backend/venv)
# - Installs Python dependencies from requirements.txt
# - Sets up .env from .env.example (with a generated secret key)
# - Runs migrations on both the 'actual' (db.sqlite3) and 'demo' (demo.sqlite3) DBs
# - Seeds demo data
# - Runs checks (Django check + API smoke test) and reports whether all is good
#
# Usage:
#   bash setup.sh              # non-interactive, full default setup
#   bash setup.sh --skip-seed  # skip demo seeding
#   bash setup.sh --help
#
set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

info()  { echo "${CYAN}── ${BOLD}$*${RESET}"; }
step()  { echo ""; echo "${GREEN}==> $*${RESET}"; }
warn()  { echo "${YELLOW}WARN: $*${RESET}"; }
fail()  { echo "${RED}ERROR: $*${RESET}"; }
ok()    { echo "${GREEN}OK: $*${RESET}"; }

SEED_DEMO=1
for arg in "$@"; do
  case "$arg" in
    --skip-seed) SEED_DEMO=0 ;;
    --help|-h)
      echo "ECDAT backend setup.sh"
      echo "  bash setup.sh            full default setup + demo seed + checks"
      echo "  bash setup.sh --skip-seed  skip the demo-data seeding"
      exit 0
      ;;
  esac
done

# Backend root = where this script lives.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

info "ECDAT backend setup running in: $ROOT_DIR"

# ---------------------------------------------------------------------------
# Platform detection (Unix vs Windows Git-Bash/WSL)
# ---------------------------------------------------------------------------
IS_WINDOWS=0
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|*WSL*) IS_WINDOWS=1 ;;
esac

if [ "$IS_WINDOWS" = "1" ]; then
  PY="python"
  VENV_PY="$ROOT_DIR/venv/Scripts/python.exe"
  command -v "$PY" >/dev/null 2>&1 || PY="py -3"
else
  PY="python3"
  VENV_PY="$ROOT_DIR/venv/bin/python"
fi

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
step "Checking prerequisites"
if ! command -v "$PY" >/dev/null 2>&1; then
  fail "Python not found. Install Python 3.12+ and re-run. (searched for: $PY)"
  exit 1
fi
echo "  $("$PY" --version 2>&1 || true)"

# ---------------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------------
step "Virtual environment"
if [ -x "$VENV_PY" ]; then
  ok "virtual environment already present: $VENV_PY"
else
  info "creating venv..."
  "$PY" -m venv venv
  ok "created: $VENV_PY"
fi

# ---------------------------------------------------------------------------
# 3. Environment variables (.env)
# ---------------------------------------------------------------------------
step "Environment variables"
if [ -f "$ROOT_DIR/.env" ]; then
  ok ".env already exists — leaving it untouched. Review it before production:"
else
  info "creating .env from .env.example with a generated secret key..."
  if command -v openssl >/dev/null 2>&1; then
    SECRET="$(openssl rand -base64 48 | tr -d '\n=' )"
  else
    SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n=' || printf 'dev-%s' "$(date +%s)")"
  fi
  cp .env.example .env
  sed -i.bak "s/change_me_to_a_long_random_string/$SECRET/" .env && rm -f .env.bak
  ok "created .env with a generated DJANGO_SECRET_KEY"
fi

cat <<'ENVHELP'
  Key variables (edit .env when needed):
    DJANGO_SECRET_KEY   secret (a random one was generated for you)
    DJANGO_DEBUG        '1' for development, '0' for live
    DJANGO_ALLOWED_HOSTS  only used when DEBUG=0 (comma separated)
    ECDAT_ACTIVE_MODE   'demo' -> demo.sqlite3, 'actual' -> db.sqlite3
    ECDAT_DEMO_MODE     '1' enables demo datasets / seed command
ENVHELP

# ---------------------------------------------------------------------------
# 4. Install Python dependencies
# ---------------------------------------------------------------------------
step "Installing Python dependencies"
"$VENV_PY" -m pip install --upgrade pip
"$VENV_PY" -m pip install -r requirements.txt
ok "Python dependencies installed"

# ---------------------------------------------------------------------------
# 5. Migrations (both 'default' and 'demo' databases)
# ---------------------------------------------------------------------------
step "Running database migrations (actual + demo)"
"$VENV_PY" manage.py migrate
"$VENV_PY" manage.py migrate --database default || true
"$VENV_PY" manage.py migrate --database demo || true
ok "Migrations applied"

# ---------------------------------------------------------------------------
# 6. Seed demo data (optional)
# ---------------------------------------------------------------------------
if [ "$SEED_DEMO" = "1" ]; then
  step "Seeding demo data"
  if "$VENV_PY" manage.py seed_demo; then
    ok "demo data seeded"
  else
    warn "seed_demo did not run. Demo seeding requires ECDAT_ACTIVE_MODE=demo and"
    warn "ECDAT_DEMO_MODE=1 in .env. Set those and run 'manage.py seed_demo' when ready."
  fi
else
  step "Skipping demo seeding (--skip-seed)"
fi

# ---------------------------------------------------------------------------
# 7. Checks — report if everything is good
# ---------------------------------------------------------------------------
step "Running checks"
FAILURES=0

echo "${BOLD}-- Django system check --${RESET}"
if "$VENV_PY" manage.py check; then ok "manage.py check passes"; else fail "manage.py check FAILED"; FAILURES=1; fi

echo ""
echo "${BOLD}-- API smoke check (Django test client) --${RESET}"
CHECK_PY="$ROOT_DIR/.ecdat_apicheck.py"
cat > "$CHECK_PY" <<'PYEOF'
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from django.test import Client
c = Client()
c.defaults['HTTP_HOST'] = '127.0.0.1'
routes = ['/api/health/', '/api/reporting/overview/', '/api/reporting/pipeline/',
          '/api/scans/', '/api/analysis/', '/api/mitigation/', '/api/session/info/']
bads = []
for path in routes:
    code = c.get(path).status_code
    if code != 200:
        bads.append(f"{path} -> {code}")
if bads:
    print("FAIL:" + "; ".join(bads))
else:
    print("OK: all 7 core API endpoints returned 200")
PYEOF
API_CHECK="$("$VENV_PY" "$CHECK_PY" 2>/dev/null || true)"
rm -f "$CHECK_PY"
echo "$API_CHECK"
if echo "$API_CHECK" | grep -q "^OK:"; then
  ok "all core API endpoints return 200"
else
  fail "some API endpoints did not return 200"
  echo "$API_CHECK"
  FAILURES=1
fi

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
if [ "$FAILURES" = "0" ]; then
  echo "${GREEN}${BOLD}✓ Backend setup complete — everything checks out.${RESET}"
  echo "================================================================
  Run the API server:

    python manage.py runserver
    -> API base  http://127.0.0.1:8000/api/   (docs: docs/api/)

  Optional:
    python manage.py createsuperuser   # admin login at /admin"
else
  echo "${RED}${BOLD}✗ Setup finished with failures. Review the messages above.${RESET}"
  echo "================================================================
"
  exit 1
fi