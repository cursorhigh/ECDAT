# ============================================================================
# ECDAT backend - full automated setup (Windows PowerShell)
#
# - Creates a virtual environment (backend/venv)
# - Installs Python dependencies from requirements.txt
# - Sets up .env from .env.example (with a generated secret key)
# - Runs migrations on both the 'actual' (db.sqlite3) and 'demo' (demo.sqlite3) DBs
# - Seeds demo data
# - Runs checks (Django check + API smoke test) and reports whether all is good
#
# Usage:
#   .\setup.ps1                 # full default setup + demo seed + checks
#   .\setup.ps1 -SkipSeed       # skip demo-data seeding
#   .\setup.ps1 -Help
# ============================================================================
param(
    [switch]$SkipSeed,
    [switch]$Help
)

$ErrorActionPreference = 'Continue'

function Info($m)  { Write-Host "── $m" -ForegroundColor Cyan }
function Step($m)  { Write-Host ""; Write-Host "==> $m" -ForegroundColor Green }
function Warn($m)  { Write-Host "WARN: $m" -ForegroundColor Yellow }
function Ok($m)    { Write-Host "OK: $m" -ForegroundColor Green }
function Fail($m)  { Write-Host "ERROR: $m" -ForegroundColor Red }

if ($Help) {
    Write-Host "ECDAT backend setup.ps1"
    Write-Host "  .\setup.ps1                 full default setup + demo seed + checks"
    Write-Host "  .\setup.ps1 -SkipSeed       skip the demo-data seeding"
    exit 0
}

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT
Info "ECDAT backend setup running in: $ROOT"

$VENV_PY = Join-Path $ROOT 'venv\Scripts\python.exe'

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
Step "Checking prerequisites"

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue; $PYCMD = "py -3" } else { $PYCMD = "python" }
if (-not $py) { Fail "Python not found. Install Python 3.12+ and re-run."; exit 1 }
Write-Host "  $(& $PYCMD --version)"

# ---------------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------------
Step "Virtual environment"
if (Test-Path $VENV_PY) {
    Ok "virtual environment already present: $VENV_PY"
} else {
    Info "creating venv..."
    & $PYCMD -m venv venv
    if (-not (Test-Path $VENV_PY)) { Fail "Failed to create venv."; exit 1 }
    Ok "created: $VENV_PY"
}

# ---------------------------------------------------------------------------
# 3. Environment variables (.env)
# ---------------------------------------------------------------------------
Step "Environment variables"
$envPath = Join-Path $ROOT '.env'
if (Test-Path $envPath) {
    Ok ".env already exists - leaving it untouched. Review it before production:"
} else {
    Info "creating .env from .env.example with a generated secret key..."
    $bytes = New-Object byte[] 48
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = [Convert]::ToBase64String($bytes).Replace('=','').Replace('+','').Replace('/','')
    Get-Content -Raw (Join-Path $ROOT '.env.example') |
        ForEach-Object { $_.Replace('change_me_to_a_long_random_string', $secret) } |
        Set-Content -Path $envPath -Encoding utf8
    Ok "created .env with a generated DJANGO_SECRET_KEY"
}
Write-Host @'
  Key variables (edit .env when needed):
    DJANGO_SECRET_KEY   secret (a random one was generated for you)
    DJANGO_DEBUG        '1' for development, '0' for live
    DJANGO_ALLOWED_HOSTS  only used when DEBUG=0 (comma separated)
    ECDAT_ACTIVE_MODE   'demo' -> demo.sqlite3, 'actual' -> db.sqlite3
    ECDAT_DEMO_MODE     '1' enables demo datasets / seed command
'@

# ---------------------------------------------------------------------------
# 4. Python dependencies
# ---------------------------------------------------------------------------
Step "Installing Python dependencies"
& $VENV_PY -m pip install --upgrade pip
& $VENV_PY -m pip install -r requirements.txt
Ok "Python dependencies installed"

# ---------------------------------------------------------------------------
# 5. Migrations (both 'default' and 'demo' databases)
# ---------------------------------------------------------------------------
Step "Running database migrations (actual + demo)"
& $VENV_PY manage.py migrate
Ok "Migrations applied"

# ---------------------------------------------------------------------------
# 6. Seed demo data (optional)
# ---------------------------------------------------------------------------
if (-not $SkipSeed) {
    Step "Seeding demo data"
    $seedLog = Join-Path $env:TEMP "ecdat_seed.log"
    & cmd /c "$VENV_PY manage.py seed_demo >`"$seedLog`" 2>&1"
    $seedOk = ($LASTEXITCODE -eq 0)
    if ($seedOk) {
        Remove-Item $seedLog -ErrorAction SilentlyContinue
        Ok "demo data seeded"
    } else {
        Warn "seed_demo did not run. Review:"
        Get-Content $seedLog -ErrorAction SilentlyContinue | Select-Object -Last 6 | ForEach-Object { Warn "  $_" }
        Remove-Item $seedLog -ErrorAction SilentlyContinue
        Warn "Demo seeding requires ECDAT_ACTIVE_MODE=demo and ECDAT_DEMO_MODE=1 in .env."
        Warn "Set those and run 'manage.py seed_demo' when ready."
    }
} else {
    Step "Skipping demo seeding (-SkipSeed)"
}

# ---------------------------------------------------------------------------
# 7. Checks - report if everything is good
# ---------------------------------------------------------------------------
Step "Running checks"
$FAILURES = 0

Write-Host "-- Django system check --"
& $VENV_PY manage.py check
if ($LASTEXITCODE -eq 0) { Ok "manage.py check passes" } else { Fail "manage.py check FAILED"; $FAILURES = 1 }

Write-Host ""
Write-Host "-- API smoke check (Django test client) --"
$checkScript = @'
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from django.test import Client
c = Client()
c.defaults['HTTP_HOST'] = '127.0.0.1'
routes = ['/api/health/', '/api/reporting/overview/', '/api/reporting/pipeline/',
          '/api/scans/', '/api/analysis/', '/api/mitigation/', '/api/session/info/']
bads = [f"{path} -> {c.get(path).status_code}" for path in routes if c.get(path).status_code != 200]
print("FAIL: " + "; ".join(bads) if bads else "OK: all 7 core API endpoints returned 200")
'@
$checkPy = Join-Path $ROOT '.ecdat_apicheck.py'
$errLog = Join-Path $env:TEMP "ecdat_apicheck_err.log"
$checkScript | Set-Content -Path $checkPy -Encoding utf8
$oldEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$apiOut = (& $VENV_PY $checkPy 2>$errLog | Out-String)
$ErrorActionPreference = $oldEAP
Remove-Item $checkPy -ErrorAction SilentlyContinue
Remove-Item $errLog -ErrorAction SilentlyContinue
Write-Host $apiOut.Trim()
if ($apiOut -match 'OK: all 7 core API endpoints returned 200') {
    Ok "all core API endpoints return 200"
} else {
    Fail "some API endpoints did not return 200 (see output above)"
    $FAILURES = 1
}

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 64)
if ($FAILURES -eq 0) {
    Write-Host "OK: Backend setup complete - everything checks out." -ForegroundColor Green
    Write-Host ("=" * 64)
    Write-Host @"
  Run the API server:

    .\venv\Scripts\python.exe manage.py runserver
    -> API base  http://127.0.0.1:8000/api/   (docs: docs/api/)

  Optional:
    .\venv\Scripts\python.exe manage.py createsuperuser   # admin at /admin
"@
} else {
    Write-Host "ERROR: Setup finished with failures. Review the messages above." -ForegroundColor Red
    Write-Host ("=" * 64)
    exit 1
}