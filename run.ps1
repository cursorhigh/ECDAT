<#
.SYNOPSIS
    ECDAT full-stack launcher (backend API + worker + UI) for native PowerShell on Windows.
    Twin of run.sh - asks which UI / frontend mode to use, then boots everything.

.DESCRIPTION
    Modes:
1) browser-dev      Browser UI + live Next.js dev server (HMR) + local backend
      2) browser-preview  Browser UI, production build served locally + backend
      3) desktop          Offline desktop shell (Tauri) + bundled backend
      4) backend-only     Backend API + worker, no UI

    Behaviour:
      * migrates the database unless -SkipMigrate
      * starts the huey worker and re-queues pending work left by a previous run
      * waits for a healthy backend before opening the UI
      * reuses an already-running backend instead of starting a duplicate
      * Ctrl+C shuts down the backend, worker, and UI cleanly

.PARAMETER Mode
    browser-dev | browser-preview | desktop | backend-only.
    Defaults to an interactive menu when running in a terminal.

.PARAMETER BindHost
    Backend bind host (alias -Host; default from $env:ECDAT_HOST, else 127.0.0.1).

.PARAMETER Port
    Backend bind port (default from $env:ECDAT_PORT, else 8000).

.PARAMETER FrontendPort
    UI dev/preview port (default from $env:ECDAT_FRONTEND_PORT, else 3000).

.PARAMETER ApiTarget
    Public Django URL used by the UI (default from $env:NEXT_PUBLIC_API_BASE_URL, else http://127.0.0.1:<Port>).

.PARAMETER Rebuild
    Force `npm run build` before preview even when .next\BUILD_ID exists.

.PARAMETER SkipMigrate
    Don't run database migrations.

.PARAMETER NoWorker
    Don't start the huey worker (jobs will stay queued).

.PARAMETER NoSweep
    Don't re-queue pending work at boot.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Mode browser-dev
    .\run.ps1 -Mode browser-preview -Rebuild
    .\run.ps1 -Mode backend-only -SkipMigrate
#>
[CmdletBinding()]
param(
    [ValidateSet('browser-dev', 'browser-preview', 'desktop', 'backend-only')]
    [string]$Mode,
    [Alias('Host')]
    [string]$BindHost = $env:ECDAT_HOST,
    [string]$Port = $env:ECDAT_PORT,
    [string]$FrontendPort = $env:ECDAT_FRONTEND_PORT,
    [string]$ApiTarget = $env:NEXT_PUBLIC_API_BASE_URL,
    [switch]$Rebuild,
    [switch]$SkipMigrate,
    [switch]$NoWorker,
    [switch]$NoSweep
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step { Write-Host ''; Write-Host "==> $args" -ForegroundColor Green }
function Write-Info { Write-Host "--- $args" -ForegroundColor Cyan }
function Write-Ok   { Write-Host "OK: $args" -ForegroundColor Green }
function Write-Warn { Write-Host "WARN: $args" -ForegroundColor Yellow }
function Write-Fail { Write-Host "ERROR: $args" -ForegroundColor Red }

$RepoRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Backend  = Join-Path $RepoRoot 'backend'
$Frontend = Join-Path $RepoRoot 'frontend'

if (-not $BindHost) { $BindHost = '127.0.0.1' }
if (-not $Port)     { $Port = '8000' }
if (-not $ApiTarget) { $ApiTarget = "http://127.0.0.1:$Port" }

# ---------------------------------------------------------------------------
# Interpreters / toolchain detection
# ---------------------------------------------------------------------------
function Find-Python {
    $candidates = @(
        (Join-Path $Backend 'venv\Scripts\python.exe'),
        (Join-Path $Backend 'venv\bin\python'),
        (Join-Path $Backend '.venv\Scripts\python.exe'),
        (Join-Path $Backend '.venv\bin\python')
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$Python = Find-Python
if (-not $Python) {
    Write-Fail 'could not locate a python interpreter. Run backend\setup.ps1 first.'
    exit 1
}
Write-Info "python        : $Python"

# Desktop capability check (Tauri shell is an optional, independently built piece)
$DesktopAvailable = $false
$DesktopNote = $null
$TauriConf = Join-Path $RepoRoot 'desktop\tauri.conf.json'
if (Test-Path -LiteralPath $TauriConf) {
    if ((Get-Command cargo -ErrorAction SilentlyContinue) -and (Get-Command rustc -ErrorAction SilentlyContinue)) {
        $DesktopAvailable = $true
    } else {
        $DesktopNote = 'desktop/ exists but no Rust toolchain was found'
    }
} else {
    $DesktopNote = 'no desktop/ Tauri shell has been built yet'
}

# ---------------------------------------------------------------------------
# Mode selection (interactive unless -Mode given)
# ---------------------------------------------------------------------------
$Modes = @('browser-dev', 'browser-preview', 'desktop', 'backend-only')

if (-not $Mode) {
    if (-not ([Environment]::UserInteractive -and $Host.UI.RawUI)) {
        Write-Fail 'no terminal available. Pass -Mode (browser-dev | browser-preview | desktop | backend-only).'
        exit 1
    }
    Write-Host ''
    Write-Host 'Which UI / frontend mode should ECDAT run in?' -ForegroundColor White
    Write-Host '  1) browser-dev      Browser UI + live Next.js dev server (HMR) + local backend'
    Write-Host '  2) browser-preview  Browser UI, production build served locally + backend'
    Write-Host '  3) desktop          Offline desktop shell (Tauri) + bundled backend'
    Write-Host '  4) backend-only     Backend API + worker, no UI'
    if ($DesktopNote) { Write-Warn "desktop not available: $DesktopNote" }
    while ($true) {
        $Choice = Read-Host 'Enter choice [1-4] (default 1)'
        if (-not $Choice) { $Choice = '1' }
        if ($Choice -match '^[1-4]$') {
            $Mode = $Modes[[int]$Choice - 1]
            break
        }
        Write-Warn "invalid choice '$Choice' (1-4)"
    }
}

Write-Step "Selected mode: $Mode"

if ($Mode -eq 'desktop') {
    if (-not $DesktopAvailable) {
        Write-Fail "desktop mode is not available on this machine$(if ($DesktopNote) { ": $DesktopNote" })."
        Write-Fail "Use 'browser-dev' or 'browser-preview' instead - the same frontend build runs in a browser."
        exit 1
    }
}

if ($Mode -ne 'backend-only') {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Fail 'node not found - required for the UI.'; exit 1 }
    if (-not (Get-Command npm -ErrorAction SilentlyContinue))  { Write-Fail 'npm not found - required for the UI.';  exit 1 }
    if (-not (Test-Path -LiteralPath (Join-Path $Frontend 'package.json'))) {
        Write-Fail "frontend/ not found at $Frontend - browser UI cannot start."
        exit 1
    }
}

if ($Mode -eq 'browser-dev')     { if (-not $FrontendPort) { $FrontendPort = '3000' } }
if ($Mode -eq 'browser-preview') { if (-not $FrontendPort) { $FrontendPort = '3000' } }

# ---------------------------------------------------------------------------
# Backend pre-flight
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath (Join-Path $Backend 'manage.py'))) {
    Write-Fail "manage.py not found in $Backend"
    exit 1
}

$script:ServerProcess = $null
$script:WorkerProcess = $null

function Stop-EcdatChildren {
    foreach ($proc in @($script:ServerProcess, $script:WorkerProcess)) {
        if ($null -ne $proc -and -not $proc.HasExited) {
            try { & taskkill /PID $proc.Id /T /F 2>&1 | Out-Null } catch { }
        }
    }
}

# Ctrl+C: intercept, kill everything we started, then stop the script.
$Script:CancelHandler = [System.ConsoleCancelEventHandler]{
    param($sender, $e)
    $e.Cancel = $true
    Stop-EcdatChildren
    Write-Ok 'all ECDAT processes stopped.'
    exit 2
}
try {
    [System.Console]::add_CancelKeyPress($Script:CancelHandler)
} catch {
    Write-Warn 'could not install Ctrl+C handler - backend processes will rely on finally-cleanup.'
}

Push-Location $Backend
try {

    # Detect an already-running backend on this port.
    $HealthUrl = "http://127.0.0.1:$Port/api/health/"
    $Existing = $false
    try {
        $null = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2
        $Existing = $true
    } catch {
        $Existing = $false
    }

    if ($Existing) {
        $KillIt = $false
        if ([Environment]::UserInteractive) {
            Write-Warn "A backend is already running at http://127.0.0.1:$Port/ "
            $Answer = Read-Host 'Kill it and restart fresh (incl. huey worker)? [y/N]'
            if ($Answer -match '^(y|yes)$') { $KillIt = $true }
        }
        if ($KillIt) {
            Write-Info 'Stopping the existing backend + worker...'
            $listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique
            foreach ($procId in $listeners) {
                try { & taskkill /PID $procId /T /F 2>&1 | Out-Null } catch { }
                Write-Ok "killed backend pid $procId"
            }
            $hueyProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*run_huey*' } |
                Select-Object -ExpandProperty ProcessId
            foreach ($procId in $hueyProcs) {
                try { & taskkill /PID $procId /T /F 2>&1 | Out-Null } catch { }
                Write-Ok "killed worker pid $procId"
            }
            Start-Sleep -Seconds 1
            $Existing = $false
        } else {
            Write-Info "a backend already answers at http://127.0.0.1:$Port/ - reusing it (no duplicate started)."
        }
    }

    function Invoke-CheckedPython {
        param([string[]]$ArgsList)
        & $Python @ArgsList
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "python command failed with exit code $LASTEXITCODE : $ArgsList"
            exit $LASTEXITCODE
        }
    }

    try {
        # 1. Migrations
        if ($Existing) {
            Write-Info 'skipping migrations/worker - external backend is already serving this port.'
        } elseif (-not $SkipMigrate) {
            Write-Step 'Applying migrations'
            Invoke-CheckedPython @('manage.py', 'migrate', '--noinput')
            Write-Ok 'migrations applied'
        } else {
            Write-Warn 'migrations skipped (-SkipMigrate)'
        }

        # 2. Worker (huey) + pending-work sweep
        if (-not $Existing -and -not $NoWorker) {
            Write-Step 'Starting huey worker (scans / analysis / mitigation jobs)'
            New-Item -ItemType Directory -Force -Path (Join-Path $Backend 'logs') | Out-Null
            $workerArgs = @('manage.py', 'run_huey', '--loglevel', 'INFO')
            if ($env:ECDAT_HUEY_WORKERS) { $workerArgs += @('--workers', $env:ECDAT_HUEY_WORKERS) }
            $script:WorkerProcess = Start-Process -FilePath $Python -ArgumentList $workerArgs `
                -WorkingDirectory $Backend -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $Backend 'logs\huey.ps.out.log') `
                -RedirectStandardError  (Join-Path $Backend 'logs\huey.ps.err.log')
            Write-Ok "worker pid $($script:WorkerProcess.Id) - logs -> backend\logs\huey.ps.out.log"

            if (-not $NoSweep) {
                Write-Info 're-queuing pending work left by a previous run...'
                & $Python manage.py sweep_pending 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Warn 'sweep_pending did not run cleanly (ignored).' }
            }
        } else {
            Write-Info 'skipping worker (-NoWorker or external backend in use)'
        }

        # 3. API server (background; kept alive while the UI runs)
        New-Item -ItemType Directory -Force -Path (Join-Path $Backend 'logs') | Out-Null
        if (-not $Existing) {
            Write-Step "Starting Django API server on http://${BindHost}:${Port}/ (logs -> backend\logs\server.ps.out.log)"
            $script:ServerProcess = Start-Process -FilePath $Python `
                -ArgumentList @('manage.py', 'runserver', "$BindHost`:$Port", '--noreload') `
                -WorkingDirectory $Backend -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $Backend 'logs\server.ps.out.log') `
                -RedirectStandardError  (Join-Path $Backend 'logs\server.ps.err.log')
        }

        # 4. Health readiness gate
        if (-not $Existing) {
            Write-Step "Waiting for backend health at $HealthUrl"
            $Healthy = $false
            for ($i = 0; $i -lt 40; $i++) {
                if ($null -ne $script:ServerProcess -and $script:ServerProcess.HasExited) { break }
                try {
                    $null = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2
                    $Healthy = $true
                    break
                } catch {
                    Start-Sleep -Seconds 1
                }
            }
            if (-not $Healthy) {
                Write-Fail 'backend did not become healthy after ~40s. Check backend\logs\server.ps.out.log'
                Write-Fail 'and, if the port was occupied, re-run with -Port <free port>.'
                exit 1
            }
            Write-Ok 'backend is healthy'
        }

        # 5. UI
        switch ($Mode) {
            'backend-only' {
                Write-Ok "backend running. API: http://${BindHost}:${Port}/api/  (health: $HealthUrl)"
                Write-Info 'Press Ctrl+C to stop.'
                while ($true) { Start-Sleep -Seconds 1 }
            }
            'browser-dev' {
                Write-Step "Starting Next.js dev server on port $FrontendPort (Django API: $ApiTarget)"
                $envFile = Join-Path $Frontend '.env'
                if (-not (Test-Path -LiteralPath $envFile)) { Copy-Item (Join-Path $Frontend '.env.example') $envFile }
                $env:NEXT_PUBLIC_API_BASE_URL = $ApiTarget
                $ui = Start-Process -FilePath 'npm.cmd' -ArgumentList @('run', 'dev', '--', '-p', $FrontendPort) `
                    -WorkingDirectory $Frontend -PassThru -NoNewWindow
                $ui.WaitForExit()
                Remove-Item Env:NEXT_PUBLIC_API_BASE_URL -ErrorAction SilentlyContinue
            }
            'browser-preview' {
                $envFile = Join-Path $Frontend '.env'
                if (-not (Test-Path -LiteralPath $envFile)) { Copy-Item (Join-Path $Frontend '.env.example') $envFile }
                $env:NEXT_PUBLIC_API_BASE_URL = $ApiTarget
                $buildMarker = Join-Path $Frontend '.next\BUILD_ID'
                if ($Rebuild -or -not (Test-Path -LiteralPath $buildMarker)) {
                    Write-Step 'Building production frontend...'
                    $build = Start-Process -FilePath 'npm.cmd' -ArgumentList @('run', 'build') `
                        -WorkingDirectory $Frontend -PassThru -NoNewWindow
                    $build.WaitForExit()
                } else {
                    Write-Info 'using existing frontend\.next - pass -Rebuild to rebuild.'
                }
                Write-Step "Serving built frontend on port $FrontendPort (Django API: $ApiTarget)"
                $ui = Start-Process -FilePath 'npm.cmd' -ArgumentList @('run', 'start', '--', '-p', $FrontendPort) `
                    -WorkingDirectory $Frontend -PassThru -NoNewWindow
                $ui.WaitForExit()
                Remove-Item Env:NEXT_PUBLIC_API_BASE_URL -ErrorAction SilentlyContinue
            }
            'desktop' {
                Write-Info 'launching Tauri desktop shell...'
                Push-Location (Join-Path $RepoRoot 'desktop')
                try {
                    & npm install 2>$null | Out-Null
                    $tauri = Start-Process -FilePath 'npm.cmd' -ArgumentList @('run', 'tauri', '--', 'dev') -PassThru -NoNewWindow
                    $tauri.WaitForExit()
                } finally {
                    Pop-Location
                }
            }
        }

        Write-Ok 'UI exited. Stopping the ECDAT backend.'
    } finally {
        Stop-EcdatChildren
    }

} finally {
    Pop-Location
}