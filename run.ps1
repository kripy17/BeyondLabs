param(
  [switch]$Help,
  [switch]$Install,
  [switch]$BackendOnly,
  [switch]$FrontendOnly,
  [string]$HostName = "127.0.0.1",
  [int]$BackendPort = 8000,
  [int]$FrontendPort = 5173
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# ── Visual toolkit ──────────────────────────────────────────────
# Shared with install.ps1 / doctor.ps1 / uninstall.ps1 — one palette,
# one logo, defined once in scripts/terminal-ui.ps1.
$UiHelper = Join-Path $RootDir "scripts\terminal-ui.ps1"
if (Test-Path $UiHelper) {
  . $UiHelper
} else {
  $C_Cyan = "DarkYellow"; $C_Green = "Green"; $C_Yellow = "Yellow"; $C_Red = "Red"; $C_Gray = "DarkGray"
  function Mark-Ok   { param($M) Write-Host ("  ● {0}" -f $M) -ForegroundColor $C_Green }
  function Mark-Info { param($M) Write-Host ("  ◆ {0}" -f $M) -ForegroundColor $C_Cyan }
  function Mark-Err  { param($M) Write-Host ("  ■ {0}" -f $M) -ForegroundColor $C_Red }
  function Mark-Warn { param($M) Write-Host ("  ▲ {0}" -f $M) -ForegroundColor $C_Yellow }
  function Hr        { Write-Host ("  " + ("─" * 44)) -ForegroundColor $C_Gray }
  function Show-Boot   { param([string[]]$Lines) }
  function Show-Banner { param([string]$Tagline, [string]$Version) }
}

Show-Boot @(
  "boot://env      resolving backend + frontend targets",
  "boot://launch   starting local services"
)
Show-Banner "Local SOC Investigation Workbench" "v0.1.0"

if ($Help) {
  Write-Host "  Usage: .\run.ps1 [options]" -ForegroundColor $C_Gray
  Hr
  Write-Host "  -Install         Install deps then start"
  Write-Host "  -BackendOnly     Backend only"
  Write-Host "  -FrontendOnly    Frontend only"
  Write-Host "  -HostName <ip>   Bind address (default: 127.0.0.1)"
  Write-Host "  -BackendPort <n> Port (default: 8000)"
  Write-Host "  -FrontendPort <n> Port (default: 5173)"
  exit 0
}

if ($Install) { & (Join-Path $RootDir "install.ps1") }

# ── Auto-env ────────────────────────────────────────────────────
$BackendEnv = Join-Path $BackendDir ".env"
$BackendEnvExample = Join-Path $BackendDir ".env.example"
if (-not (Test-Path $BackendEnv) -and (Test-Path $BackendEnvExample)) {
  Copy-Item $BackendEnvExample $BackendEnv
  Mark-Ok "Created backend\.env from example"
}

# Fall back to backend\.env for host/port, but never override an explicit
# -HostName / -BackendPort flag the user passed on the command line.
if (Test-Path $BackendEnv) {
  $envLines = Get-Content $BackendEnv -ErrorAction SilentlyContinue
  if (-not $PSBoundParameters.ContainsKey("HostName")) {
    $envHost = (($envLines | Where-Object { $_ -match '^BEYONDLABS_BACKEND_HOST=' } | Select-Object -Last 1) -replace '^BEYONDLABS_BACKEND_HOST=', '').Trim()
    if ($envHost) { $HostName = $envHost }
  }
  if (-not $PSBoundParameters.ContainsKey("BackendPort")) {
    $envPort = (($envLines | Where-Object { $_ -match '^BEYONDLABS_BACKEND_PORT=' } | Select-Object -Last 1) -replace '^BEYONDLABS_BACKEND_PORT=', '').Trim()
    if ($envPort) { $BackendPort = [int]$envPort }
  }
}

# ── Preflight ───────────────────────────────────────────────────
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
$ViteCmd = Join-Path $FrontendDir "node_modules\.bin\vite.cmd"

if (-not $FrontendOnly -and -not (Test-Path $VenvPython)) { Mark-Err "Backend venv missing — run .\install.ps1"; exit 1 }
if (-not $BackendOnly -and -not (Test-Path $ViteCmd))    { Mark-Err "Frontend deps missing — run .\install.ps1"; exit 1 }

# ── Launch ──────────────────────────────────────────────────────
$Pids = @{}
try {
  if (-not $FrontendOnly) {
    Mark-Info "Backend   http://${HostName}:${BackendPort}"
    $Pids.Backend = Start-Process -FilePath $VenvPython -ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", $HostName, "--port", "$BackendPort") -WorkingDirectory $BackendDir -PassThru -NoNewWindow
    Start-Sleep -Seconds 2
    if ($Pids.Backend.HasExited) { throw "Backend failed to start." }
  }

  if (-not $BackendOnly) {
    Mark-Info "Frontend  http://${HostName}:${FrontendPort}"
    $Pids.Frontend = Start-Process -FilePath "npm" -ArgumentList @("run", "dev", "--", "--host", $HostName, "--port", "$FrontendPort") -WorkingDirectory $FrontendDir -PassThru -NoNewWindow
    Start-Sleep -Seconds 2
    if ($Pids.Frontend.HasExited) { throw "Frontend failed to start." }
  }

  Write-Host ""
  Hr
  Write-Host ""
  Write-Host "  │  BeyondLabs running" -ForegroundColor $C_Cyan
  if (-not $BackendOnly)  { Write-Host "  │  Frontend  http://${HostName}:${FrontendPort}" -ForegroundColor $C_Cyan }
  if (-not $FrontendOnly) { Write-Host "  │  Backend   http://${HostName}:${BackendPort}" -ForegroundColor $C_Cyan }
  Write-Host "  │"
  Write-Host "  │  Ctrl+C to stop" -ForegroundColor $C_Gray
  Write-Host "  │"
  Write-Host ""

  do { Start-Sleep -Milliseconds 500 } while ($true)
}
finally {
  ForEach ($p in $Pids.Values) {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  }
  Write-Host ""
  Mark-Ok "Stopped cleanly"
}
