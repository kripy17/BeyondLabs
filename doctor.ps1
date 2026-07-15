param([switch]$Help)

$ErrorActionPreference = "Continue"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# ── Visual toolkit ──────────────────────────────────────────────
# Shared with run.ps1 / install.ps1 / uninstall.ps1 — defined once in
# scripts/terminal-ui.ps1.
$UiHelper = Join-Path $RootDir "scripts\terminal-ui.ps1"
if (-not (Test-Path $UiHelper)) {
  Write-Host "  ■  Missing scripts\terminal-ui.ps1" -ForegroundColor Red
  exit 1
}
. $UiHelper

$Pass = 0; $Warn = 0; $Fail = 0
function OK($M)   { $script:Pass++; Mark-Ok $M }
function WARN($M) { $script:Warn++; Mark-Warn $M }
function ERR($M)  { $script:Fail++; Mark-Err $M }
function INFO($M) { Mark-Info $M }
function HR()     { Hr }
function Section($T) { Write-Section $T }

function Test-Python {
  $candidates = @("py -3", "python", "python3")
  foreach ($c in $candidates) {
    $parts = $c -split " "
    try { $ver = & $parts[0] @($parts[1..$parts.Count] | Where-Object { $_ }) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null; if ($ver) { return $parts } } catch {}
  }
  return $null
}

if ($Help) { Write-Host "Usage: .\doctor.ps1"; exit 0 }

# ── Logo ────────────────────────────────────────────────────────
Show-Boot @(
  "boot://scan     enumerating project layout and runtimes",
  "boot://probe    checking live services on :8000 / :5173"
)
Show-Banner "System Health Dashboard — Windows" (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Section "Project layout"
if (Test-Path $BackendDir) { OK "backend\" } else { ERR "backend\ missing" }
if (Test-Path $FrontendDir) { OK "frontend\" } else { ERR "frontend\ missing" }
if (Test-Path (Join-Path $BackendDir "requirements.txt")) { OK "backend\requirements.txt" } else { ERR "backend\requirements.txt missing" }
if (Test-Path (Join-Path $FrontendDir "package.json")) { OK "frontend\package.json" } else { ERR "frontend\package.json missing" }

Section "Required runtimes"
$py = Test-Python
if ($py) { OK "Python $($py -join ' ')" } else { ERR "Python 3 missing" }
$nodeVer = & node --version 2>$null
if ($LASTEXITCODE -eq 0) { OK "Node.js $nodeVer" } else { ERR "Node.js missing" }
$npmVer = & npm --version 2>$null
if ($LASTEXITCODE -eq 0) { OK "npm $npmVer" } else { ERR "npm missing" }

Section "Backend environment"
$Venv = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (Test-Path $Venv) {
  OK "backend\.venv"
  & $Venv -m compileall -q (Join-Path $BackendDir "app") 2>$null
  if ($LASTEXITCODE -eq 0) { OK "Backend compiles" } else { ERR "Backend compile failed" }
} else { WARN "backend\.venv missing — run .\install.ps1" }

Section "Frontend readiness"
$Vite = Join-Path $FrontendDir "node_modules\.bin\vite.cmd"
if (Test-Path $Vite) {
  OK "node_modules"
  & npm --prefix $FrontendDir run lint > $null 2>&1
  if ($LASTEXITCODE -eq 0) { OK "Lint passed" } else { WARN "Lint fails" }
  & npm --prefix $FrontendDir run build > $null 2>&1
  if ($LASTEXITCODE -eq 0) { OK "Build passed" } else { WARN "Build fails" }
} else { WARN "node_modules missing — run .\install.ps1" }

Section "Live services"
try {
  $req = [System.Net.WebRequest]::Create("http://127.0.0.1:8000/health"); $req.Timeout = 3000
  if ($req.GetResponse().StatusCode -eq 200) { OK "Backend responds at :8000" } else { INFO "Backend not running" }
} catch { INFO "Backend not running" }
try {
  $req = [System.Net.WebRequest]::Create("http://127.0.0.1:5173"); $req.Timeout = 3000
  if ($req.GetResponse().StatusCode -eq 200) { OK "Frontend responds at :5173" } else { INFO "Frontend not running" }
} catch { INFO "Frontend not running" }

Section "Summary"
HR
$summary = "  ● $Pass passed  ▲ $Warn warnings  ■ $Fail errors"
Write-Host $summary -ForegroundColor $C_Cyan
Write-Host ""
if ($Fail -gt 0) { Write-Host "  │  Recommended: .\install.ps1" -ForegroundColor $C_Cyan; exit 1 }
Write-Host "  ● BeyondLabs health check passed" -ForegroundColor $C_Green
Write-Host ""
