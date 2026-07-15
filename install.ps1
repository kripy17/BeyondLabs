param(
  [switch]$Yes,
  [switch]$Help
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"

# ── Visual toolkit ──────────────────────────────────────────────
# Shared with run.ps1 / doctor.ps1 / uninstall.ps1 — one palette, one
# logo, defined once in scripts/terminal-ui.ps1.
$UiHelper = Join-Path $RootDir "scripts\terminal-ui.ps1"
if (-not (Test-Path $UiHelper)) {
  Write-Host "  ■  Missing scripts\terminal-ui.ps1" -ForegroundColor Red
  Write-Host "     Run this script from the BeyondLabs project root." -ForegroundColor DarkGray
  exit 1
}
. $UiHelper

function Write-Step($Label, $File, $Arguments, $WorkingDirectory = $RootDir) {
  Write-Host ("  ⡿ {0}" -f $Label) -ForegroundColor $C_Cyan
  $process = Start-Process -FilePath $File -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -NoNewWindow -PassThru -Wait
  if ($process.ExitCode -ne 0) { throw "$Label failed ($($process.ExitCode))" }
  Mark-Ok $Label
}

function Find-Python {
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) { return @("py", "-3") }
  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) { return @("python") }
  return $null
}

if ($Help) { Write-Host "Usage: .\install.ps1 [-Yes]"; exit 0 }

# ── Logo ────────────────────────────────────────────────────────
Show-Boot @(
  "boot://env      resolving project root and dependencies",
  "boot://net      local-only — no external calls made",
  "boot://wizard   preparing Windows setup wizard"
)
Show-Banner "Windows Setup Wizard" "v0.1.0"

# ── Preflight ───────────────────────────────────────────────────
Write-Section "Preflight"
if (-not (Test-Path $BackendDir)) { throw "backend\ is missing" }
if (-not (Test-Path $FrontendDir)) { throw "frontend\ is missing" }
Mark-Ok "Project layout detected"

$PythonCmd = Find-Python
if (-not $PythonCmd) { throw "Python not found — install Python 3" }
$Node = Get-Command node -ErrorAction SilentlyContinue
if (-not $Node) { throw "Node.js not found" }
$Npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $Npm) { throw "npm not found" }

Mark-Ok "Python $($PythonCmd -join ' ')"
Mark-Ok "Node.js $(node --version)"
Mark-Ok "npm $(npm --version)"

if (-not $Yes) {
  Write-Host ""
  $answer = Read-Host "  ? Start BeyondLabs Windows setup? [y/N]"
  if ($answer -notmatch "^(y|yes)$") { Mark-Info "Setup cancelled"; exit 0 }
}

# ── Dependencies ────────────────────────────────────────────────
Write-Section "Application dependencies"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
  $args = @()
  if ($PythonCmd.Count -gt 1) { $args += $PythonCmd[1..($PythonCmd.Count - 1)] }
  $args += @("-m", "venv", (Join-Path $BackendDir ".venv"))
  Write-Step "Creating backend virtual environment" $PythonCmd[0] $args
} else { Mark-Ok "backend\.venv already exists" }

Write-Step "Upgrading pip" $VenvPython @("-m", "pip", "install", "--upgrade", "pip")
Write-Step "Installing backend requirements" $VenvPython @("-m", "pip", "install", "-r", (Join-Path $BackendDir "requirements.txt"))

if (Test-Path (Join-Path $FrontendDir "package-lock.json")) {
  Write-Step "Installing frontend npm deps" "npm" @("ci", "--include=dev") $FrontendDir
} else {
  Write-Step "Installing frontend npm deps" "npm" @("install", "--include=dev") $FrontendDir
}

# ── Optional helpers ────────────────────────────────────────────
Write-Section "Optional helpers"
Write-Host "  The following are optional/manual on Windows:" -ForegroundColor $C_Gray
Write-Host "  Core helpers:              curl, openssl, jq" -ForegroundColor $C_Gray
Write-Host "  DNS/domain metadata:       dig/nslookup, whois, traceroute" -ForegroundColor $C_Gray
Write-Host "  Recommended SOC/recon:     nmap, whatweb" -ForegroundColor $C_Gray

# ── Done ────────────────────────────────────────────────────────
Write-Section "Setup complete"
Write-Host ""
Mark-Ok "backend\.venv + requirements"
Mark-Ok "frontend\node_modules"
Write-Host ""
Hr
Write-Host "  │  Launch   .\run.ps1" -ForegroundColor $C_Cyan
Write-Host "  │  Doctor   .\doctor.ps1" -ForegroundColor $C_Cyan
Write-Host "  │"
Write-Host "  │  Frontend http://127.0.0.1:5173" -ForegroundColor $C_Cyan
Write-Host "  │  Backend  http://127.0.0.1:8000" -ForegroundColor $C_Cyan
Write-Host ""
