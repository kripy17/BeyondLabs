param(
  [switch]$Help,
  [switch]$DryRun,
  [switch]$Yes,
  [switch]$AppDepsOnly,
  [switch]$Purge
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateDir = Join-Path $RootDir ".beyondarch"

# ── Visual toolkit ──────────────────────────────────────────────
$C_Cyan = "Cyan"; $C_Green = "Green"; $C_Yellow = "Yellow"
$C_Red = "Red"; $C_Gray = "DarkGray"

function Mark-Ok($M)   { Write-Host ("  ● {0}" -f $M) -ForegroundColor $C_Green }
function Mark-Info($M) { Write-Host ("  ◆ {0}" -f $M) -ForegroundColor $C_Cyan }
function Mark-Warn($M) { Write-Host ("  ▲ {0}" -f $M) -ForegroundColor $C_Yellow }
function Hr()          { Write-Host ("  " + ("─" * 44)) -ForegroundColor $C_Gray }

function Write-Section($T) {
  Write-Host ""
  Write-Host ("  [{0}] {1}" -f $script:sectionNum, $T) -ForegroundColor $C_Cyan
  Hr(); $script:sectionNum = [int]$script:sectionNum + 1
  if ($script:sectionNum -lt 10) { $script:sectionNum = "0$($script:sectionNum)" }
}

function Add-Target($Targets, $Path) {
  if (Test-Path $Path) { [void]$Targets.Add($Path) }
}

if ($Help) {
  Write-Host ""
  Write-Host "  Usage: .\uninstall.ps1 [options]" -ForegroundColor $C_Gray
  Hr
  Write-Host "  -DryRun         Show what would be removed"
  Write-Host "  -Yes            Skip confirmation"
  Write-Host "  -AppDepsOnly    Remove .venv + node_modules only"
  Write-Host "  -Purge          Also remove .beyondarch/ state"
  exit 0
}

# ── Logo ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗ " -ForegroundColor $C_Cyan
Write-Host "  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗" -ForegroundColor $C_Cyan
Write-Host "  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██████╔╝" -ForegroundColor $C_Cyan
Write-Host "  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██╔══██╗" -ForegroundColor $C_Cyan
Write-Host "  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝" -ForegroundColor $C_Cyan
Write-Host "  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝" -ForegroundColor $C_Cyan
Write-Host "  Local State Cleanup — Windows" -ForegroundColor $C_Gray
Write-Host ""
Mark-Warn "Removes local dependency and cache files only."
Mark-Info "Source code and .git are never touched."

$sectionNum = "01"
$Targets = New-Object System.Collections.Generic.List[string]

Add-Target $Targets (Join-Path $RootDir "backend\.venv")
Add-Target $Targets (Join-Path $RootDir "frontend\node_modules")

if (-not $AppDepsOnly) {
  foreach ($relative in @(
    "frontend\dist", "frontend\.vite", "frontend\test-results",
    "frontend\playwright-report", "test-results", "playwright-report",
    ".pytest_cache", "backend\.pytest_cache", "backend\.ruff_cache",
    ".beyondarch\logs", ".beyondarch\runtime"
  )) { Add-Target $Targets (Join-Path $RootDir $relative) }
  Get-ChildItem -Path $RootDir -Directory -Recurse -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "*\.git\*" -and $_.FullName -notlike "*\backend\app\*" -and $_.FullName -notlike "*\frontend\src\*" } |
    ForEach-Object { [void]$Targets.Add($_.FullName) }
}
if ($Purge) { Add-Target $Targets $StateDir }

Write-Section "Cleanup plan"
if ($Targets.Count -eq 0) { Mark-Ok "No cleanup targets found"; exit 0 }
Write-Host ("  {0} target(s) found:" -f $Targets.Count) -ForegroundColor $C_Gray
foreach ($target in $Targets) { Write-Host ("    {0}" -f $target) -ForegroundColor $C_Gray }

if ($DryRun) { Write-Host ""; Mark-Info "Dry run — nothing removed"; exit 0 }
if (-not $Yes) {
  Write-Host ""
  $answer = Read-Host "  ? Remove $($Targets.Count) paths? [y/N]"
  if ($answer -notmatch "^(y|yes)$") { Mark-Info "Cleanup cancelled"; exit 0 }
}

Write-Section "Removing"
$removed = 0; $skipped = 0
$Protected = @(".git", "backend\app", "frontend\src", $RootDir)
foreach ($target in $Targets) {
  $skip = $false
  foreach ($p in $Protected) { if ($target -like "*$p*") { $skip = $true; break } }
  if ($skip) { Mark-Warn "Skipped protected: $target"; $skipped++; continue }
  Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
  Mark-Ok "Removed: $(Split-Path $target -Leaf)"
  $removed++
}

Write-Section "Complete"
Mark-Ok "$removed path(s) removed"
if ($skipped -gt 0) { Mark-Info "$skipped protected path(s) skipped" }
Write-Host ""
Hr
Write-Host "  │  Reinstall: .\install.ps1" -ForegroundColor $C_Cyan
Write-Host ""
