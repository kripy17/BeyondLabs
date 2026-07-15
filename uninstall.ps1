param(
  [switch]$Help,
  [switch]$DryRun,
  [switch]$Yes,
  [switch]$AppDepsOnly,
  [switch]$Purge
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateDir = Join-Path $RootDir ".beyondlabs"

# ── Visual toolkit ──────────────────────────────────────────────
# Shared with run.ps1 / install.ps1 / doctor.ps1 — defined once in
# scripts/terminal-ui.ps1.
$UiHelper = Join-Path $RootDir "scripts\terminal-ui.ps1"
if (-not (Test-Path $UiHelper)) {
  Write-Host "  ■  Missing scripts\terminal-ui.ps1" -ForegroundColor Red
  exit 1
}
. $UiHelper

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
  Write-Host "  -Purge          Also remove .beyondlabs/ state"
  exit 0
}

# ── Logo ────────────────────────────────────────────────────────
Show-Boot @(
  "boot://scan     enumerating local dependency and cache paths"
)
Show-Banner "Local State Cleanup — Windows" "v0.1.0"
Mark-Warn "Removes local dependency and cache files only."
Mark-Info "Source code and .git are never touched."
$Targets = New-Object System.Collections.Generic.List[string]

Add-Target $Targets (Join-Path $RootDir "backend\.venv")
Add-Target $Targets (Join-Path $RootDir "frontend\node_modules")

if (-not $AppDepsOnly) {
  foreach ($relative in @(
    "frontend\dist", "frontend\.vite", "frontend\test-results",
    "frontend\playwright-report", "test-results", "playwright-report",
    ".pytest_cache", "backend\.pytest_cache", "backend\.ruff_cache",
    ".beyondlabs\logs", ".beyondlabs\runtime"
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
