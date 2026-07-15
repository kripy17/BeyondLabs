# BeyondLabs terminal UI toolkit (Windows) — signature visual identity
# Dot-source with: . "$PSScriptRoot\scripts\terminal-ui.ps1"
#
# Mirrors scripts/terminal-ui.sh. One shared palette + one shared logo —
# run.ps1, install.ps1, doctor.ps1, and uninstall.ps1 all pull from here
# instead of each carrying its own copy of the banner and colors.

# Console named colors are the only reliably supported option across
# Windows PowerShell 5.1 and PowerShell 7 without relying on ANSI VT
# support being enabled. DarkYellow is the closest console analogue to
# the amber accent used in the bash scripts — it reads as warm gold/amber
# in effectively every terminal color scheme, unlike the generic Cyan
# almost every other CLI tool defaults to.
$C_Cyan   = "DarkYellow"   # signature amber accent (kept under old name)
$C_Green  = "Green"
$C_Yellow = "Yellow"
$C_Red    = "Red"
$C_Gray   = "DarkGray"

function Mark-Ok   { param($M) Write-Host ("  ● {0}" -f $M) -ForegroundColor $C_Green }
function Mark-Info { param($M) Write-Host ("  ◆ {0}" -f $M) -ForegroundColor $C_Cyan }
function Mark-Warn { param($M) Write-Host ("  ▲ {0}" -f $M) -ForegroundColor $C_Yellow }
function Mark-Err  { param($M) Write-Host ("  ■ {0}" -f $M) -ForegroundColor $C_Red }
function Hr        { Write-Host ("  " + ("─" * 44)) -ForegroundColor $C_Gray }

$script:sectionNum = "01"
function Write-Section {
  param($T)
  Write-Host ""
  Write-Host ("  [{0}] {1}" -f $script:sectionNum, $T) -ForegroundColor $C_Cyan
  Hr
  $script:sectionNum = [int]$script:sectionNum + 1
  if ($script:sectionNum -lt 10) { $script:sectionNum = "0$($script:sectionNum)" }
}

# ── Boot sequence ─────────────────────────────────────────────
# Faux system lines with timestamps before the logo, matching the
# boot-sequence intro on the BeyondLabs web frontend.
function Show-Boot {
  param([string[]]$Lines)
  foreach ($line in $Lines) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host ("  {0}  {1}" -f $ts, $line) -ForegroundColor $C_Gray
    Start-Sleep -Milliseconds 50
  }
}

# ── Logo ────────────────────────────────────────────────────────
# Single canonical logo — do not redefine this per-script.
function Show-Logo {
  Write-Host ""
  Write-Host "  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗ ██╗      █████╗ ██████╗ ███████╗" -ForegroundColor $C_Cyan
  Write-Host "  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝" -ForegroundColor $C_Cyan
  Write-Host "  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ██║██║     ███████║██████╔╝███████╗" -ForegroundColor $C_Cyan
  Write-Host "  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██║  ██║██║     ██╔══██║██╔══██╗╚════██║" -ForegroundColor $C_Cyan
  Write-Host "  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║██████╔╝███████║" -ForegroundColor $C_Cyan
  Write-Host "  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝" -ForegroundColor $C_Cyan
  Write-Host ""
}

# Logo + tagline strip framed with dotted scan marks, mirroring ba_banner
# on the bash side.
function Show-Banner {
  param([string]$Tagline = "Local SOC Investigation Workbench", [string]$Version = "v0.1.0")
  Show-Logo
  Write-Host "  ┈┈┈ " -ForegroundColor $C_Gray -NoNewline
  Write-Host $Tagline -ForegroundColor White -NoNewline
  Write-Host " ┈┈┈ " -ForegroundColor $C_Gray -NoNewline
  Write-Host $Version -ForegroundColor $C_Gray
}
