<#
.SYNOPSIS
    REPLATFORM safe upgrade from a portable ZIP.

.DESCRIPTION
    Verifies the SHA-256 checksum (when provided), runs a dry-run by default,
    and only then replaces installation files. User data is preserved:
    config.json, workspaces/, plugins/, license.json, audit.jsonl.

    Run this script from the extracted *new* bundle (or from outside the install
    directory) so the upgrade uses the newest logic, not the old installation's.

.PARAMETER Bundle
    Path to replatform-<version>-portable.zip

.PARAMETER Sha256
    Expected SHA-256 (from SHA256SUMS). Strongly recommended.

.PARAMETER Yes
    Actually apply the upgrade. Without it the script only previews.

.PARAMETER Target
    Installation directory. Defaults to the script's directory.

.EXAMPLE
    # From the extracted new bundle, upgrading an older install in place:
    powershell -ExecutionPolicy Bypass -File .\replatform-1.5.2\upgrade.ps1 `
      -Bundle .\replatform-1.5.2-portable.zip -Target C:\REPLATFORM -Sha256 <hash> -Yes
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Bundle,
    [string]$Sha256 = "",
    [string]$Target = $PSScriptRoot,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$python = Join-Path $Target ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }
# Run the upgrader shipped next to this script (the version being installed) so
# upgrades always use the newest logic, even when the target is an older install.
$upgrader = Join-Path $PSScriptRoot "repl.py"
if (-not (Test-Path $upgrader)) { $upgrader = Join-Path $Target "repl.py" }
$safeCwd = [IO.Path]::GetTempPath()

if (-not (Test-Path $Bundle)) { throw "Bundle not found: $Bundle" }

$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Bundle).Hash.ToLower()
Write-Host "Bundle : $Bundle"
Write-Host "SHA256 : $actual"
if ($Sha256) {
    if ($actual -ne $Sha256.ToLower()) {
        throw "Checksum mismatch. Expected $Sha256 but got $actual. Refusing to upgrade."
    }
    Write-Host "Checksum verified." -ForegroundColor Green
} else {
    Write-Warning "No -Sha256 provided. Compare the hash above with SHA256SUMS before continuing."
}

if (-not $Yes) {
    Push-Location $safeCwd
    try { & $python $upgrader upgrade $Bundle --target $Target --dry-run }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "Dry-run failed." }
    Write-Host ""
    Write-Host "Preview only. Re-run with -Yes to apply (data is preserved)." -ForegroundColor Yellow
    exit 0
}

Push-Location $safeCwd
try { & $python $upgrader upgrade $Bundle --target $Target --sha256 $actual --yes }
finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "Upgrade failed. The previous version was restored automatically." }

Write-Host ""
Write-Host "Upgrade complete. Verify with:" -ForegroundColor Green
Write-Host "  $python (Join-Path $Target 'repl.py') doctor"
