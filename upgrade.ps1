<#
.SYNOPSIS
    REPLATFORM safe upgrade from a portable ZIP.

.DESCRIPTION
    Verifies the SHA-256 checksum (when provided), runs a dry-run by default,
    and only then replaces installation files. User data is preserved:
    config.json, workspaces/, plugins/, license.json.

.PARAMETER Bundle
    Path to replatform-<version>-portable.zip

.PARAMETER Sha256
    Expected SHA-256 (from SHA256SUMS). Strongly recommended.

.PARAMETER Yes
    Actually apply the upgrade. Without it the script only previews.

.PARAMETER Target
    Installation directory. Defaults to the script's directory.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\upgrade.ps1 -Bundle .\replatform-1.5.0-portable.zip -Sha256 <hash>
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
    & $python (Join-Path $Target "repl.py") upgrade $Bundle --target $Target --dry-run
    if ($LASTEXITCODE -ne 0) { throw "Dry-run failed." }
    Write-Host ""
    Write-Host "Preview only. Re-run with -Yes to apply (data is preserved)." -ForegroundColor Yellow
    exit 0
}

& $python (Join-Path $Target "repl.py") upgrade $Bundle --target $Target --sha256 $actual --yes
if ($LASTEXITCODE -ne 0) { throw "Upgrade failed. The previous version was restored automatically." }

Write-Host ""
Write-Host "Upgrade complete. Verify with:" -ForegroundColor Green
Write-Host "  $python (Join-Path $Target 'repl.py') doctor"
