<#
.SYNOPSIS
    REPLATFORM uninstaller (portable installation).

.DESCRIPTION
    Removes generated environments and caches. By default it KEEPS user data
    (config.json, workspaces/, plugins/, license.json, audit.jsonl). Use
    -PurgeData to delete those too. Nothing outside the installation folder
    is touched.

.PARAMETER Target
    Installation directory. Defaults to the script's directory.

.PARAMETER PurgeData
    Also delete config, workspaces, plugins, license and audit log.

.PARAMETER Yes
    Required to actually delete anything.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Yes
#>
[CmdletBinding()]
param(
    [string]$Target = $PSScriptRoot,
    [switch]$PurgeData,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $Target).Path

$targets = @(
    (Join-Path $root ".venv"),
    (Join-Path $root "build"),
    (Join-Path $root "dist"),
    (Join-Path $root ".ruff_cache"),
    (Join-Path $root ".pytest_cache"),
    (Join-Path $root ".coverage")
)
$targets += Get-ChildItem -Path $root -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName

if ($PurgeData) {
    $targets += @(
        (Join-Path $root "config.json"),
        (Join-Path $root "workspaces"),
        (Join-Path $root "plugins"),
        (Join-Path $root "license.json"),
        (Join-Path $root "audit.jsonl")
    )
}

Write-Host "Installation: $root"
Write-Host "Will remove:"
foreach ($item in $targets) { if (Test-Path $item) { Write-Host "  - $item" } }
if (-not $PurgeData) {
    Write-Host "User data is kept (use -PurgeData to delete it)." -ForegroundColor Yellow
}

if (-not $Yes) {
    Write-Host ""
    Write-Host "Preview only. Re-run with -Yes to delete the items above." -ForegroundColor Yellow
    exit 0
}

$removed = 0
foreach ($item in $targets) {
    if (-not (Test-Path $item)) { continue }
    $resolved = (Resolve-Path -LiteralPath $item).Path
    if (-not $resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Skipping path outside installation: $resolved"
        continue
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $removed++
}
Write-Host "Removed $removed item(s). The source folder itself is kept." -ForegroundColor Green
