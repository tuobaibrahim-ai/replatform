<#
.SYNOPSIS
    REPLATFORM bootstrap installer (portable / source checkout).

.DESCRIPTION
    Creates a local virtual environment, installs runtime dependencies, and
    verifies the CLI. It never downloads malware, never installs external
    reverse-engineering tools, and never writes secrets.

.PARAMETER Dev
    Also install development tools (ruff, coverage, build) and try an editable
    install of the package.

.PARAMETER NoVenv
    Use the current Python interpreter instead of creating .venv.

.PARAMETER SkipDeps
    Do not run pip (useful for fully offline machines with deps preinstalled).

.PARAMETER WheelDir
    Install dependencies from local wheels only (offline / air-gapped).

.PARAMETER Python
    Path to a Python 3.11+ interpreter. Defaults to py -3, then python.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Dev
#>
[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$NoVenv,
    [switch]$SkipDeps,
    [string]$WheelDir = "",
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Write-Step([string]$Text) {
    Write-Host ""
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Fail([string]$Text) {
    Write-Host "ERROR: $Text" -ForegroundColor Red
    exit 1
}

# --- 1. Locate a suitable Python -------------------------------------------
Write-Step "Locating Python 3.11+"
$candidates = @()
if ($Python) { $candidates += $Python }
$candidates += @("py", "python", "python3")

$BasePython = $null
$BaseArgs = @()
foreach ($candidate in $candidates) {
    if (-not $candidate) { continue }
    try {
        if ($candidate -eq "py") {
            $probeArgs = @("-3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])")
            $venvArgs = @("-3")
        } else {
            $probeArgs = @("-c", "import sys; print('%d.%d' % sys.version_info[:2])")
            $venvArgs = @()
        }
        $version = & $candidate @probeArgs 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $version) { continue }
        $parts = "$version".Trim().Split(".")
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11) {
            $BasePython = $candidate
            $BaseArgs = $venvArgs
            break
        }
    } catch {
        continue
    }
}
if (-not $BasePython) {
    Fail "Python 3.11+ not found. Install it from https://www.python.org/downloads/windows/ and re-run."
}
Write-Host "Using: $BasePython ($version)"

# --- 2. Create the virtual environment -------------------------------------
if ($NoVenv) {
    $Py = $BasePython
    $PyPrefix = @()
    if ($BasePython -eq "py") { $PyPrefix = @("-3") }
} else {
    Write-Step "Creating .venv (if missing)"
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        & $BasePython @BaseArgs -m venv .venv
        if ($LASTEXITCODE -ne 0) { Fail "Could not create .venv" }
    }
    $Py = Join-Path $Root ".venv\Scripts\python.exe"
    $PyPrefix = @()
}
if (-not (Test-Path $Py) -and $Py -ne "python" -and $Py -ne "py") {
    Fail "Interpreter not found: $Py"
}

# --- 3. Dependencies --------------------------------------------------------
if (-not $SkipDeps) {
    Write-Step "Installing runtime dependencies"
    if ($WheelDir) {
        if (-not (Test-Path $WheelDir)) { Fail "Wheel directory not found: $WheelDir" }
        & $Py @PyPrefix -m pip install --no-index --find-links $WheelDir -r requirements.txt
    } else {
        & $Py @PyPrefix -m pip install --upgrade pip
        & $Py @PyPrefix -m pip install -r requirements.txt
    }
    if ($LASTEXITCODE -ne 0) { Fail "Dependency installation failed" }

    if ($Dev) {
        Write-Step "Installing development tools"
        & $Py @PyPrefix -m pip install "ruff>=0.6" "coverage>=7.4" "build>=1.2"
        if ($LASTEXITCODE -ne 0) { Fail "Dev dependency installation failed" }
        # Editable install is optional: the launcher works from source anyway.
        & $Py @PyPrefix -m pip install -e . --no-build-isolation
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARN: editable install skipped (setuptools missing?). Source launcher still works." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "Skipping pip (SkipDeps)." -ForegroundColor Yellow
}

# --- 4. Local config (no secrets) ------------------------------------------
if (-not (Test-Path "config.json") -and (Test-Path "config.example.json")) {
    Copy-Item "config.example.json" "config.json"
    Write-Host "Created config.json from config.example.json (no API keys written)."
}

# --- 5. Verify --------------------------------------------------------------
Write-Step "Verifying installation"
& $Py @PyPrefix -m replatform version
if ($LASTEXITCODE -ne 0) { Fail "CLI verification failed" }

& $Py @PyPrefix -m replatform selftest
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARN: selftest reported an issue. Review the output above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "REPLATFORM is ready." -ForegroundColor Green
Write-Host "  .\replatform.cmd version"
Write-Host "  .\replatform.cmd tools"
Write-Host "  .\replatform.cmd analyze <file>"
Write-Host ""
Write-Host "External tools (apktool, jadx, Ghidra, YARA, Rizin) are NOT installed."
Write-Host "See docs/DEPLOYMENT.md and PLATFORM.md for optional setup."
exit 0
