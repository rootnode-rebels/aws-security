<#
.SYNOPSIS
    AWSSecurity AI - One-Click PowerShell Runner for Windows
.DESCRIPTION
    Runs the complete cyber defense platform locally or via Docker.
.EXAMPLE
    .\run.ps1
    .\run.ps1 -Docker
    .\run.ps1 -Test
#>

param(
    [switch]$Docker,
    [switch]$Test
)

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  AWSSecurity AI - Automated Defense & Audit Platform" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

if ($Docker) {
    Write-Host "[INFO] Starting application via Docker Compose..." -ForegroundColor Green
    docker-compose up --build
    exit $LASTEXITCODE
}

# Find Python executable
$PythonCmd = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonCmd = "py"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
}

if (-not $PythonCmd) {
    Write-Host "[ERROR] No Python installation found in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from python.org or the Microsoft Store." -ForegroundColor Yellow
    exit 1
}

if ($Test) {
    Write-Host "[INFO] Running full test suite using $PythonCmd..." -ForegroundColor Green
    & $PythonCmd -m unittest discover tests
    exit $LASTEXITCODE
}

Write-Host "[INFO] Launching standalone platform using $PythonCmd..." -ForegroundColor Green
& $PythonCmd run_standalone.py
