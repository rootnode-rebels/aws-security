@echo off
echo ==============================================================
echo AWSSecurity AI - Security Audit Runner
echo ==============================================================

where py >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Running tests using py launcher...
    py -m unittest discover tests > test_results.txt 2>&1
    py generate_report.py
    exit /b 0
)

where python3 >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Running tests using python3...
    python3 -m unittest discover tests > test_results.txt 2>&1
    python3 generate_report.py
    exit /b 0
)

where python >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Running tests using python...
    python -m unittest discover tests > test_results.txt 2>&1
    python generate_report.py
    exit /b 0
)

echo [ERROR] No valid Python installation found in PATH.
exit /b 1
