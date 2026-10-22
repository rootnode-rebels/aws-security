@echo off
echo ==============================================================
echo AWSSecurity AI - Security Audit Runner
echo ==============================================================

if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
    echo [INFO] Running tests using %LOCALAPPDATA%\Python\bin\python.exe...
    "%LOCALAPPDATA%\Python\bin\python.exe" -m unittest discover tests > test_results.txt 2>&1
    if exist generate_report.py (
        "%LOCALAPPDATA%\Python\bin\python.exe" generate_report.py
    )
    exit /b 0
)

where py >nul 2>nul
if %errorlevel%==0 (
    echo [INFO] Running tests using py launcher...
    py -m unittest discover tests > test_results.txt 2>&1
    if exist generate_report.py (
        py generate_report.py
    )
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
